"""Spoke-side client for hub-and-spoke ledger sync.

Spokes hold full replicas. They submit intended transactions to the hub
(signed against the hub's chain head), then pull accepted rows and replay-apply
them locally. Spokes never append via ``execute_signed`` for synced writes —
the hub is the single serializer of the chain; local appends happen only through
replay-apply of hub-accepted ledger rows.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from mschf.audit import historical_rbac_check, replay_audit
from mschf.storage import (
    GENESIS_PREV_HASH,
    MSFStorage,
    PAYLOAD_FMT_V3,
    canonical_payload,
    ledger_row_hash,
    make_json_serializable,
    payload_from_ledger_row,
)
from mschf.trust import is_cert_trusted, resolve_trust_anchors

_TS_FORMAT = '%Y-%m-%d %H:%M:%S'


class StaleHead(Exception):
    """Hub rejected a submit because the payload was signed against a stale head.

    ``head`` carries the hub's current head response (same shape as GET /head)
    so the caller can re-sign without an extra round-trip.
    """

    def __init__(self, message, head=None):
        super().__init__(message)
        self.head = head or {}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _url(hub_url, *parts, query=None):
    base = hub_url.rstrip('/')
    path = '/'.join(str(p) for p in parts)
    url = f'{base}/{path}'
    if query:
        url = f'{url}?{urllib.parse.urlencode(query)}'
    return url


def _http_json(method, url, body=None, timeout=60):
    data = None
    headers = {'Accept': 'application/json'}
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            code = resp.status
            if not raw:
                return code, {}
            return code, json.loads(raw.decode('utf-8'))
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw.decode('utf-8')) if raw else {}
        except json.JSONDecodeError:
            parsed = {'error': 'http_error', 'detail': raw.decode('utf-8', errors='replace')}
        return e.code, parsed


def _http_bytes(url, timeout=60):
    req = urllib.request.Request(url, method='GET')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _b64d(s):
    return base64.b64decode(s.encode('ascii') if isinstance(s, str) else s)


def _cert_cn(cert_pem):
    pem = cert_pem.encode('utf-8') if isinstance(cert_pem, str) else cert_pem
    cert = x509.load_pem_x509_certificate(pem, default_backend())
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


# ---------------------------------------------------------------------------
# Manifest homing
# ---------------------------------------------------------------------------

def homing(storage):
    """Return ``(sync_hub_url, sync_hub_cn)`` from the container manifest, or (None, None)."""
    url = storage.get_manifest_item('sync_hub_url')
    cn = storage.get_manifest_item('sync_hub_cn')
    return url, cn


# ---------------------------------------------------------------------------
# Sidecar: external head attestation record
# ---------------------------------------------------------------------------

def head_sidecar_path(container_path):
    return f'{container_path}.head'


def load_attested_head(container_path):
    path = head_sidecar_path(container_path)
    if not os.path.isfile(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def store_attested_head(container_path, head_dict):
    """Persist the latest verified head attestation next to the container."""
    path = head_sidecar_path(container_path)
    # Keep a compact, stable record: next_seq, prev_hash, full attestation.
    record = {
        'container': head_dict.get('container'),
        'next_seq': head_dict['next_seq'],
        'prev_hash': head_dict['prev_hash'],
        'attestation': head_dict.get('attestation'),
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(record, f, indent=2, sort_keys=True)


def _head_extends(previous, hub_next_seq, hub_prev_hash):
    """True if hub head extends (or equals) a previously attested head.

    Regression (hub behind previous) or same-seq fork (hash mismatch) → False.
    """
    if previous is None:
        return True
    prev_seq = previous['next_seq']
    prev_hash = previous['prev_hash']
    if hub_next_seq < prev_seq:
        return False
    if hub_next_seq == prev_seq and hub_prev_hash != prev_hash:
        return False
    return True


# ---------------------------------------------------------------------------
# Head fetch + attestation verification
# ---------------------------------------------------------------------------

def fetch_head(hub_url, container_id, expected_hub_cn=None, ca_cert_path=None, trust_dir=None):
    """Fetch and verify the hub's head attestation.

    Returns ``(next_seq, prev_hash, attestation_dict)`` where attestation_dict
    is the full head response (including nested attestation).
    """
    code, data = _http_json('GET', _url(hub_url, 'containers', container_id, 'head'))
    if code != 200:
        raise PermissionError(f'fetch_head failed ({code}): {data}')

    next_seq = data.get('next_seq')
    prev_hash = data.get('prev_hash')
    att = data.get('attestation') or {}
    payload_str = att.get('payload')
    sig_b64 = att.get('signature')
    hub_cert = att.get('hub_cert')

    if payload_str is None or sig_b64 is None or hub_cert is None:
        raise PermissionError('fetch_head: attestation missing payload/signature/hub_cert')

    # Payload must bind the same head the response advertises.
    expected_payload = json.dumps(
        {'container': container_id, 'next_seq': next_seq, 'prev_hash': prev_hash},
        sort_keys=True,
    )
    if payload_str != expected_payload:
        # Also accept if container field in response matches via re-parse.
        try:
            parsed = json.loads(payload_str)
        except json.JSONDecodeError as e:
            raise PermissionError(f'fetch_head: attestation payload not JSON: {e}') from e
        if (
            parsed.get('container') != container_id
            or parsed.get('next_seq') != next_seq
            or parsed.get('prev_hash') != prev_hash
        ):
            raise PermissionError(
                'fetch_head: attestation payload does not match advertised head'
            )

    # Verify hub signature over the attestation payload.
    try:
        cert = x509.load_pem_x509_certificate(
            hub_cert.encode('utf-8') if isinstance(hub_cert, str) else hub_cert,
            default_backend(),
        )
        cert.public_key().verify(
            _b64d(sig_b64),
            payload_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:
        raise PermissionError(f'fetch_head: hub attestation signature invalid: {e}') from e

    # Hub cert must chain to a trust anchor.
    anchors = resolve_trust_anchors(ca_cert_path, trust_dir)
    if not is_cert_trusted(hub_cert, anchors):
        raise PermissionError(
            'fetch_head: hub certificate is not signed by a trusted Root CA'
        )

    if expected_hub_cn is not None:
        cn = _cert_cn(hub_cert)
        if cn != expected_hub_cn:
            raise PermissionError(
                f'fetch_head: hub CN {cn!r} does not match expected {expected_hub_cn!r}'
            )

    return next_seq, prev_hash, data


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------

def submit(hub_url, container_id, query, params, signature, pub_key_pem,
           seq=None, prev_hash=None):
    """POST a signed transaction to the hub.

    Optional ``seq``/``prev_hash`` declare the head the payload was signed
    against so the hub can return 409 (stale) vs 403 (bad signature).

    Returns the parsed success response (new head). Raises ``StaleHead`` on
    409, ``PermissionError`` on 403.
    """
    if isinstance(pub_key_pem, bytes):
        pub_key_pem = pub_key_pem.decode('utf-8')
    body = {
        'query': query,
        'params': make_json_serializable(params if params is not None else []),
        'signature_b64': base64.b64encode(bytes(signature)).decode('ascii'),
        'pub_key': pub_key_pem,
    }
    if seq is not None:
        body['seq'] = seq
        body['prev_hash'] = prev_hash if prev_hash is not None else GENESIS_PREV_HASH

    code, data = _http_json(
        'POST', _url(hub_url, 'containers', container_id, 'transactions'), body=body
    )
    if code == 200:
        return data
    if code == 409:
        raise StaleHead(data.get('detail') or data.get('error') or 'stale_head', head=data)
    if code == 403:
        raise PermissionError(data.get('detail') or data.get('error') or 'forbidden')
    raise PermissionError(f'submit failed ({code}): {data}')


def sign_and_submit(
    hub_url,
    container_id,
    private_key,
    cert_pem,
    query,
    params,
    max_retries=3,
    expected_hub_cn=None,
    ca_cert_path=None,
    trust_dir=None,
    expected_container_uid=None,
):
    """Fetch verified head → sign with ``canonical_payload`` → submit; retry on StaleHead.

    The hub's head response includes ``container_uid``; the payload is signed
    under v3 against that claim. When ``expected_container_uid`` is set (local
    replica's uid), a mismatch with the hub raises before signing.
    """
    if isinstance(cert_pem, bytes):
        cert_pem = cert_pem.decode('utf-8')
    params = params if params is not None else []
    last_err = None
    for _ in range(max_retries):
        next_seq, prev_hash, head = fetch_head(
            hub_url, container_id,
            expected_hub_cn=expected_hub_cn,
            ca_cert_path=ca_cert_path,
            trust_dir=trust_dir,
        )
        hub_uid = head.get('container_uid')
        if expected_container_uid is not None and hub_uid != expected_container_uid:
            raise PermissionError(
                f'sign_and_submit: hub container_uid {hub_uid!r} does not match '
                f'local expected_container_uid {expected_container_uid!r}'
            )
        payload = canonical_payload(query, params, next_seq, prev_hash, hub_uid)
        signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        try:
            return submit(
                hub_url, container_id, query, params, signature, cert_pem,
                seq=next_seq, prev_hash=prev_hash,
            )
        except StaleHead as e:
            last_err = e
            continue
    raise last_err if last_err else PermissionError('sign_and_submit: exhausted retries')


# ---------------------------------------------------------------------------
# Pull + replay-apply
# ---------------------------------------------------------------------------

def _local_max_seq(storage):
    row = storage.conn.execute(
        "SELECT IFNULL(MAX(seq), 0) FROM transactions WHERE seq IS NOT NULL"
    ).fetchone()
    return row[0] if row else 0


def _verify_row_signature(storage, query, params, signature, pub_key, seq, prev_hash,
                          payload_fmt=None):
    # Replica and hub share container_uid by construction (bootstrap copies the
    # whole file). Reconstruct from the row's stored fmt using this storage's uid.
    uid = storage.container_uid
    if payload_fmt == PAYLOAD_FMT_V3 and not uid:
        raise PermissionError(
            f'pull_and_apply: v3 row seq={seq} but local container_uid is missing'
        )
    payload = payload_from_ledger_row(
        query, params, seq, prev_hash, payload_fmt, uid)
    if not storage.verify_signature(payload, signature, pub_key):
        raise PermissionError(
            f'pull_and_apply: invalid signature on hub row seq={seq}'
        )
    if not storage._signer_is_ca_trusted(pub_key):
        raise PermissionError(
            f'pull_and_apply: untrusted signer on hub row seq={seq}'
        )
    return payload


def pull_and_apply(
    storage,
    hub_url,
    container_id,
    expected_hub_cn=None,
    ca_cert_path=None,
    trust_dir=None,
):
    """Pull hub rows since the local head and replay-apply them into ``storage``.

    Verifies each row continues the local chain and its signature + CA trust.
    SELECT (read-audit) rows insert the ledger row only; mutations re-execute
    SQL with ``_active_signer`` and a ``datetime`` override so triggers stamp
    historically-correct attribution and timestamps.

    Stores the latest verified head attestation in ``<container>.msf.head``.
    Raises if the hub head regresses relative to a previously attested head.
    """
    ca = ca_cert_path if ca_cert_path is not None else storage._ca_cert_path_arg
    td = trust_dir if trust_dir is not None else storage.trust_dir

    next_seq, prev_hash, head = fetch_head(
        hub_url, container_id,
        expected_hub_cn=expected_hub_cn,
        ca_cert_path=ca,
        trust_dir=td,
    )

    previous = load_attested_head(storage.filename)
    if not _head_extends(previous, next_seq, prev_hash):
        raise PermissionError(
            f'pull_and_apply: hub head (next_seq={next_seq}, prev_hash={prev_hash!r}) '
            f'does not extend previously attested head '
            f'(next_seq={previous["next_seq"]}, prev_hash={previous["prev_hash"]!r}) '
            f'— possible truncation or fork'
        )

    since_seq = _local_max_seq(storage)
    code, data = _http_json(
        'GET',
        _url(hub_url, 'containers', container_id, 'transactions', query={'since_seq': since_seq}),
    )
    if code != 200:
        raise PermissionError(f'pull_and_apply: fetch transactions failed ({code}): {data}')

    rows = data.get('rows') or []

    # Chain state at the local tip — same derivation as get_chain_head.
    expected_next, running_hash = storage.get_chain_head()

    # datetime('now') override — pattern from audit.py._replay_datetime.
    # create_function permanently shadows the SQLite builtin for this
    # connection; after apply we reinstall a now-returning implementation
    # (passing None does not restore the engine builtin and leaves a
    # broken UDF that raises on call).
    #
    # Limitation: the shim only implements the 1-arg form
    # (``datetime('now')`` and ``datetime(iso_string)``). Multi-arg SQLite
    # ``datetime(timestring, modifier, ...)`` is not emulated.
    now_holder = {'ts': None}

    def _replay_datetime(*args):
        if len(args) == 1 and args[0] == 'now' and now_holder['ts']:
            return now_holder['ts']
        if len(args) == 1 and args[0] == 'now':
            return datetime.utcnow().strftime(_TS_FORMAT)
        if len(args) == 1:
            try:
                return datetime.fromisoformat(str(args[0])).strftime(_TS_FORMAT)
            except (ValueError, TypeError):
                return None
        return None

    def _live_datetime(*args):
        if len(args) == 1 and args[0] == 'now':
            return datetime.utcnow().strftime(_TS_FORMAT)
        if len(args) == 1:
            try:
                return datetime.fromisoformat(str(args[0])).strftime(_TS_FORMAT)
            except (ValueError, TypeError):
                return None
        return None

    storage.conn.create_function('datetime', -1, _replay_datetime)
    applied = 0
    try:
        for row in rows:
            query = row['query']
            params = row.get('params') or []
            signature = _b64d(row['signature_b64'])
            pub_key = row['pub_key']
            ts = row['timestamp']
            seq = row['seq']
            row_prev = row['prev_hash']
            payload_fmt = row.get('payload_fmt')
            txn_id = row['id']

            if seq != expected_next:
                raise PermissionError(
                    f'pull_and_apply: seq gap — got {seq}, expected {expected_next}'
                )
            if row_prev != running_hash:
                raise PermissionError(
                    f'pull_and_apply: prev_hash mismatch at seq={seq} '
                    f'(got {row_prev!r}, expected {running_hash!r})'
                )

            payload = _verify_row_signature(
                storage, query, params, signature, pub_key, seq, row_prev,
                payload_fmt=payload_fmt,
            )

            operation, _ = storage._parse_sql_query(query)
            if operation != 'read':
                identity = storage._get_identity(pub_key)
                # Re-enforce coarse historical RBAC before applying. A
                # malicious hub colluding with a trusted-but-unprivileged
                # signer can feed a correctly-chained row the writer-side
                # RBAC would have denied; refuse and roll back the batch.
                allowed, reason = historical_rbac_check(
                    storage.conn, identity, query, storage._parse_sql_query)
                if not allowed:
                    raise PermissionError(
                        f'pull_and_apply: rbac denied for seq={seq} '
                        f'({identity}): {reason}'
                    )
                now_holder['ts'] = ts
                storage._active_signer = identity
                try:
                    if params:
                        storage.conn.execute(query, params)
                    else:
                        storage.conn.execute(query)
                except Exception as e:
                    # Redundant DDL (table/trigger already present on bootstrap
                    # replica that already has schema) is tolerable only if the
                    # end state matches — bootstrap copies the full file, so
                    # mid-chain DDL rows should already be applied. Still re-
                    # execute for pure replicas that advanced only via pull.
                    err = str(e).lower()
                    if not any(t in err for t in ('duplicate column name', 'already exists')):
                        raise PermissionError(
                            f'pull_and_apply: failed to apply seq={seq}: {e}'
                        ) from e
                finally:
                    storage._active_signer = None
                    now_holder['ts'] = None

            # Insert the ledger row verbatim (explicit id, timestamp, seq,
            # prev_hash, payload_fmt).
            params_str = json.dumps(make_json_serializable(params))
            storage.conn.execute(
                "INSERT INTO transactions "
                "(id, query, params, signature, pub_key, timestamp, seq, prev_hash, "
                "payload_fmt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (txn_id, query, params_str, signature, pub_key, ts, seq, row_prev,
                 payload_fmt),
            )
            running_hash = ledger_row_hash(payload, signature)
            expected_next = seq + 1
            applied += 1

        storage.conn.commit()
    except Exception:
        storage.conn.rollback()
        raise
    finally:
        # Reinstall a live datetime('now') so subsequent queries are not
        # frozen at the last replayed ledger timestamp.
        storage.conn.create_function('datetime', -1, _live_datetime)

    # Sidecar: store the fetched-head attestation iff the local tip now equals
    # it; otherwise leave the previous sidecar in place (next pull persists a
    # fresh one). Mid-pull race: hub advanced between head-fetch and row-fetch
    # so the replica's applied tip lands *past* the fetched head
    # (local_next > next_seq with applied > 0) — benign; skip sidecar store.
    local_next, local_prev = storage.get_chain_head()
    if local_next == next_seq and local_prev == prev_hash:
        store_attested_head(storage.filename, head)
    elif applied == 0 and (local_next, local_prev) != (next_seq, prev_hash):
        raise PermissionError(
            f'pull_and_apply: local head ({local_next}, {local_prev!r}) does not '
            f'match hub head ({next_seq}, {prev_hash!r}) and no rows were available'
        )

    return {
        'applied': applied,
        'head': head,
        'local_next_seq': local_next,
        'local_prev_hash': local_prev,
    }


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap(
    hub_url,
    container_id,
    dest_path,
    expected_hub_cn=None,
    ca_cert_path=None,
    trust_dir=None,
):
    """Download the container file from the hub, audit it, store attested head.

    Returns the open ``MSFStorage`` for the local replica.
    """
    data = _http_bytes(_url(hub_url, 'containers', container_id, 'file'))
    dest_dir = os.path.dirname(os.path.abspath(dest_path))
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)
    with open(dest_path, 'wb') as f:
        f.write(data)

    storage = MSFStorage(dest_path, ca_cert_path=ca_cert_path, trust_dir=trust_dir)
    report = replay_audit(storage)
    if not report.get('ok'):
        storage.close()
        raise PermissionError(
            f'bootstrap: replay_audit failed for {container_id}: '
            f'{report.get("transactions")}'
        )

    next_seq, prev_hash, head = fetch_head(
        hub_url, container_id,
        expected_hub_cn=expected_hub_cn,
        ca_cert_path=ca_cert_path,
        trust_dir=trust_dir,
    )
    local_next, local_prev = storage.get_chain_head()
    if (local_next, local_prev) != (next_seq, prev_hash):
        storage.close()
        raise PermissionError(
            f'bootstrap: local head ({local_next}, {local_prev!r}) != '
            f'hub head ({next_seq}, {prev_hash!r})'
        )
    store_attested_head(dest_path, head)
    return storage
