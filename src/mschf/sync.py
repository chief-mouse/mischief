"""Spoke-side client for hub-and-spoke ledger sync.

Spokes hold full replicas. They submit intended transactions to the hub
(signed against the hub's chain head), then pull accepted rows and replay-apply
them locally. Spokes never append via ``execute_signed`` for synced writes —
the hub is the single serializer of the chain; local appends happen only through
replay-apply of hub-accepted ledger rows.

Also provides:
- long-poll ``subscribe`` for event-driven pull
- in-container ``sync_outbox`` for offline write intents
- ``hub_write`` (product-facing online/offline write path)
- ``sync_status`` and a small CLI (``python -m mschf.sync``)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
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

# Long-poll / reconnect defaults
_DEFAULT_EVENTS_TIMEOUT = 25
_EVENTS_HTTP_SLOP = 10  # HTTP client timeout = poll timeout + slop
_BACKOFF_START = 1.0
_BACKOFF_CAP = 30.0

_OUTBOX_DDL = """
CREATE TABLE IF NOT EXISTS sync_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_cn TEXT NOT NULL,
    query TEXT NOT NULL,
    params TEXT NOT NULL,
    created_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'failed')),
    error TEXT
)
"""


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
# Hub head attestation (container_meta infrastructure metadata)
# ---------------------------------------------------------------------------

_HUB_ATTESTATION_KEY = 'hub_attestation'


def load_attested_head(storage):
    """Return the verified hub head record from ``container_meta``, or None."""
    row = storage.conn.execute(
        "SELECT value FROM container_meta WHERE key = ?",
        (_HUB_ATTESTATION_KEY,),
    ).fetchone()
    if row is None or not row[0]:
        return None
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return None


def store_attested_head(storage, head_dict):
    """Persist the latest verified head attestation in ``container_meta``.

    Direct unsigned write — same class of infrastructure metadata as
    ``set_payload_fmt_floor`` / ``container_uid`` (not ledgered history).
    """
    record = {
        'container': head_dict.get('container'),
        'next_seq': head_dict['next_seq'],
        'prev_hash': head_dict['prev_hash'],
        'attestation': head_dict.get('attestation'),
    }
    storage.conn.execute(
        "INSERT OR REPLACE INTO container_meta (key, value) VALUES (?, ?)",
        (_HUB_ATTESTATION_KEY, json.dumps(record, sort_keys=True)),
    )
    storage.conn.commit()


def _migrate_legacy_head_sidecar(storage):
    """One-way import of a legacy ``<container>.msf.head`` sidecar into meta.

    If a sidecar file exists next to the open container: parse it; when the
    container has no ``hub_attestation`` yet or the sidecar's ``next_seq`` is
    higher, import the compact record into ``container_meta``; then delete the
    sidecar. Unreadable sidecars are left in place and a warning is printed
    (do not destroy what we cannot parse).
    """
    # Legacy path: <container path>.head — only consulted here for migration.
    path = f'{storage.filename}.head'
    if not os.path.isfile(path):
        return
    try:
        with open(path, 'r', encoding='utf-8') as f:
            sidecar = json.load(f)
        if not isinstance(sidecar, dict):
            raise ValueError('sidecar JSON is not an object')
        if 'next_seq' not in sidecar or 'prev_hash' not in sidecar:
            raise ValueError('sidecar missing next_seq/prev_hash')
    except Exception as e:
        print(
            f'warning: unreadable legacy head sidecar {path!r} '
            f'(left in place): {e}',
            file=sys.stderr,
        )
        return

    existing = load_attested_head(storage)
    if existing is None or sidecar['next_seq'] > existing.get('next_seq', -1):
        store_attested_head(storage, sidecar)
    try:
        os.remove(path)
    except OSError as e:
        print(
            f'warning: could not delete legacy head sidecar {path!r}: {e}',
            file=sys.stderr,
        )


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

    Stores the latest verified head attestation in ``container_meta``
    (``hub_attestation`` key). Raises if the hub head regresses relative to a
    previously attested head.
    """
    ca = ca_cert_path if ca_cert_path is not None else storage._ca_cert_path_arg
    td = trust_dir if trust_dir is not None else storage.trust_dir

    # Import any legacy <container>.msf.head sidecar before the regression check.
    _migrate_legacy_head_sidecar(storage)

    next_seq, prev_hash, head = fetch_head(
        hub_url, container_id,
        expected_hub_cn=expected_hub_cn,
        ca_cert_path=ca,
        trust_dir=td,
    )

    previous = load_attested_head(storage)
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

    # Store the fetched-head attestation iff the local tip now equals it;
    # otherwise leave the previous container_meta record in place (next pull
    # persists a fresh one). Mid-pull race: hub advanced between head-fetch
    # and row-fetch so the replica's applied tip lands *past* the fetched head
    # (local_next > next_seq with applied > 0) — benign; skip attestation store.
    local_next, local_prev = storage.get_chain_head()
    if local_next == next_seq and local_prev == prev_hash:
        store_attested_head(storage, head)
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
    # Clean up a leftover legacy .head sidecar next to dest (bootstrap
    # overwrites the .msf itself; pull is the primary migration path).
    _migrate_legacy_head_sidecar(storage)
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
    # After head check passes: store attestation (overwrites any imported
    # legacy record with the verified hub head for this bootstrap snapshot).
    store_attested_head(storage, head)
    return storage


# ---------------------------------------------------------------------------
# Connection-error helpers
# ---------------------------------------------------------------------------

def _is_connection_error(exc):
    """True for network/unreachable failures (not HTTP 4xx/5xx app errors)."""
    if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, OSError)):
        # HTTPError is a subclass of URLError but carries an HTTP status —
        # those are application-level, not "hub unreachable".
        if isinstance(exc, urllib.error.HTTPError):
            return False
        return True
    return False


# ---------------------------------------------------------------------------
# Event-driven subscribe (long-poll)
# ---------------------------------------------------------------------------

def subscribe(
    storage,
    hub_url,
    container_id,
    stop_event,
    expected_hub_cn=None,
    on_applied=None,
    ca_cert_path=None,
    trust_dir=None,
    timeout=None,
):
    """Long-poll the hub for new ledger rows and pull_and_apply them.

    Loop until ``stop_event`` is set. Safe to run in a thread with its own
    ``MSFStorage`` connection (do not share ``storage`` with other threads).

    The events payload is a wake-up signal only — every applied row is still
    re-verified by ``pull_and_apply``. On connection errors, exponential
    backoff from 1s to 30s; the loop keeps running until stopped.
    """
    ca = ca_cert_path if ca_cert_path is not None else storage._ca_cert_path_arg
    td = trust_dir if trust_dir is not None else storage.trust_dir
    poll_timeout = (
        _DEFAULT_EVENTS_TIMEOUT if timeout is None else float(timeout)
    )
    backoff = _BACKOFF_START

    while not stop_event.is_set():
        since_seq = _local_max_seq(storage)
        try:
            code, data = _http_json(
                'GET',
                _url(
                    hub_url,
                    'containers',
                    container_id,
                    'events',
                    query={
                        'since_seq': since_seq,
                        'timeout': poll_timeout,
                    },
                ),
                timeout=poll_timeout + _EVENTS_HTTP_SLOP,
            )
            if code != 200:
                raise PermissionError(
                    f'subscribe: events failed ({code}): {data}'
                )
            # Wake-up only — always re-verify via pull_and_apply (idempotent).
            result = pull_and_apply(
                storage,
                hub_url,
                container_id,
                expected_hub_cn=expected_hub_cn,
                ca_cert_path=ca,
                trust_dir=td,
            )
            backoff = _BACKOFF_START
            if result.get('applied', 0) > 0 and on_applied is not None:
                try:
                    on_applied(result)
                except Exception:
                    pass
        except Exception as e:
            if stop_event.is_set():
                break
            if _is_connection_error(e) or isinstance(e, TimeoutError):
                # Back off and keep looping.
                stop_event.wait(timeout=backoff)
                backoff = min(backoff * 2, _BACKOFF_CAP)
                continue
            # Application / crypto errors: brief pause then continue so a
            # transient 403/audit glitch does not kill the subscriber.
            stop_event.wait(timeout=min(backoff, 5.0))
            backoff = min(backoff * 2, _BACKOFF_CAP)
            continue


# ---------------------------------------------------------------------------
# In-container outbox (unsigned infrastructure, like container_meta)
# ---------------------------------------------------------------------------

def _ensure_outbox(storage):
    """Create ``sync_outbox`` if missing (direct unsigned DDL; not ledgered)."""
    storage.conn.execute(_OUTBOX_DDL)
    storage.conn.commit()


def queue_intent(storage, identity_cn, query, params):
    """Append a pending write intent; returns the new outbox row id."""
    _ensure_outbox(storage)
    params_json = json.dumps(
        make_json_serializable(params if params is not None else []),
        sort_keys=True,
    )
    created = datetime.utcnow().strftime(_TS_FORMAT)
    cur = storage.conn.execute(
        "INSERT INTO sync_outbox (identity_cn, query, params, created_at, status) "
        "VALUES (?, ?, ?, ?, 'pending')",
        (identity_cn, query, params_json, created),
    )
    storage.conn.commit()
    return cur.lastrowid


def list_outbox(storage):
    """Return outbox rows as dicts ordered by id (creates table if needed)."""
    _ensure_outbox(storage)
    rows = storage.conn.execute(
        "SELECT id, identity_cn, query, params, created_at, status, error "
        "FROM sync_outbox ORDER BY id"
    ).fetchall()
    out = []
    for (oid, cn, query, params_str, created_at, status, error) in rows:
        try:
            params = json.loads(params_str) if params_str else []
        except json.JSONDecodeError:
            params = []
        out.append({
            'id': oid,
            'identity_cn': cn,
            'query': query,
            'params': params,
            'created_at': created_at,
            'status': status,
            'error': error,
        })
    return out


def flush_outbox(
    storage,
    hub_url,
    container_id,
    private_key,
    cert_pem,
    identity_cn,
    expected_hub_cn=None,
    ca_cert_path=None,
    trust_dir=None,
    max_retries=3,
):
    """Submit pending outbox intents for ``identity_cn`` in id order.

    Success → delete the row. On ``StaleHead`` exhaustion or ``PermissionError``
    → mark that intent ``failed`` with the error text and STOP (later intents
    may depend on earlier ones). On connection error → stop, leave remaining
    pending. After any successful submit, ``pull_and_apply``.

    Returns ``{'flushed': int, 'failed': int, 'remaining': int,
    'stopped_on': None|'connection'|'permission'|'stale_head'|str}``.
    """
    _ensure_outbox(storage)
    ca = ca_cert_path if ca_cert_path is not None else storage._ca_cert_path_arg
    td = trust_dir if trust_dir is not None else storage.trust_dir
    if isinstance(cert_pem, bytes):
        cert_pem = cert_pem.decode('utf-8')

    pending = storage.conn.execute(
        "SELECT id, query, params FROM sync_outbox "
        "WHERE identity_cn = ? AND status = 'pending' ORDER BY id",
        (identity_cn,),
    ).fetchall()

    flushed = 0
    failed = 0
    stopped_on = None
    submitted_any = False

    for oid, query, params_str in pending:
        try:
            params = json.loads(params_str) if params_str else []
        except json.JSONDecodeError:
            params = []

        try:
            sign_and_submit(
                hub_url,
                container_id,
                private_key,
                cert_pem,
                query,
                params,
                max_retries=max_retries,
                expected_hub_cn=expected_hub_cn,
                ca_cert_path=ca,
                trust_dir=td,
                expected_container_uid=storage.container_uid,
            )
        except StaleHead as e:
            storage.conn.execute(
                "UPDATE sync_outbox SET status = 'failed', error = ? WHERE id = ?",
                (str(e), oid),
            )
            storage.conn.commit()
            failed += 1
            stopped_on = 'stale_head'
            break
        except PermissionError as e:
            storage.conn.execute(
                "UPDATE sync_outbox SET status = 'failed', error = ? WHERE id = ?",
                (str(e), oid),
            )
            storage.conn.commit()
            failed += 1
            stopped_on = 'permission'
            break
        except Exception as e:
            if _is_connection_error(e):
                stopped_on = 'connection'
                break
            # Unexpected non-network error: treat like permission (stop chain).
            storage.conn.execute(
                "UPDATE sync_outbox SET status = 'failed', error = ? WHERE id = ?",
                (str(e), oid),
            )
            storage.conn.commit()
            failed += 1
            stopped_on = type(e).__name__
            break

        storage.conn.execute("DELETE FROM sync_outbox WHERE id = ?", (oid,))
        storage.conn.commit()
        flushed += 1
        submitted_any = True

    if submitted_any:
        try:
            pull_and_apply(
                storage,
                hub_url,
                container_id,
                expected_hub_cn=expected_hub_cn,
                ca_cert_path=ca,
                trust_dir=td,
            )
        except Exception:
            # Flush already landed on the hub; pull can retry later.
            pass

    remaining = storage.conn.execute(
        "SELECT COUNT(*) FROM sync_outbox "
        "WHERE identity_cn = ? AND status = 'pending'",
        (identity_cn,),
    ).fetchone()[0]

    return {
        'flushed': flushed,
        'failed': failed,
        'remaining': remaining,
        'stopped_on': stopped_on,
    }


def hub_write(
    storage,
    hub_url,
    container_id,
    private_key,
    cert_pem,
    identity_cn,
    query,
    params,
    expected_hub_cn=None,
    ca_cert_path=None,
    trust_dir=None,
    max_retries=3,
):
    """Product-facing write: online submit or queue offline intent.

    1. If this identity has pending outbox intents, flush them first (ordering).
       If flush stops on a connection error, queue the new intent and return
       ``{'status': 'queued', ...}``.
    2. Otherwise ``sign_and_submit``; on connection failure queue
       (``'queued'``); on success ``pull_and_apply`` and return
       ``{'status': 'committed', 'seq': ...}``.
    """
    ca = ca_cert_path if ca_cert_path is not None else storage._ca_cert_path_arg
    td = trust_dir if trust_dir is not None else storage.trust_dir
    if isinstance(cert_pem, bytes):
        cert_pem = cert_pem.decode('utf-8')
    params = params if params is not None else []

    _ensure_outbox(storage)
    pending_count = storage.conn.execute(
        "SELECT COUNT(*) FROM sync_outbox "
        "WHERE identity_cn = ? AND status = 'pending'",
        (identity_cn,),
    ).fetchone()[0]

    if pending_count > 0:
        summary = flush_outbox(
            storage,
            hub_url,
            container_id,
            private_key,
            cert_pem,
            identity_cn,
            expected_hub_cn=expected_hub_cn,
            ca_cert_path=ca,
            trust_dir=td,
            max_retries=max_retries,
        )
        if summary.get('stopped_on') == 'connection' or summary.get('remaining', 0) > 0:
            oid = queue_intent(storage, identity_cn, query, params)
            return {
                'status': 'queued',
                'outbox_id': oid,
                'flush': summary,
            }
        if summary.get('failed', 0) > 0:
            # Prior intent failed; still queue the new one behind failed/pending
            # so the operator can inspect — but do not attempt online submit
            # out of order. Spec: flush stops on failure; queue new behind.
            oid = queue_intent(storage, identity_cn, query, params)
            return {
                'status': 'queued',
                'outbox_id': oid,
                'flush': summary,
            }

    try:
        resp = sign_and_submit(
            hub_url,
            container_id,
            private_key,
            cert_pem,
            query,
            params,
            max_retries=max_retries,
            expected_hub_cn=expected_hub_cn,
            ca_cert_path=ca,
            trust_dir=td,
            expected_container_uid=storage.container_uid,
        )
    except Exception as e:
        if _is_connection_error(e):
            oid = queue_intent(storage, identity_cn, query, params)
            return {
                'status': 'queued',
                'outbox_id': oid,
                'error': str(e),
            }
        raise

    try:
        pull_and_apply(
            storage,
            hub_url,
            container_id,
            expected_hub_cn=expected_hub_cn,
            ca_cert_path=ca,
            trust_dir=td,
        )
    except Exception:
        pass

    # next_seq in the head response is the *next* free seq; the committed
    # row is next_seq - 1 when the hub advanced by one.
    next_seq = resp.get('next_seq')
    committed_seq = (next_seq - 1) if isinstance(next_seq, int) and next_seq > 0 else next_seq
    return {
        'status': 'committed',
        'seq': committed_seq,
        'head': resp,
    }


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def sync_status(storage, probe_hub_url=None, expected_hub_cn=None,
                ca_cert_path=None, trust_dir=None):
    """Return a dict describing local sync state (optionally probe the hub).

    Keys: ``homed``, ``hub_cn``, ``attested_seq``, ``local_next_seq``,
    ``outbox_pending``, ``outbox_failed``, ``reachable`` (True/False/None),
    ``in_sync`` (bool|None). ``reachable`` / ``in_sync`` only set when probing.
    """
    hub_url, hub_cn = homing(storage)
    attested = load_attested_head(storage)
    local_next, _ = storage.get_chain_head()
    attested_seq = attested.get('next_seq') if attested else None

    _ensure_outbox(storage)
    pending = storage.conn.execute(
        "SELECT COUNT(*) FROM sync_outbox WHERE status = 'pending'"
    ).fetchone()[0]
    failed = storage.conn.execute(
        "SELECT COUNT(*) FROM sync_outbox WHERE status = 'failed'"
    ).fetchone()[0]

    status = {
        'homed': bool(hub_cn),
        'hub_cn': hub_cn,
        'attested_seq': attested_seq,
        'local_next_seq': local_next,
        'outbox_pending': pending,
        'outbox_failed': failed,
        'reachable': None,
        'in_sync': None,
    }

    probe = probe_hub_url or hub_url
    if probe:
        ca = ca_cert_path if ca_cert_path is not None else storage._ca_cert_path_arg
        td = trust_dir if trust_dir is not None else storage.trust_dir
        # Need a container id for the head endpoint — use filename stem.
        container_id = os.path.splitext(os.path.basename(storage.filename))[0]
        cn = expected_hub_cn if expected_hub_cn is not None else hub_cn
        try:
            hub_next, hub_prev, _head = fetch_head(
                probe,
                container_id,
                expected_hub_cn=cn,
                ca_cert_path=ca,
                trust_dir=td,
            )
            status['reachable'] = True
            local_next_now, local_prev = storage.get_chain_head()
            status['in_sync'] = (
                local_next_now == hub_next and local_prev == hub_prev
            )
        except Exception as e:
            if _is_connection_error(e):
                status['reachable'] = False
                status['in_sync'] = None
            else:
                # Hub answered but attestation/CN failed — still "reachable"
                # at the transport layer; treat as reachable but not in_sync.
                status['reachable'] = True
                status['in_sync'] = False

    return status


# ---------------------------------------------------------------------------
# CLI: python -m mschf.sync <status|pull|flush> <file> ...
# ---------------------------------------------------------------------------

def _cli_load_identity(cn, project_root=None):
    """Load ``<cn>.crt`` / ``<cn>.key`` from host root (passphrase env / plaintext)."""
    root = project_root or os.getcwd()
    cert_path = os.path.join(root, f'{cn}.crt')
    key_path = os.path.join(root, f'{cn}.key')
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        raise SystemExit(
            f'{cn}.crt/{cn}.key not found in {root} — provision the identity first'
        )
    passphrase = os.environ.get('MSCHF_ADMIN_PASSPHRASE', 'changeit')
    with open(cert_path, 'rb') as f:
        cert_pem = f.read()
    with open(key_path, 'rb') as f:
        key_pem = f.read()
    try:
        private_key = load_pem_private_key(
            key_pem, password=passphrase.encode('utf-8'), backend=default_backend()
        )
    except (TypeError, ValueError):
        private_key = load_pem_private_key(
            key_pem, password=None, backend=default_backend()
        )
    return cert_pem, private_key


def main(argv=None):
    parser = argparse.ArgumentParser(description='mschf hub-spoke sync client')
    parser.add_argument(
        'command',
        choices=['status', 'pull', 'flush'],
        help='status | pull | flush',
    )
    parser.add_argument('file', help='Path to local .msf replica')
    parser.add_argument('--hub', default=None, help='Hub base URL (default: manifest)')
    parser.add_argument('--cn', default=None, help='Expected hub CN (default: manifest)')
    parser.add_argument(
        '--identity',
        default='admin',
        help='Identity CN for flush (loads <cn>.crt/.key; default admin)',
    )
    parser.add_argument('--ca-cert', default=None, help='Host CA cert path')
    parser.add_argument('--trust-dir', default=None, help='Extra trust-store directory')
    args = parser.parse_args(argv)

    storage = MSFStorage(
        args.file, ca_cert_path=args.ca_cert, trust_dir=args.trust_dir,
    )
    try:
        manifest_url, manifest_cn = homing(storage)
        hub_url = args.hub or manifest_url
        hub_cn = args.cn if args.cn is not None else manifest_cn
        container_id = os.path.splitext(os.path.basename(args.file))[0]

        if args.command == 'status':
            st = sync_status(
                storage,
                probe_hub_url=hub_url,
                expected_hub_cn=hub_cn,
                ca_cert_path=args.ca_cert,
                trust_dir=args.trust_dir,
            )
            print(f"homed: {st['homed']}")
            print(f"hub_cn: {st['hub_cn']}")
            print(f"attested_seq: {st['attested_seq']}")
            print(f"local_next_seq: {st['local_next_seq']}")
            print(f"outbox_pending: {st['outbox_pending']}")
            print(f"outbox_failed: {st['outbox_failed']}")
            print(f"reachable: {st['reachable']}")
            print(f"in_sync: {st['in_sync']}")
            return 0

        if not hub_url:
            raise SystemExit(
                'no hub URL: set --hub or store sync_hub_url in the manifest'
            )

        if args.command == 'pull':
            result = pull_and_apply(
                storage,
                hub_url,
                container_id,
                expected_hub_cn=hub_cn,
                ca_cert_path=args.ca_cert,
                trust_dir=args.trust_dir,
            )
            print(
                f"applied={result['applied']} "
                f"local_next_seq={result['local_next_seq']}"
            )
            return 0

        if args.command == 'flush':
            cert_pem, private_key = _cli_load_identity(args.identity)
            summary = flush_outbox(
                storage,
                hub_url,
                container_id,
                private_key,
                cert_pem,
                args.identity,
                expected_hub_cn=hub_cn,
                ca_cert_path=args.ca_cert,
                trust_dir=args.trust_dir,
            )
            print(
                f"flushed={summary['flushed']} failed={summary['failed']} "
                f"remaining={summary['remaining']} "
                f"stopped_on={summary['stopped_on']}"
            )
            return 0 if summary['failed'] == 0 else 1

        return 1
    finally:
        storage.close()


if __name__ == '__main__':
    sys.exit(main() or 0)
