"""Ledger replay audit: detect writes that bypassed execute_signed.

``replay_audit(storage)`` rebuilds a shadow database by replaying the signed
``transactions`` ledger in order, then diffs the shadow against the live
tables. Because every legitimate mutation flows through ``execute_signed``
(and is therefore in the ledger), any divergence means the live file was
modified out-of-band — e.g. with a raw sqlite3 client.

Design notes (each of these prevents a class of false positives):

- **Signatures first**: every ledger row is re-verified (payload signature +
  signer chains to the trusted CA) before use; tampered ledger rows are
  reported and still replayed (they *were* executed historically).
- **The chain is verified alongside the signatures**: chained rows embed
  ``seq`` and ``prev_hash`` in their signed payload, so dropped, reordered,
  or spliced ledger rows surface as ``chain_breaks`` even though each row's
  own signature still verifies. Legacy pre-chaining rows (NULL ``seq``) are
  exempt, but must all precede the first chained row. (Inherent limits:
  pure truncation of the ledger *tail* leaves an intact chain — detecting
  that needs an external record of the expected head — and rows *within* a
  legacy prefix are not linked to each other by the chain itself. When an
  admin has committed a signed ``legacy_checkpoint`` (digest of the whole
  prefix), scrubbing a legacy audit row is detectable; without one, only
  the last legacy row is anchored by the first chained row.)
- **Time is replayed, not re-evaluated**: the shadow connection overrides the
  ``datetime`` SQL function so ``datetime('now')`` — in query text, trigger
  bodies, and column defaults — returns the ledger row's own timestamp.
  (``CURRENT_TIMESTAMP`` keyword defaults are not intercepted; prefer
  ``DEFAULT (datetime('now'))`` in container schemas.)
- **Tables are pre-seeded, triggers are not**: table DDL is authored unsigned
  at container creation, so table schemas are seeded from the live file
  (redundant signed ALTERs replay with 'duplicate column' tolerance — end
  state is identical). Triggers, however, alter *behavior*, so they are NOT
  pre-seeded: they come into existence exactly where their signed DDL sits in
  the ledger, ensuring guards and stamping fire only on transactions they
  historically governed.
- **The ledger itself is copied progressively**: row i is inserted into the
  shadow's transactions table right after replaying transaction i, so signed
  statements that read the ledger see exactly what they saw historically.
- **source_code is excluded** from the diff: byte params are stored base64 in
  the audit JSON (irrecoverably stringly), and code blobs are already
  verified against their signing transaction by get_code_signature_status —
  its per-blob verdicts are folded into this report instead.
- **Bootstrap emulation**: the first-writer-becomes-admin insert happens
  outside the ledger, so the shadow grants admin to the first mutating
  transaction's identity, mirroring bootstrap_admin.

Timestamp columns that differ by <=2 seconds are classed as ``skew`` warnings
rather than mismatches: the original ``datetime('now')`` and the audit row's
timestamp were taken moments apart.
"""
import json
import re
from datetime import datetime, timedelta

from mschf.storage import (
    MSFStorage, GENESIS_PREV_HASH, PAYLOAD_FMT_V2, PAYLOAD_FMT_V3,
    ledger_row_hash, payload_from_ledger_row, legacy_prefix_digest,
)

# Tables never diffed: transactions is the replay input, source_code is
# verified via signatures (see module docstring), sqlite_sequence is engine
# bookkeeping, container_meta is unsigned infrastructure (minted at open).
EXCLUDED_TABLES = {'transactions', 'source_code', 'sqlite_sequence', 'container_meta'}

# Replay errors that only mean "the pre-seeded live schema already contains
# this DDL's end state" — safe to skip.
_REDUNDANT_DDL = ('duplicate column name', 'already exists')

_TS_FORMAT = '%Y-%m-%d %H:%M:%S'


def historical_rbac_check(conn, identity, query, parse_fn):
    """Coarse historical RBAC gate against the RBAC state visible in ``conn``.

    Evaluates the same pre-authorizer gates ``execute_signed`` applies, using
    whatever ``user_roles`` / ``rbac_rules`` are currently visible on ``conn``
    (a shadow DB during ``replay_audit``, or a replica connection during
    ``pull_and_apply``) at that point in the chain:

    1. Resolve role from ``user_roles`` (absent → ``'guest'``).
    2. ``operation, table = parse_fn(query)`` (pass ``MSFStorage._parse_sql_query``).
    3. Database-level: role needs database read (op ``'read'``) or write (else)
       permission per ``rbac_rules`` (admin bypasses, mirroring
       ``check_permission``).
    4. System tables (``MSFStorage.SYSTEM_TABLES``): any operation → role must
       be ``'admin'``.
    5. Otherwise object-level rule check for ``(operation, table)``, same
       wildcard semantics as ``check_permission``.

    **Limitation**: this is the coarse (operation, first-table) gate only — not
    the compiled-statement authorizer. Replicas re-checking at authorizer depth
    (joins, subqueries, CTEs, views, triggers, PRAGMA/ATTACH) is future work.

    Returns ``(allowed: bool, reason: str | None)``.
    """
    row = conn.execute(
        "SELECT role FROM user_roles WHERE identity = ?", (identity,)
    ).fetchone()
    role = row[0] if row else 'guest'

    operation, table_name = parse_fn(query)

    def _has_permission(level, target, permission):
        if role == 'admin':
            return True
        count = conn.execute(
            '''
            SELECT COUNT(*) FROM rbac_rules
            WHERE level = ?
              AND (target = ? OR target = '*')
              AND role = ?
              AND (permission = ? OR permission = '*')
            ''',
            (level, target, role, permission),
        ).fetchone()[0]
        return count > 0

    db_perm_needed = 'read' if operation == 'read' else 'write'
    if not _has_permission('database', '*', db_perm_needed):
        return (
            False,
            f"Identity '{identity}' does not have database-level "
            f"{db_perm_needed} permissions",
        )

    if table_name != '*':
        if table_name in MSFStorage.SYSTEM_TABLES:
            if role != 'admin':
                return (
                    False,
                    f"System table '{table_name}' can only be modified by admin.",
                )
        else:
            if not _has_permission('object', table_name, operation):
                return (
                    False,
                    f"Identity '{identity}' does not have '{operation}' "
                    f"permission on table '{table_name}'.",
                )

    return True, None


def _is_skew(a, b, tolerance_seconds=2):
    """True if a and b are timestamps within tolerance of each other."""
    try:
        ta = datetime.strptime(str(a), _TS_FORMAT)
        tb = datetime.strptime(str(b), _TS_FORMAT)
    except (ValueError, TypeError):
        return False
    return abs(ta - tb) <= timedelta(seconds=tolerance_seconds)


def _user_tables(conn):
    return {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ) if r[0] not in EXCLUDED_TABLES
    }


def _rows_by_key(conn, table):
    info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    cols = [r[1] for r in info]
    pk_cols = [r[1] for r in sorted((r for r in info if r[5] > 0), key=lambda r: r[5])]
    rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
    if pk_cols:
        pk_idx = [cols.index(c) for c in pk_cols]
        keyed = {tuple(row[i] for i in pk_idx): row for row in rows}
    else:
        keyed = {('row', i): row for i, row in enumerate(sorted(rows, key=repr))}
    return cols, keyed


def _diff_table(live_conn, shadow_conn, table):
    cols, live_rows = _rows_by_key(live_conn, table)
    _, shadow_rows = _rows_by_key(shadow_conn, table)

    unexplained = [
        {'key': k, 'row': dict(zip(cols, live_rows[k]))}
        for k in live_rows if k not in shadow_rows
    ]
    missing = [
        {'key': k, 'row': dict(zip(cols, shadow_rows[k]))}
        for k in shadow_rows if k not in live_rows
    ]
    changed, skews = [], []
    for k in live_rows:
        if k not in shadow_rows or live_rows[k] == shadow_rows[k]:
            continue
        diffs = [
            {'column': c, 'live': lv, 'expected': sv}
            for c, lv, sv in zip(cols, live_rows[k], shadow_rows[k]) if lv != sv
        ]
        real = [d for d in diffs if not _is_skew(d['live'], d['expected'])]
        if real:
            changed.append({'key': k, 'diffs': real})
        else:
            skews.append({'key': k, 'diffs': diffs})

    status = 'mismatch' if (unexplained or missing or changed) else ('skew' if skews else 'match')
    return {
        'status': status,
        'unexplained_rows': unexplained,   # in live, not reproducible from the ledger
        'missing_rows': missing,           # ledger says they should exist, live lacks them
        'changed_rows': changed,
        'timestamp_skews': skews,
    }


def replay_audit(storage):
    """Audit ``storage`` (an open MSFStorage) against its own signed ledger.

    Returns a report dict; report['ok'] is True only if every ledger signature
    verifies against a CA-trusted signer, replay raised no anomalies, and
    every audited table matches (timestamp skews don't fail the audit).
    """
    live = storage.conn
    shadow_store = MSFStorage(
        ':memory:',
        ca_cert_path=storage.ca_cert_path,
        trust_dir=storage.trust_dir,
    )
    shadow = shadow_store.conn

    # Replayed time: datetime('now') yields the in-flight ledger timestamp.
    now_holder = {'ts': None}

    def _replay_datetime(*args):
        if len(args) == 1 and args[0] == 'now' and now_holder['ts']:
            return now_holder['ts']
        if len(args) == 1:
            try:
                return datetime.fromisoformat(str(args[0])).strftime(_TS_FORMAT)
            except (ValueError, TypeError):
                return None
        return None

    shadow.create_function('datetime', -1, _replay_datetime)

    # Pre-seed table schemas (NOT triggers — see module docstring).
    system = {
        'manifest', 'source_code', 'transactions', 'rbac_rules', 'user_roles',
        'container_meta',
    }
    for (sql,) in live.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND sql IS NOT NULL "
        "AND name NOT LIKE 'sqlite_%'"
    ):
        m = re.search(r'TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?(\w+)', sql, re.IGNORECASE)
        if m and m.group(1).lower() in system:
            continue
        shadow.execute(sql)
    shadow.commit()

    ledger = live.execute(
        "SELECT id, query, params, signature, pub_key, timestamp, seq, prev_hash, "
        "payload_fmt FROM transactions ORDER BY id"
    ).fetchall()

    report = {
        'ok': False,
        'transactions': {
            'total': len(ledger), 'replayed': 0, 'skipped_reads': 0,
            'invalid_signatures': [], 'untrusted_signers': [], 'replay_anomalies': [],
            'chain_breaks': [],
            # Failing: mutating row that historical RBAC state would have denied
            # (e.g. low-priv signer writing a system table). Row is still
            # replayed so the table diff stays clean; the violation is the finding.
            'rbac_violations': [],
            # Non-failing: trusted v2 rows from a stale writer amid v3 history
            # whose prev_hash matches the old (no-container) derivation.
            'version_skew': [],
            # Legacy-prefix digest checkpoint (see create_legacy_checkpoint).
            # Absent on pure-chained containers; mismatch fails the audit.
            'legacy_checkpoint': {'status': 'none'},
        },
        'tables': {},
        'code': {},
    }
    txr = report['transactions']

    # Hash-chain state: every row (legacy or chained) advances running_hash;
    # chained rows must link to it and carry consecutive seq values.
    # prev_v2view_hash is the preceding row hashed under the pre-v3 payload
    # view (no container field) — what a stale v2 writer would embed as
    # prev_hash when computing the tip under old code.
    chained_seen = False
    v3_seen = False
    expected_seq = 1
    running_hash = GENESIS_PREV_HASH
    prev_v2view_hash = GENESIS_PREV_HASH
    container_uid = storage.container_uid

    bootstrapped = False
    for (txn_id, query, params_str, signature, pub_key, ts, seq, prev_hash,
         payload_fmt) in ledger:
        try:
            params = json.loads(params_str) if params_str else []
        except json.JSONDecodeError:
            params = []
            txr['replay_anomalies'].append({'id': txn_id, 'error': 'unparseable params JSON'})

        if seq is None:
            payload = payload_from_ledger_row(
                query, params, seq, prev_hash, payload_fmt, container_uid)
            if chained_seen:
                txr['chain_breaks'].append({
                    'id': txn_id,
                    'error': 'unchained legacy row after chained history (spliced or downgraded)'})
        else:
            # Format downgrade / prev_hash mismatch may be benign version skew
            # (stale writer appending v2 after v3) rather than a splice — see
            # the four-condition test below.
            is_v3 = payload_fmt == PAYLOAD_FMT_V3
            would_downgrade = v3_seen and not is_v3
            payload = payload_from_ledger_row(
                query, params, seq, prev_hash, payload_fmt, container_uid)

            seq_ok = (seq == expected_seq)
            if not seq_ok:
                txr['chain_breaks'].append({
                    'id': txn_id,
                    'error': f'seq {seq} where {expected_seq} was expected '
                             '(row dropped, injected, or reordered)'})
                expected_seq = seq  # resync so one gap doesn't cascade

            would_prev_break = (prev_hash != running_hash)
            # Signature + trust needed for the skew classifier; results feed
            # the shared invalid/untrusted reporting below.
            sig_ok = storage.verify_signature(payload, signature, pub_key)
            trusted = bool(sig_ok and storage._signer_is_ca_trusted(pub_key))

            if would_downgrade or would_prev_break:
                # Benign skew: ALL of (1) v2 after v3, (2) valid + trusted sig
                # over the v2 payload, (3) seq continuous, (4) prev_hash equals
                # the previous row hashed under the old no-container view.
                is_benign_skew = (
                    would_downgrade
                    and sig_ok and trusted
                    and seq_ok
                    and prev_hash == prev_v2view_hash
                )
                if is_benign_skew:
                    identity = storage._get_identity(pub_key)
                    txr['version_skew'].append({
                        'id': txn_id,
                        'error': (
                            f'v2 row by {identity} amid v3 history (stale writer)'
                        ),
                    })
                else:
                    if would_downgrade:
                        txr['chain_breaks'].append({
                            'id': txn_id,
                            'error': (
                                'format downgrade: v2 row after v3 history '
                                '(spliced or downgraded)'
                            ),
                        })
                    if would_prev_break:
                        txr['chain_breaks'].append({
                            'id': txn_id,
                            'error': (
                                'prev_hash does not match the preceding row '
                                '(chain broken)'
                            ),
                        })

            chained_seen = True
            if is_v3:
                v3_seen = True
            expected_seq += 1

        # Advance both hash views. running_hash uses the row's stored fmt
        # (subsequent v3 writers chain over skew rows this way). prev_v2view
        # drops the container field so the next row can be classified if a
        # stale writer hashed the tip without knowing about fmt 3.
        running_hash = ledger_row_hash(payload, signature)
        v2view_payload = payload_from_ledger_row(
            query, params, seq, prev_hash,
            None if seq is None else PAYLOAD_FMT_V2,
            None,
        )
        prev_v2view_hash = ledger_row_hash(v2view_payload, signature)

        # Reuse early verification for chained rows; legacy path verifies here.
        if seq is None:
            sig_ok = storage.verify_signature(payload, signature, pub_key)
            trusted = bool(sig_ok and storage._signer_is_ca_trusted(pub_key))
        if not sig_ok:
            txr['invalid_signatures'].append({'id': txn_id, 'query': query[:120]})
        elif not trusted:
            txr['untrusted_signers'].append({'id': txn_id, 'query': query[:120]})

        operation, _ = storage._parse_sql_query(query)
        if operation == 'read':
            txr['skipped_reads'] += 1
        else:
            identity = shadow_store._get_identity(pub_key)
            if not bootstrapped:
                # Mirror bootstrap_admin: first writer claims admin (that
                # insert happens outside the ledger).
                if shadow.execute("SELECT COUNT(*) FROM user_roles").fetchone()[0] == 0:
                    shadow.execute(
                        "INSERT INTO user_roles (identity, role) VALUES (?, 'admin')", (identity,))
                bootstrapped = True
            # Re-check coarse RBAC against historical shadow state *before*
            # executing. Denied rows are flagged but still replayed so the
            # table diff stays clean (the violation itself is the finding).
            allowed, reason = historical_rbac_check(
                shadow, identity, query, storage._parse_sql_query)
            if not allowed:
                txr['rbac_violations'].append({
                    'id': txn_id,
                    'identity': identity,
                    'reason': reason,
                })
            now_holder['ts'] = ts
            shadow_store._active_signer = identity
            try:
                shadow.execute(query, params)
                txr['replayed'] += 1
            except Exception as e:
                if any(t in str(e).lower() for t in _REDUNDANT_DDL):
                    txr['replayed'] += 1  # end state already present via pre-seeded schema
                else:
                    txr['replay_anomalies'].append({'id': txn_id, 'query': query[:120], 'error': str(e)})
            finally:
                shadow_store._active_signer = None
                now_holder['ts'] = None

        # Progressive ledger copy: statements later in the ledger that READ
        # the transactions table see exactly what they saw historically.
        shadow.execute(
            "INSERT INTO transactions "
            "(id, query, params, signature, pub_key, timestamp, seq, prev_hash, payload_fmt) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (txn_id, query, params_str, signature, pub_key, ts, seq, prev_hash, payload_fmt))
    shadow.commit()

    # Diff every user + ledger-driven system table present on either side.
    for table in sorted(_user_tables(live) | _user_tables(shadow)):
        if table not in _user_tables(live):
            report['tables'][table] = {'status': 'missing_in_live'}
        elif table not in _user_tables(shadow):
            report['tables'][table] = {'status': 'unexplained_table'}
        else:
            report['tables'][table] = _diff_table(live, shadow, table)

    # Fold in per-blob code verification (covers the excluded source_code).
    for (code_id,) in live.execute("SELECT id FROM source_code"):
        report['code'][code_id] = storage.get_code_signature_status(code_id)

    # Legacy-prefix checkpoint: when an admin signed a digest of the
    # pre-chaining rows, recompute it over live rows with id <= upto_id.
    # A scrubbed SELECT audit row (previously invisible to the hash chain)
    # fails here. Rows with id > upto_id keep the normal legacy-after-chained
    # / version-skew rules — the checkpoint only fences what it signed.
    cp_raw = live.execute(
        "SELECT value FROM manifest WHERE key = 'legacy_checkpoint'"
    ).fetchone()
    if cp_raw is None:
        txr['legacy_checkpoint'] = {'status': 'none'}
    else:
        cp_value = cp_raw[0]
        try:
            expected = json.loads(cp_value)
            upto_id = expected['upto_id']
            exp_count = expected['count']
            exp_digest = expected['digest']
            act_count, _act_last, act_digest = legacy_prefix_digest(
                storage, upto_id=upto_id)
            if act_count == exp_count and act_digest == exp_digest:
                txr['legacy_checkpoint'] = {
                    'status': 'verified',
                    'count': act_count,
                }
            else:
                txr['legacy_checkpoint'] = {
                    'status': 'mismatch',
                    'expected': {
                        'upto_id': upto_id,
                        'count': exp_count,
                        'digest': exp_digest,
                    },
                    'actual': {
                        'count': act_count,
                        'digest': act_digest,
                    },
                }
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as e:
            txr['legacy_checkpoint'] = {
                'status': 'mismatch',
                'expected': cp_value,
                'actual': f'unparseable: {e}',
            }

    shadow_store.close()
    cp_status = txr['legacy_checkpoint'].get('status')
    report['ok'] = (
        not txr['invalid_signatures']
        and not txr['untrusted_signers']
        and not txr['replay_anomalies']
        and not txr['chain_breaks']
        and not txr['rbac_violations']
        and cp_status != 'mismatch'
        and all(t['status'] in ('match', 'skew') for t in report['tables'].values())
        and all(c['verified'] for c in report['code'].values())
    )
    return report


def format_report(report):
    """Human-readable summary of a replay_audit report."""
    lines = []
    txr = report['transactions']
    lines.append(f"Ledger: {txr['total']} transactions "
                 f"({txr['replayed']} replayed, {txr['skipped_reads']} reads)")
    for item in txr['invalid_signatures']:
        lines.append(f"  [!!] INVALID SIGNATURE on txn #{item['id']}: {item['query']}")
    for item in txr['untrusted_signers']:
        lines.append(f"  [!!] UNTRUSTED SIGNER on txn #{item['id']}: {item['query']}")
    for item in txr['chain_breaks']:
        lines.append(f"  [!!] CHAIN BREAK at txn #{item['id']}: {item['error']}")
    for item in txr.get('version_skew', []):
        lines.append(f"  [~] VERSION SKEW at txn #{item['id']}: {item['error']}")
    cp = txr.get('legacy_checkpoint') or {}
    if cp.get('status') == 'verified':
        lines.append(f"  [OK] legacy checkpoint: {cp.get('count', 0)} rows verified")
    elif cp.get('status') == 'mismatch':
        lines.append(
            f"  [!!] LEGACY CHECKPOINT MISMATCH expected={cp.get('expected')!r} "
            f"actual={cp.get('actual')!r}"
        )
    for item in txr.get('rbac_violations', []):
        lines.append(
            f"  [!!] RBAC VIOLATION on txn #{item['id']}: "
            f"{item.get('reason')} (identity={item.get('identity')})"
        )
    for item in txr['replay_anomalies']:
        lines.append(f"  [!] replay anomaly on txn #{item['id']}: {item.get('error')}")
    for table, result in report['tables'].items():
        status = result['status']
        if status == 'match':
            lines.append(f"  [OK] {table}: matches ledger replay")
        elif status == 'skew':
            lines.append(f"  [OK] {table}: matches (timestamp skew on "
                         f"{len(result['timestamp_skews'])} row(s))")
        else:
            lines.append(f"  [!!] {table}: {status}")
            for r in result.get('unexplained_rows', []):
                lines.append(f"        unexplained row {r['key']}: {r['row']}")
            for r in result.get('missing_rows', []):
                lines.append(f"        missing row {r['key']}: {r['row']}")
            for r in result.get('changed_rows', []):
                lines.append(f"        changed row {r['key']}: {r['diffs']}")
    for code_id, status in report['code'].items():
        tag = 'OK' if status['verified'] else '!!'
        lines.append(f"  [{tag}] code '{code_id}': signer={status['signer']}"
                     + ('' if status['verified'] else f" error={status['error']}"))
    lines.append(f"AUDIT {'PASSED' if report['ok'] else 'FAILED'}")
    return '\n'.join(lines)
