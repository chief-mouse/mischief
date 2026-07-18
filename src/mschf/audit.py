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

from mschf.storage import MSFStorage

# Tables never diffed: transactions is the replay input, source_code is
# verified via signatures (see module docstring), sqlite_sequence is engine
# bookkeeping.
EXCLUDED_TABLES = {'transactions', 'source_code', 'sqlite_sequence'}

# Replay errors that only mean "the pre-seeded live schema already contains
# this DDL's end state" — safe to skip.
_REDUNDANT_DDL = ('duplicate column name', 'already exists')

_TS_FORMAT = '%Y-%m-%d %H:%M:%S'


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
    shadow_store = MSFStorage(':memory:', ca_cert_path=storage.ca_cert_path)
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
    system = {'manifest', 'source_code', 'transactions', 'rbac_rules', 'user_roles'}
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
        "SELECT id, query, params, signature, pub_key, timestamp FROM transactions ORDER BY id"
    ).fetchall()

    report = {
        'ok': False,
        'transactions': {
            'total': len(ledger), 'replayed': 0, 'skipped_reads': 0,
            'invalid_signatures': [], 'untrusted_signers': [], 'replay_anomalies': [],
        },
        'tables': {},
        'code': {},
    }
    txr = report['transactions']

    bootstrapped = False
    for txn_id, query, params_str, signature, pub_key, ts in ledger:
        try:
            params = json.loads(params_str) if params_str else []
        except json.JSONDecodeError:
            params = []
            txr['replay_anomalies'].append({'id': txn_id, 'error': 'unparseable params JSON'})

        payload = json.dumps({'query': query, 'params': params}, sort_keys=True).encode('utf-8')
        if not storage.verify_signature(payload, signature, pub_key):
            txr['invalid_signatures'].append({'id': txn_id, 'query': query[:120]})
        elif not storage._signer_is_ca_trusted(pub_key):
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
            "INSERT INTO transactions (id, query, params, signature, pub_key, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (txn_id, query, params_str, signature, pub_key, ts))
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

    shadow_store.close()
    report['ok'] = (
        not txr['invalid_signatures']
        and not txr['untrusted_signers']
        and not txr['replay_anomalies']
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
