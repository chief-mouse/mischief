"""Ledger replay audit test.

Builds a container the auditable way (bootstrap -> signed trigger DDL ->
signed data mutations, mirroring dev_tracker.py init), asserts a clean audit,
then tampers with the file out-of-band exactly as an attacker with a raw
sqlite3 client would, and asserts every class of tampering is flagged:

  1. changed row     (raw UPDATE)         -> changed_rows names the column
  2. injected row    (raw INSERT)         -> unexplained_rows
  3. deleted row     (raw DELETE)         -> missing_rows
  4. edited ledger   (raw UPDATE on transactions.query) -> invalid signature
  5. dropped ledger row (raw DELETE on transactions)    -> chain break
                      (each signed payload embeds seq + prev-row hash, so
                      removing or reordering rows breaks the hash chain even
                      though every remaining row's own signature verifies)
  6. trigger shield  (raw DML on a trigger-guarded table fails outright:
                      current_signer() doesn't exist outside the host)
"""
import sys
import os
sys.path.insert(0, os.path.abspath('src'))

import sqlite3
from mschf.storage import MSFStorage, canonical_payload
from mschf.audit import replay_audit, format_report
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert, default_backend, serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from dev_tracker import AUDIT_TRIGGERS  # canonical trigger pattern


def make_signed_payload(db, query, params, pem_key_bytes):
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(query, params, next_seq, prev_hash)
    key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())
    return key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())


def run():
    db_path = 'test_ledger_audit.msf'
    if os.path.exists(db_path):
        os.remove(db_path)

    ca_cert_path, ca_key_path = 'ca.crt', 'ca.key'
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        ca_pem, ca_key_pem_new = generate_selfsigned_cert("Temporary Root CA")
        with open(ca_cert_path, 'wb') as f:
            f.write(ca_pem)
        with open(ca_key_path, 'wb') as f:
            f.write(ca_key_pem_new)
    with open(ca_cert_path, 'rb') as f:
        ca_cert_pem = f.read()
    with open(ca_key_path, 'rb') as f:
        ca_key_pem = f.read()
    admin_cert, admin_key = generate_user_cert('audit_admin', ca_cert_pem, ca_key_pem)

    db = MSFStorage(db_path)

    def signed(query, params, bootstrap=False):
        sig = make_signed_payload(db, query, params, admin_key)
        if bootstrap:
            return db.bootstrap_admin(query, params, sig, admin_cert)
        return db.execute_signed(query, params, sig, admin_cert)

    print("--- Building auditable container ---")
    # Tables: unsigned authoring (pre-seeded from live schema during replay).
    # dev_tasks mirrors the dev tracker (trigger-guarded); notes has none.
    db.conn.execute(
        "CREATE TABLE dev_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, "
        "detail TEXT, status TEXT NOT NULL DEFAULT 'backlog', "
        "created_at TEXT DEFAULT (datetime('now')), created_by TEXT, "
        "updated_at TEXT DEFAULT (datetime('now')), updated_by TEXT)")
    db.conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
    db.conn.commit()

    signed("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", ['entry_point', 'none'], bootstrap=True)
    for ddl in AUDIT_TRIGGERS:
        signed(ddl, [])
    signed("INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, ?)", ['task one', 'd1', 'backlog'])
    signed("INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, ?)", ['task two', 'd2', 'backlog'])
    signed("UPDATE dev_tasks SET status = ? WHERE id = ?", ['done', 1])
    signed("INSERT INTO notes (body) VALUES (?)", ['legit note'])
    signed("ALTER TABLE notes ADD COLUMN tag TEXT", [])            # migration -> duplicate-column tolerance
    signed("UPDATE notes SET tag = ? WHERE id = ?", ['misc', 1])
    signed("SELECT id, title FROM dev_tasks", []).fetchall()        # audit-row churn

    print("--- 1. Clean container audits clean ---")
    report = replay_audit(db)
    print(format_report(report))
    assert report['ok'], "clean container must pass"
    assert report['tables']['dev_tasks']['status'] in ('match', 'skew')

    print("\n--- 2-4. Out-of-band tampering (raw sqlite3, no signatures) ---")
    raw = sqlite3.connect(db_path)
    raw.execute("UPDATE notes SET body = 'DOCTORED' WHERE id = 1")          # change
    raw.execute("INSERT INTO notes (id, body) VALUES (99, 'injected')")     # inject
    raw.execute("DELETE FROM dev_tasks WHERE id = 2")                       # delete (no per-row trigger blocks DELETE)
    raw.commit()

    report = replay_audit(db)
    notes = report['tables']['notes']
    tasks = report['tables']['dev_tasks']
    assert not report['ok'], "tampered container must fail"
    assert any(d['column'] == 'body' for c in notes['changed_rows'] for d in c['diffs']), notes
    print("  [OK] doctored row flagged (notes.body)")
    assert any(r['key'] == (99,) for r in notes['unexplained_rows']), notes
    print("  [OK] injected row flagged (notes id=99)")
    assert any(r['key'] == (2,) for r in tasks['missing_rows']), tasks
    print("  [OK] deleted row flagged (dev_tasks id=2)")

    print("--- 5. Ledger tampering breaks the signature ---")
    # Queries are parameterized, so the payload's attacker-visible content
    # lives in the params JSON — doctor it there.
    raw.execute("UPDATE transactions SET params = replace(params, 'task one', 'task 0wned') "
                "WHERE params LIKE '%task one%'")
    raw.commit()
    report = replay_audit(db)
    assert report['transactions']['invalid_signatures'], "edited ledger row must fail verification"
    print(f"  [OK] invalid signature flagged: txn #{report['transactions']['invalid_signatures'][0]['id']}")

    print("--- 6. Dropped ledger row breaks the hash chain ---")
    # Delete a mid-chain row: every remaining signature still verifies, but the
    # seq gap and prev_hash mismatch expose the removal.
    victim = raw.execute(
        "SELECT id FROM transactions WHERE seq IS NOT NULL "
        "ORDER BY seq LIMIT 1 OFFSET 3").fetchone()[0]
    raw.execute("DELETE FROM transactions WHERE id = ?", (victim,))
    raw.commit()
    report = replay_audit(db)
    breaks = report['transactions']['chain_breaks']
    assert any('seq' in b['error'] for b in breaks), f"expected a seq-gap chain break, got {breaks}"
    assert not report['ok']
    print(f"  [OK] dropped row flagged as chain break: {breaks[0]['error']}")

    print("--- 7. Trigger shield: raw DML on guarded tables fails outright ---")
    try:
        raw.execute("INSERT INTO dev_tasks (title) VALUES ('sneaky')")
        raise AssertionError("raw insert into trigger-guarded table should fail")
    except sqlite3.OperationalError as e:
        assert 'current_signer' in str(e), e
        print(f"  [OK] raw write rejected by container trigger: {e}")
    raw.close()

    db.close()
    os.remove(db_path)
    print("\n==========================================")
    print("ALL LEDGER AUDIT TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
