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
  7. OOB NULL-seq injection after chained history -> flagged as a chain
     break, get_chain_head does NOT reset the sequence (next_seq comes from
     MAX(seq), not the tip row), and legitimate writes continue the chain
     with no cascading breaks.
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
    payload_bytes = canonical_payload(
        query, params, next_seq, prev_hash, db.container_uid)
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

    print("--- 8. OOB NULL-seq tip must not reset the chain sequence ---")
    db2_path = 'test_ledger_audit_nulltip.msf'
    if os.path.exists(db2_path):
        os.remove(db2_path)
    db2 = MSFStorage(db2_path)
    db2.conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
    db2.conn.commit()

    def signed2(query, params, bootstrap=False):
        sig = make_signed_payload(db2, query, params, admin_key)
        if bootstrap:
            return db2.bootstrap_admin(query, params, sig, admin_cert)
        return db2.execute_signed(query, params, sig, admin_cert)

    signed2("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", ['entry_point', 'none'], bootstrap=True)
    signed2("INSERT INTO notes (body) VALUES (?)", ['first'])   # seq 2

    # Attacker appends a raw, unchained ledger row after chained history.
    raw2 = sqlite3.connect(db2_path)
    raw2.execute("INSERT INTO transactions (query, params, signature, pub_key) VALUES (?, ?, ?, ?)",
                 ("INSERT INTO notes (body) VALUES (?)", '["oob"]', b'\x00', 'garbage'))
    raw2.commit()
    raw2.close()

    next_seq, _ = db2.get_chain_head()
    assert next_seq == 3, f"NULL-seq tip must not reset the sequence (got next_seq={next_seq})"
    signed2("INSERT INTO notes (body) VALUES (?)", ['after pollution'])  # seq 3

    report = replay_audit(db2)
    breaks = report['transactions']['chain_breaks']
    assert not report['ok'], "polluted ledger must fail the audit"
    assert len(breaks) == 1 and 'unchained' in breaks[0]['error'], \
        f"expected exactly the injected row flagged, got {breaks}"
    seqs = [r[0] for r in db2.conn.execute(
        "SELECT seq FROM transactions WHERE seq IS NOT NULL ORDER BY id")]
    assert seqs == [1, 2, 3], f"chained sequence must stay continuous, got {seqs}"
    print(f"  [OK] injected row flagged, sequence continued 1..3, no cascade: {breaks[0]['error']}")
    db2.close()
    os.remove(db2_path)

    # ------------------------------------------------------------------
    # 9–11. Version-skew downgrade policy + payload_fmt_floor guard
    # ------------------------------------------------------------------
    from mschf.storage import (
        ledger_row_hash, payload_from_ledger_row, set_payload_fmt_floor,
        PAYLOAD_FMT_V2, PAYLOAD_FMT_V3,
    )
    import json as _json

    def _build_v3_notes_container(path, cert, key_pem):
        if os.path.exists(path):
            os.remove(path)
        store = MSFStorage(path)
        store.conn.execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
        store.conn.commit()

        def _signed(query, params, bootstrap=False):
            sig = make_signed_payload(store, query, params, key_pem)
            if bootstrap:
                return store.bootstrap_admin(query, params, sig, cert)
            return store.execute_signed(query, params, sig, cert)

        _signed("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
                ['entry_point', 'none'], bootstrap=True)
        _signed("INSERT INTO notes (body) VALUES (?)", ['a'])
        _signed("INSERT INTO notes (body) VALUES (?)", ['b'])
        return store, _signed

    def _stale_v2_append(store, cert, key_pem, query, params,
                        prev_hash_override=None, seq_override=None,
                        signer_cert=None, signer_key=None):
        """Simulate a pre-v3 writer: hash tip under the no-container view,
        sign a v2 payload, raw-insert with payload_fmt NULL. Optionally
        corrupt prev_hash/seq or swap the signer for malice variants.
        """
        cert = signer_cert if signer_cert is not None else cert
        key_pem = signer_key if signer_key is not None else key_pem
        # Tip under the stored fmt (what get_chain_head returns) — used only
        # for next_seq; prev_hash is recomputed under the old v2 view.
        next_seq, _ = store.get_chain_head()
        if seq_override is not None:
            next_seq = seq_override

        tip = store.conn.execute(
            "SELECT query, params, signature, seq, prev_hash, payload_fmt "
            "FROM transactions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if tip is None:
            v2_prev = ''
        else:
            tq, tps, tsig, tseq, tph, tfmt = tip
            try:
                tparams = _json.loads(tps) if tps else []
            except _json.JSONDecodeError:
                tparams = []
            # Old writer reconstructed the tip without the container field.
            v2view = payload_from_ledger_row(
                tq, tparams, tseq, tph,
                None if tseq is None else PAYLOAD_FMT_V2,
                None,
            )
            v2_prev = ledger_row_hash(v2view, tsig)

        if prev_hash_override is not None:
            v2_prev = prev_hash_override

        payload = canonical_payload(query, params, next_seq, v2_prev)  # no uid
        key = serialization.load_pem_private_key(
            key_pem, password=None, backend=default_backend())
        sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

        # Apply the SQL so live state matches (audit diffs rows too).
        store._active_signer = store._get_identity(cert)
        try:
            if params:
                store.conn.execute(query, params)
            else:
                store.conn.execute(query)
        finally:
            store._active_signer = None
        store.conn.execute(
            "INSERT INTO transactions "
            "(query, params, signature, pub_key, seq, prev_hash, payload_fmt) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (query, _json.dumps(params), sig, cert, next_seq, v2_prev),
        )
        store.conn.commit()
        return next_seq

    print("--- 9. Benign version skew warns; audit still passes ---")
    db3_path = 'test_ledger_audit_skew.msf'
    db3, signed3 = _build_v3_notes_container(db3_path, admin_cert, admin_key)

    # One skew row, then a normal v3 write (mirrors the live incident).
    _stale_v2_append(
        db3, admin_cert, admin_key,
        "SELECT id, body FROM notes", [])
    signed3("INSERT INTO notes (body) VALUES (?)", ['after-skew-1'])

    report = replay_audit(db3)
    print(format_report(report))
    assert report['ok'], "benign skew must not fail the audit"
    skews = report['transactions']['version_skew']
    breaks = report['transactions']['chain_breaks']
    assert len(skews) == 1, f"expected one version_skew, got {skews}"
    assert len(breaks) == 0, f"expected no chain_breaks, got {breaks}"
    assert 'stale writer' in skews[0]['error']
    print(f"  [OK] single skew: txn #{skews[0]['id']} — {skews[0]['error']}")

    # Twice-interleaved (skew, v3, skew, v3) — real tracker had two skew rows.
    _stale_v2_append(
        db3, admin_cert, admin_key,
        "SELECT id, body FROM notes", [])
    signed3("INSERT INTO notes (body) VALUES (?)", ['after-skew-2'])
    report = replay_audit(db3)
    print(format_report(report))
    assert report['ok'], "interleaved benign skew must still pass"
    skews = report['transactions']['version_skew']
    breaks = report['transactions']['chain_breaks']
    assert len(skews) == 2, f"expected two version_skew entries, got {skews}"
    assert len(breaks) == 0, f"expected no chain_breaks, got {breaks}"
    print(f"  [OK] interleaved skew x2, audit ok, no chain_breaks")
    db3.close()
    os.remove(db3_path)

    print("--- 10. Malice still fails (untrusted / garbage prev / seq gap) ---")
    # 10a. Same construction but signed by a rogue (untrusted) CA cert.
    rogue_ca_pem, rogue_ca_key = generate_selfsigned_cert("Rogue Skew CA")
    rogue_cert, rogue_key = generate_user_cert(
        'rogue_skew', rogue_ca_pem, rogue_ca_key)
    db4_path = 'test_ledger_audit_malice.msf'
    db4, signed4 = _build_v3_notes_container(db4_path, admin_cert, admin_key)
    _stale_v2_append(
        db4, admin_cert, admin_key,
        "SELECT id FROM notes", [],
        signer_cert=rogue_cert, signer_key=rogue_key)
    report = replay_audit(db4)
    assert not report['ok']
    assert report['transactions']['chain_breaks'] or report['transactions']['untrusted_signers'], \
        report['transactions']
    # Untrusted signer alone fails ok; also expect format-downgrade chain break
    # because benign-skew condition (2) requires a trusted signer.
    assert any(
        'format downgrade' in b['error'] or 'prev_hash' in b['error']
        for b in report['transactions']['chain_breaks']
    ) or report['transactions']['untrusted_signers'], report
    assert len(report['transactions']['version_skew']) == 0
    print("  [OK] untrusted signer → not classified as version_skew, audit fails")
    db4.close()
    os.remove(db4_path)

    # 10b. Garbage prev_hash (matches neither derivation).
    db5_path = 'test_ledger_audit_garbage_prev.msf'
    db5, signed5 = _build_v3_notes_container(db5_path, admin_cert, admin_key)
    _stale_v2_append(
        db5, admin_cert, admin_key,
        "SELECT id FROM notes", [],
        prev_hash_override='0' * 64)
    report = replay_audit(db5)
    assert not report['ok']
    breaks = report['transactions']['chain_breaks']
    assert any('prev_hash' in b['error'] or 'format downgrade' in b['error']
               for b in breaks), breaks
    assert len(report['transactions']['version_skew']) == 0
    print(f"  [OK] garbage prev_hash → chain_breaks, not version_skew: {breaks[0]['error']}")
    db5.close()
    os.remove(db5_path)

    # 10c. Seq gap.
    db6_path = 'test_ledger_audit_seq_gap.msf'
    db6, signed6 = _build_v3_notes_container(db6_path, admin_cert, admin_key)
    next_seq, _ = db6.get_chain_head()
    _stale_v2_append(
        db6, admin_cert, admin_key,
        "SELECT id FROM notes", [],
        seq_override=next_seq + 5)
    report = replay_audit(db6)
    assert not report['ok']
    breaks = report['transactions']['chain_breaks']
    assert any('seq' in b['error'] for b in breaks), breaks
    assert len(report['transactions']['version_skew']) == 0
    print(f"  [OK] seq gap → chain_breaks, not version_skew: "
          f"{[b['error'] for b in breaks]}")
    db6.close()
    os.remove(db6_path)

    print("--- 11. payload_fmt_floor guard ---")
    db7_path = 'test_ledger_audit_floor.msf'
    db7, signed7 = _build_v3_notes_container(db7_path, admin_cert, admin_key)
    # Floor equal to current writer format is a no-op.
    set_payload_fmt_floor(db7, PAYLOAD_FMT_V3)
    signed7("INSERT INTO notes (body) VALUES (?)", ['floor-3-ok'])
    print("  [OK] floor=3 allows current writer")
    # Floor above current format blocks.
    set_payload_fmt_floor(db7, 4)
    try:
        signed7("INSERT INTO notes (body) VALUES (?)", ['should-fail'])
        raise AssertionError("floor=4 must reject fmt-3 writer")
    except PermissionError as e:
        assert 'payload_fmt_floor' in str(e) or 'floor' in str(e).lower(), e
        assert '4' in str(e), e
        print(f"  [OK] floor=4 blocks writer: {e}")
    db7.close()
    os.remove(db7_path)

    print("\n==========================================")
    print("ALL LEDGER AUDIT TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
