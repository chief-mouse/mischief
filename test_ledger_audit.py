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

import json
import sqlite3
from mschf.storage import (
    MSFStorage, PAYLOAD_FMT_V3, canonical_payload, create_legacy_checkpoint,
    legacy_prefix_digest, make_json_serializable,
)
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
    assert not report['transactions'].get('rbac_violations'), (
        "clean container must have zero rbac_violations"
    )

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

    # ------------------------------------------------------------------
    # 12–16. Legacy-prefix checkpoint (closes scrubbing gap for seq IS NULL)
    # ------------------------------------------------------------------
    print("--- 12. Legacy checkpoint: create, verify, no-op re-run ---")
    db8_path = 'test_ledger_audit_legacy_cp.msf'
    if os.path.exists(db8_path):
        os.remove(db8_path)
    db8 = MSFStorage(db8_path)
    db8.conn.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
    db8.conn.commit()

    admin_key_obj = serialization.load_pem_private_key(
        admin_key, password=None, backend=default_backend())

    def insert_v1_legacy(query, params, apply_sql=True, ts='2020-01-01 00:00:00'):
        """Hand-craft a valid v1 (seq NULL) ledger row from the trusted cert."""
        payload = canonical_payload(query, params)  # v1: no seq
        sig = admin_key_obj.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        if apply_sql:
            db8._active_signer = db8._get_identity(admin_cert)
            try:
                if params:
                    db8.conn.execute(query, params)
                else:
                    db8.conn.execute(query)
            finally:
                db8._active_signer = None
        db8.conn.execute(
            "INSERT INTO transactions "
            "(query, params, signature, pub_key, timestamp, seq, prev_hash, payload_fmt) "
            "VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)",
            (query, _json.dumps(params), sig, admin_cert, ts),
        )
        db8.conn.commit()
        return db8.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # 3+ legacy rows including a SELECT audit row (scrub target).
    insert_v1_legacy(
        "INSERT INTO notes (body) VALUES (?)", ['legacy-a'], ts='2020-01-01 00:00:01')
    insert_v1_legacy(
        "INSERT INTO notes (body) VALUES (?)", ['legacy-b'], ts='2020-01-01 00:00:02')
    select_id = insert_v1_legacy(
        "SELECT id, body FROM notes", [], apply_sql=False, ts='2020-01-01 00:00:03')
    insert_v1_legacy(
        "INSERT INTO notes (body) VALUES (?)", ['legacy-c'], ts='2020-01-01 00:00:04')

    legacy_n = db8.conn.execute(
        "SELECT COUNT(*) FROM transactions WHERE seq IS NULL").fetchone()[0]
    assert legacy_n >= 3, f"expected 3+ legacy rows, got {legacy_n}"

    def signed8(query, params, bootstrap=False):
        sig = make_signed_payload(db8, query, params, admin_key)
        if bootstrap:
            return db8.bootstrap_admin(query, params, sig, admin_cert)
        return db8.execute_signed(query, params, sig, admin_cert)

    # Chained v3 history after the legacy prefix.
    signed8("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'], bootstrap=True)
    signed8("INSERT INTO notes (body) VALUES (?)", ['chained-1'])

    count0, last0, dig0 = legacy_prefix_digest(db8)
    assert count0 == legacy_n and last0 > 0 and len(dig0) == 64

    cp = create_legacy_checkpoint(db8, admin_key, admin_cert)
    assert cp['count'] == count0 and cp['digest'] == dig0
    assert cp['upto_id'] == last0
    report = replay_audit(db8)
    print(format_report(report))
    assert report['ok'], "checkpointed container must audit clean"
    assert report['transactions']['legacy_checkpoint']['status'] == 'verified'
    assert report['transactions']['legacy_checkpoint']['count'] == count0
    print(f"  [OK] create_legacy_checkpoint → audit verified ({count0} rows)")

    print("--- 13. Idempotent re-run is a no-op ---")
    n_before = db8.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    cp2 = create_legacy_checkpoint(db8, admin_key, admin_cert)
    n_after = db8.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    assert n_before == n_after, "identical-state re-run must not append a ledger row"
    assert cp2['digest'] == dig0
    print(f"  [OK] re-run no-op (txn count still {n_after})")

    print("--- 14. Scrubbing a legacy SELECT audit row fails the checkpoint ---")
    # Capture the row so we can restore it with identical values (incl. id).
    select_row = db8.conn.execute(
        "SELECT id, query, params, signature, pub_key, timestamp, seq, prev_hash, payload_fmt "
        "FROM transactions WHERE id = ?", (select_id,)
    ).fetchone()
    assert select_row is not None and select_row[0] == select_id
    raw8 = sqlite3.connect(db8_path)
    raw8.execute("DELETE FROM transactions WHERE id = ?", (select_id,))
    raw8.commit()
    raw8.close()

    report = replay_audit(db8)
    print(format_report(report))
    assert not report['ok'], "scrubbed legacy SELECT must fail audit"
    cp_rep = report['transactions']['legacy_checkpoint']
    assert cp_rep['status'] == 'mismatch', cp_rep
    print(f"  [OK] deleted legacy SELECT → legacy_checkpoint mismatch")

    print("--- 15. Restore identical row → audit passes again ---")
    raw8 = sqlite3.connect(db8_path)
    raw8.execute(
        "INSERT INTO transactions "
        "(id, query, params, signature, pub_key, timestamp, seq, prev_hash, payload_fmt) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        select_row,
    )
    raw8.commit()
    raw8.close()

    report = replay_audit(db8)
    print(format_report(report))
    assert report['ok'], "restored identical legacy row must pass"
    assert report['transactions']['legacy_checkpoint']['status'] == 'verified'
    print(f"  [OK] content-based restore (same id/fields) re-verifies")
    db8.close()
    os.remove(db8_path)

    print("--- 16. No legacy rows → refuse checkpoint; audit status none ---")
    db9_path = 'test_ledger_audit_no_legacy.msf'
    if os.path.exists(db9_path):
        os.remove(db9_path)
    db9 = MSFStorage(db9_path)
    db9.conn.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
    db9.conn.commit()

    def signed9(query, params, bootstrap=False):
        sig = make_signed_payload(db9, query, params, admin_key)
        if bootstrap:
            return db9.bootstrap_admin(query, params, sig, admin_cert)
        return db9.execute_signed(query, params, sig, admin_cert)

    signed9("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'], bootstrap=True)
    signed9("INSERT INTO notes (body) VALUES (?)", ['pure-v3'])

    try:
        create_legacy_checkpoint(db9, admin_key, admin_cert)
        raise AssertionError("create_legacy_checkpoint must refuse empty legacy prefix")
    except ValueError as e:
        assert 'legacy' in str(e).lower() or 'no legacy' in str(e).lower(), e
        print(f"  [OK] refused: {e}")

    report = replay_audit(db9)
    print(format_report(report))
    assert report['ok'], "pure-v3 container without checkpoint must still pass"
    assert report['transactions']['legacy_checkpoint']['status'] == 'none'
    print(f"  [OK] audit status=none, ok=True")
    db9.close()
    os.remove(db9_path)

    print("\n--- 10. Historical RBAC violation flagged; table diff stays clean ---")
    # Low-priv writer with notes-only rights; a colluding raw insert of a
    # correctly-signed system-table write must surface as rbac_violations
    # (not as unexplained/changed rows — the row is still replayed).
    db10_path = 'test_ledger_audit_rbac.msf'
    if os.path.exists(db10_path):
        os.remove(db10_path)
    writer_cert, writer_key = generate_user_cert(
        'audit_writer', ca_cert_pem, ca_key_pem)
    db10 = MSFStorage(db10_path)

    def signed10(query, params, bootstrap=False):
        sig = make_signed_payload(db10, query, params, admin_key)
        if bootstrap:
            return db10.bootstrap_admin(query, params, sig, admin_cert)
        return db10.execute_signed(query, params, sig, admin_cert)

    db10.conn.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
    db10.conn.commit()
    signed10(
        "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
        ['entry_point', 'none'], bootstrap=True)
    for level, target, role, perm in [
        ('database', '*', 'writer', 'read'),
        ('database', '*', 'writer', 'write'),
        ('object', 'notes', 'writer', 'write'),
        ('object', 'notes', 'writer', 'read'),
    ]:
        signed10(
            "INSERT INTO rbac_rules (level, target, role, permission) "
            "VALUES (?, ?, ?, ?)",
            [level, target, role, perm],
        )
    signed10(
        "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
        ['cert:CN=audit_writer', 'writer'],
    )
    signed10("INSERT INTO notes (body) VALUES (?)", ['legit'])

    clean = replay_audit(db10)
    assert clean['ok']
    assert not clean['transactions']['rbac_violations']
    print("  [OK] clean multi-role container has zero rbac_violations")

    poison_q = (
        "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
    )
    poison_params = ['cert:CN=evil', 'admin']
    next_seq, prev_hash = db10.get_chain_head()
    payload = canonical_payload(
        poison_q, poison_params, next_seq, prev_hash, db10.container_uid)
    key = serialization.load_pem_private_key(
        writer_key, password=None, backend=default_backend())
    poison_sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    from datetime import datetime as _dt
    ts = _dt.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    params_str = json.dumps(make_json_serializable(poison_params))
    pub_key_val = (
        writer_cert.decode('utf-8') if isinstance(writer_cert, bytes)
        else writer_cert
    )
    raw10 = sqlite3.connect(db10_path)
    raw10.execute(poison_q, poison_params)
    raw10.execute(
        "INSERT INTO transactions "
        "(query, params, signature, pub_key, timestamp, seq, prev_hash, "
        "payload_fmt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (poison_q, params_str, poison_sig, pub_key_val, ts,
         next_seq, prev_hash, PAYLOAD_FMT_V3),
    )
    raw10.commit()
    raw10.close()

    # MSFStorage may hold a stale snapshot of user_roles; re-open for audit.
    db10.close()
    db10 = MSFStorage(db10_path)
    report = replay_audit(db10)
    print(format_report(report))
    assert not report['ok'], "poisoned container must fail audit"
    violations = report['transactions']['rbac_violations']
    assert violations, "expected rbac_violations"
    assert any(
        v.get('identity') == 'cert:CN=audit_writer' for v in violations
    ), violations
    # Table diff must stay clean: violation is flagged, not double-reported
    # as unexplained/changed rows from a failed replay.
    for table, result in report['tables'].items():
        assert result['status'] in ('match', 'skew'), (
            f"{table} should match after replaying the denied row, got {result}"
        )
    print(f"  [OK] rbac_violations={violations}; table diffs clean")
    db10.close()
    os.remove(db10_path)

    print("\n==========================================")
    print("ALL LEDGER AUDIT TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
