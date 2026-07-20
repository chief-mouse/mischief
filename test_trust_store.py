"""Integration tests for configurable trust anchors (org CA / trust store).

Run: python test_trust_store.py
"""
import sys
import os
import shutil
import tempfile

sys.path.insert(0, os.path.abspath('src'))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from mschf.storage import MSFStorage, canonical_payload
from mschf.gen_cert import (
    generate_selfsigned_cert,
    generate_user_cert,
    default_backend,
    serialization,
)
from mschf.identity import Identity
from mschf.audit import replay_audit


def make_signed_payload(db, query, params, pem_key_bytes):
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(
        query, params, next_seq, prev_hash, db.container_uid)
    private_key = serialization.load_pem_private_key(
        pem_key_bytes, password=None, backend=default_backend()
    )
    return private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())


def run_trust_store_test():
    artifacts = []
    trust_dir = None
    empty_trust_dir = None
    db_path = 'test_trust_store.msf'
    db2_path = 'test_trust_store_empty.msf'
    org_user_cert_path = 'org_user_trust_test.crt'
    org_user_key_path = 'org_user_trust_test.key'

    def track(path):
        artifacts.append(path)
        return path

    try:
        # --- Host Root CA (reuse project files; never overwrite if present) ---
        print("--- Host Root CA ---")
        ca_cert_path, ca_key_path = 'ca.crt', 'ca.key'
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            pem_ca_cert, pem_ca_key = generate_selfsigned_cert("Temporary Root CA")
            with open(ca_cert_path, 'wb') as f:
                f.write(pem_ca_cert)
            with open(ca_key_path, 'wb') as f:
                f.write(pem_ca_key)
            print("Generated temporary host ca.crt / ca.key")
        else:
            print("Reusing existing host ca.crt / ca.key")

        with open(ca_cert_path, 'rb') as f:
            host_ca_cert = f.read()
        with open(ca_key_path, 'rb') as f:
            host_ca_key = f.read()

        host_admin_cert, host_admin_key = generate_user_cert(
            'host_admin', host_ca_cert, host_ca_key
        )

        # --- Org CA + org user in temp trust dir ---
        print("\n--- Org CA trust store setup ---")
        trust_dir = tempfile.mkdtemp(prefix='mschf_trust_')
        empty_trust_dir = tempfile.mkdtemp(prefix='mschf_trust_empty_')

        org_ca_cert, org_ca_key = generate_selfsigned_cert("Org Root CA")
        org_ca_path = os.path.join(trust_dir, 'org_ca.crt')
        with open(org_ca_path, 'wb') as f:
            f.write(org_ca_cert)

        # Garbage in trust dir must be skipped (not raise).
        junk_path = os.path.join(trust_dir, 'junk.crt')
        with open(junk_path, 'w', encoding='utf-8') as f:
            f.write('this is not a certificate\n')
        print(f"Wrote org_ca.crt + junk.crt into {trust_dir}")

        org_user_cert, org_user_key = generate_user_cert(
            'org_user', org_ca_cert, org_ca_key
        )
        with open(track(org_user_cert_path), 'wb') as f:
            f.write(org_user_cert)
        with open(track(org_user_key_path), 'wb') as f:
            f.write(org_user_key)

        # Untrusted CA (not in trust dir)
        other_ca_cert, other_ca_key = generate_selfsigned_cert("Untrusted Other CA")
        untrusted_cert, untrusted_key = generate_user_cert(
            'untrusted_user', other_ca_cert, other_ca_key
        )

        # --- 1. Org-CA trust via trust store ---
        print("\n--- 1. Org-CA trust via trust store ---")
        if os.path.exists(db_path):
            os.remove(db_path)
        track(db_path)

        db = MSFStorage(db_path, trust_dir=trust_dir)
        host_admin_id = db._get_identity(host_admin_cert)
        org_user_id = db._get_identity(org_user_cert)
        print(f"Host admin identity: {host_admin_id}")
        print(f"Org user identity:   {org_user_id}")

        # Bootstrap admin with host-CA identity
        sig = make_signed_payload(
            db,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'main'],
            host_admin_key,
        )
        db.bootstrap_admin(
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'main'],
            sig,
            host_admin_cert,
        )
        print("✓ Host admin bootstrapped")

        # Create notes table + RBAC so org_user can write
        sig = make_signed_payload(
            db,
            "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)",
            [],
            host_admin_key,
        )
        db.create_object_table('notes', {'body': 'TEXT'}, sig, host_admin_cert)

        sig = make_signed_payload(
            db,
            "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
            [org_user_id, 'writer'],
            host_admin_key,
        )
        db.assign_user_role(org_user_id, 'writer', sig, host_admin_cert)

        for level, target, perm in (
            ('database', '*', '*'),
            ('object', 'notes', 'write'),
            ('object', 'notes', 'read'),
        ):
            sig = make_signed_payload(
                db,
                "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
                [level, target, 'writer', perm],
                host_admin_key,
            )
            db.add_rbac_rule(level, target, 'writer', perm, sig, host_admin_cert)

        # Org user signed INSERT must succeed (org CA is in trust dir)
        sig = make_signed_payload(
            db, "INSERT INTO notes (body) VALUES (?)", ['hello from org'], org_user_key
        )
        db.execute_signed(
            "INSERT INTO notes (body) VALUES (?)",
            ['hello from org'],
            sig,
            org_user_cert,
        )
        row = db.conn.execute("SELECT body FROM notes").fetchone()
        assert row and row[0] == 'hello from org', f"Expected org write, got {row}"
        print("✓ Org-user signed INSERT accepted via trust store")

        report = replay_audit(db)
        assert report['ok'], f"replay_audit failed: {report}"
        print("✓ replay_audit passed (shadow store mirrors trust_dir)")

        # --- 2. Untrusted CA still rejected ---
        print("\n--- 2. Untrusted CA still rejected ---")
        before_count = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        sig = make_signed_payload(
            db, "INSERT INTO notes (body) VALUES (?)", ['evil'], untrusted_key
        )
        try:
            db.execute_signed(
                "INSERT INTO notes (body) VALUES (?)",
                ['evil'],
                sig,
                untrusted_cert,
            )
            raise AssertionError("Untrusted CA signer was accepted!")
        except PermissionError as e:
            assert "Chain Verification Failed" in str(e), f"Unexpected error: {e}"
            print(f"✓ Untrusted CA rejected: {e}")
        after_count = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        assert after_count == before_count, "Ledger grew after rejected untrusted write"
        db.close()

        # --- 3. Fail closed on empty trust ---
        print("\n--- 3. Fail closed on empty trust ---")
        if os.path.exists(db2_path):
            os.remove(db2_path)
        track(db2_path)

        missing_ca = os.path.join(empty_trust_dir, 'does_not_exist.crt')
        db2 = MSFStorage(
            db2_path,
            ca_cert_path=missing_ca,
            trust_dir=empty_trust_dir,
        )
        before_count = db2.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        # Host-admin cert is fine cryptographically but no anchors are loaded.
        sig = make_signed_payload(
            db2,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['k', 'v'],
            host_admin_key,
        )
        try:
            db2.execute_signed(
                "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
                ['k', 'v'],
                sig,
                host_admin_cert,
            )
            raise AssertionError("Signed execute allowed with empty trust!")
        except PermissionError as e:
            msg = str(e)
            assert (
                "no trusted Root CA" in msg
                or "Chain Verification Failed" in msg
                or "trusted Root CA" in msg
            ), f"Expected fail-closed trust error, got: {e}"
            print(f"✓ Empty trust rejected: {e}")
        after_count = db2.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        assert after_count == before_count == 0, "Ledger row appended despite empty trust"
        db2.close()

        # --- 4. Identity.load with trust store ---
        print("\n--- 4. Identity.load with trust store ---")
        missing = os.path.join(empty_trust_dir, 'no_ca.crt')
        ident_ok = Identity.load(
            org_user_cert_path, missing, trust_dir=trust_dir
        )
        assert ident_ok.is_valid, "Org user should be valid via trust_dir"
        assert ident_ok.cn == 'org_user', f"Expected cn=org_user, got {ident_ok.cn}"
        print(f"✓ Identity.load with trust store: valid ({ident_ok.cn})")

        ident_bad = Identity.load(
            org_user_cert_path, missing, trust_dir=empty_trust_dir
        )
        assert not ident_bad.is_valid, "Org user must be invalid with empty trust + missing CA"
        print("✓ Identity.load with empty trust: invalid")

        # --- 5. Garbage already present; re-check org path still works ---
        print("\n--- 5. Garbage in trust dir is skipped ---")
        assert os.path.isfile(junk_path)
        # Re-open and re-verify org user still works (junk.crt was already there for test 1)
        db3 = MSFStorage(db_path, trust_dir=trust_dir)
        assert db3._signer_is_ca_trusted(org_user_cert), "Org user should still be trusted"
        assert not db3._signer_is_ca_trusted(untrusted_cert), "Untrusted still not trusted"
        db3.close()
        print("✓ junk.crt skipped; trust store still functions")

        print("\n==========================================")
        print("🔥 ALL TRUST STORE TESTS PASSED! 🔥")
        print("==========================================")

    finally:
        for path in artifacts:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass
        for d in (trust_dir, empty_trust_dir):
            if d and os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    run_trust_store_test()
