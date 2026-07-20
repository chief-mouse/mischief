"""Integration tests for the Identity Directory micro-app container.

Run: python test_directory.py

Authors a signed phonebook .msf, registers host-CA and org-CA identities,
exercises RBAC / revocation / immutability / trust refusal, and ends with a
clean replay_audit. Does not modify existing project files beyond temporary
artifacts created and cleaned up here.
"""
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.abspath("src"))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from mschf.audit import replay_audit, format_report
from mschf.directory import (
    create_directory_container,
    register_identity,
    set_identity_status,
    lookup,
    cert_fingerprint,
)
from mschf.gen_cert import (
    generate_selfsigned_cert,
    generate_user_cert,
    default_backend,
    serialization,
)
from mschf.identity import Identity
from mschf.storage import MSFStorage, canonical_payload


def make_signed_payload(db, query, params, pem_key_bytes):
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(query, params, next_seq, prev_hash, db.container_uid)
    private_key = serialization.load_pem_private_key(
        pem_key_bytes, password=None, backend=default_backend()
    )
    return private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())


def load_key(pem_key_bytes):
    return load_pem_private_key(pem_key_bytes, password=None)


def run():
    artifacts = []
    trust_dir = None
    dest = "test_directory.msf"

    def track(path):
        artifacts.append(path)
        return path

    try:
        # ------------------------------------------------------------------
        # Fixtures: reuse host CA if present (NEVER overwrite)
        # ------------------------------------------------------------------
        print("--- Host Root CA ---")
        ca_cert_path, ca_key_path = "ca.crt", "ca.key"
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            pem_ca_cert, pem_ca_key = generate_selfsigned_cert("Temporary Root CA")
            with open(ca_cert_path, "wb") as f:
                f.write(pem_ca_cert)
            with open(ca_key_path, "wb") as f:
                f.write(pem_ca_key)
            print("Generated temporary host ca.crt / ca.key")
        else:
            print("Reusing existing host ca.crt / ca.key")

        with open(ca_cert_path, "rb") as f:
            host_ca_cert = f.read()
        with open(ca_key_path, "rb") as f:
            host_ca_key = f.read()

        # Bootstrap / admin identity for authoring
        dir_admin_cert, dir_admin_key = generate_user_cert(
            "dir_admin", host_ca_cert, host_ca_key
        )
        with open(track("dir_admin.crt"), "wb") as f:
            f.write(dir_admin_cert)
        with open(track("dir_admin.key"), "wb") as f:
            f.write(dir_admin_key)

        # Member identity (host CA)
        dir_member_cert, dir_member_key = generate_user_cert(
            "dir_member", host_ca_cert, host_ca_key
        )
        with open(track("dir_member.crt"), "wb") as f:
            f.write(dir_member_cert)
        with open(track("dir_member.key"), "wb") as f:
            f.write(dir_member_key)

        # Directory-admin role holder (separate from bootstrap admin)
        role_admin_cert, role_admin_key = generate_user_cert(
            "role_directory_admin", host_ca_cert, host_ca_key
        )
        with open(track("role_directory_admin.crt"), "wb") as f:
            f.write(role_admin_cert)
        with open(track("role_directory_admin.key"), "wb") as f:
            f.write(role_admin_key)

        # Org CA in temp trust dir + partner_user issued from it
        print("\n--- Partner Org CA trust store ---")
        trust_dir = tempfile.mkdtemp(prefix="mschf_dir_trust_")
        partner_ca_cert, partner_ca_key = generate_selfsigned_cert("Partner Org CA")
        partner_ca_path = os.path.join(trust_dir, "partner_org_ca.crt")
        with open(partner_ca_path, "wb") as f:
            f.write(partner_ca_cert)

        partner_user_cert, partner_user_key = generate_user_cert(
            "partner_user", partner_ca_cert, partner_ca_key
        )
        with open(track("partner_user.crt"), "wb") as f:
            f.write(partner_user_cert)
        with open(track("partner_user.key"), "wb") as f:
            f.write(partner_user_key)
        print(f"Trust dir: {trust_dir}")

        # Untrusted CA (not in trust store)
        other_ca_cert, other_ca_key = generate_selfsigned_cert("Unknown Other CA")
        untrusted_cert, untrusted_key = generate_user_cert(
            "untrusted_user", other_ca_cert, other_ca_key
        )

        # Extra host-CA identity to register as phonebook entry
        host_user_cert, host_user_key = generate_user_cert(
            "host_listed_user", host_ca_cert, host_ca_key
        )

        # ------------------------------------------------------------------
        # 1. Authoring
        # ------------------------------------------------------------------
        print("\n--- 1. Authoring Identity Directory container ---")
        if os.path.exists(dest):
            os.remove(dest)
        track(dest)

        identity = Identity.load("dir_admin.crt", ca_cert_path)
        assert identity.is_valid, "dir_admin must chain to host CA"
        create_directory_container(
            dest, identity, ca_cert_path=ca_cert_path, trust_dir=trust_dir
        )

        db = MSFStorage(dest, ca_cert_path=ca_cert_path, trust_dir=trust_dir)

        assert db.get_manifest_item("entry_point") == "main_app"
        assert db.get_manifest_item("name") == "Identity Directory"
        assert db.get_manifest_item("description"), "description must be set"
        print("  [OK] manifest wired")

        status = db.get_code_signature_status("main_app")
        assert status["verified"], f"code signature not verified: {status['error']}"
        assert status["signer"] == "dir_admin"
        print(f"  [OK] code blob signed and verified (signer={status['signer']})")

        code_func = db.get_code("main_app")
        assert callable(code_func), "directory code must unpickle to a callable"
        print("  [OK] code blob unpickles to a callable (by-value)")

        admin_row = db.conn.execute(
            "SELECT role FROM user_roles WHERE identity = 'cert:CN=dir_admin'"
        ).fetchone()
        assert admin_row and admin_row[0] == "admin", "creator must be container admin"
        print("  [OK] creating identity bootstrapped as container admin")

        report = replay_audit(db)
        print(format_report(report))
        assert report["ok"], f"authored container must pass replay_audit: {report}"
        print("  [OK] replay_audit clean after authoring")

        # ------------------------------------------------------------------
        # 2. register_identity (host-CA + partner_user via trust_dir)
        # ------------------------------------------------------------------
        print("\n--- 2. register_identity ---")
        admin_pk = load_key(dir_admin_key)

        fp_host = register_identity(
            db,
            dir_admin_cert,
            admin_pk,
            host_user_cert,
            display_name="Host Listed User",
            org="Host Org",
        )
        expected_host_fp = cert_fingerprint(host_user_cert)
        assert fp_host == expected_host_fp, (fp_host, expected_host_fp)

        fp_partner = register_identity(
            db,
            dir_admin_cert,
            admin_pk,
            partner_user_cert,
            display_name="Partner User",
            org="Partner Org",
        )
        expected_partner_fp = cert_fingerprint(partner_user_cert)
        assert fp_partner == expected_partner_fp

        rows = lookup(db, status="active")
        cns = {r["cn"] for r in rows}
        assert "host_listed_user" in cns and "partner_user" in cns, cns
        for r in rows:
            assert r["added_by"] == "cert:CN=dir_admin", (
                f"added_by must be trigger-stamped to signing admin, got {r['added_by']!r}"
            )
            assert r["fingerprint"] in (fp_host, fp_partner)
        print(f"  [OK] registered {len(rows)} identities; added_by stamped; fingerprints match")

        # ------------------------------------------------------------------
        # 3. Trust refusal, non-cert, duplicate fingerprint
        # ------------------------------------------------------------------
        print("\n--- 3. Refuse untrusted / non-cert / duplicate ---")
        ledger_before = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        row_count_before = db.conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0]

        try:
            register_identity(db, dir_admin_cert, admin_pk, untrusted_cert)
            raise AssertionError("untrusted CA cert should be refused")
        except PermissionError as e:
            assert "trust" in str(e).lower() or "not trusted" in str(e).lower(), e
            print(f"  [OK] unknown CA refused: {e}")

        try:
            register_identity(db, dir_admin_cert, admin_pk, b"this is not a certificate")
            raise AssertionError("non-cert blob should be refused")
        except ValueError as e:
            assert "certificate" in str(e).lower() or "pem" in str(e).lower(), e
            print(f"  [OK] non-cert refused: {e}")

        try:
            register_identity(db, dir_admin_cert, admin_pk, host_user_cert)
            raise AssertionError("duplicate fingerprint should raise clean error")
        except ValueError as e:
            assert "fingerprint" in str(e).lower() or "already" in str(e).lower(), e
            print(f"  [OK] duplicate fingerprint clean error: {e}")

        ledger_after = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        row_count_after = db.conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0]
        assert ledger_after == ledger_before, "ledger must be unchanged by failed attempts"
        assert row_count_after == row_count_before, "no partial identity rows on failure"
        print("  [OK] ledger and identities table unchanged by failed attempts")

        # ------------------------------------------------------------------
        # 4. RBAC: member read-only; directory_admin write
        # ------------------------------------------------------------------
        print("\n--- 4. RBAC ---")
        member_id = db._get_identity(dir_member_cert)
        role_admin_id = db._get_identity(role_admin_cert)

        q = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
        sig = make_signed_payload(db, q, [member_id, "member"], dir_admin_key)
        db.assign_user_role(member_id, "member", sig, dir_admin_cert)

        sig = make_signed_payload(
            db, q, [role_admin_id, "directory_admin"], dir_admin_key
        )
        db.assign_user_role(role_admin_id, "directory_admin", sig, dir_admin_cert)
        print("  [OK] assigned member + directory_admin roles")

        # Member can signed-SELECT
        sel = "SELECT cn FROM identities"
        sig = make_signed_payload(db, sel, [], dir_member_key)
        cur = db.execute_signed(sel, [], sig, dir_member_cert)
        member_rows = cur.fetchall()
        assert len(member_rows) >= 2, member_rows
        print(f"  [OK] dir_member signed-SELECT ok ({len(member_rows)} rows)")

        # Member signed INSERT denied
        ledger_before = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        ins = (
            "INSERT INTO identities (cn, fingerprint, cert_pem) "
            "VALUES (?, ?, ?)"
        )
        bad_params = ["sneaky", "f" * 64, "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"]
        sig = make_signed_payload(db, ins, bad_params, dir_member_key)
        try:
            db.execute_signed(ins, bad_params, sig, dir_member_cert)
            raise AssertionError("member INSERT must be denied")
        except PermissionError as e:
            print(f"  [OK] member INSERT denied: {e}")
        ledger_after = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        assert ledger_after == ledger_before, "denied INSERT must not append ledger"

        # directory_admin role can write (register another host-CA identity)
        extra_cert, extra_key = generate_user_cert(
            "extra_listed", host_ca_cert, host_ca_key
        )
        role_pk = load_key(role_admin_key)
        fp_extra = register_identity(
            db, role_admin_cert, role_pk, extra_cert, org="Host Org"
        )
        found = lookup(db, cn="extra_listed")
        assert len(found) == 1 and found[0]["fingerprint"] == fp_extra
        assert found[0]["added_by"] == "cert:CN=role_directory_admin"
        print("  [OK] directory_admin role can write (register_identity)")

        # ------------------------------------------------------------------
        # 5. Revocation
        # ------------------------------------------------------------------
        print("\n--- 5. Revocation ---")
        set_identity_status(db, dir_admin_cert, admin_pk, fp_host, "revoked")
        rev = lookup(db, cn="host_listed_user", status="revoked")
        assert len(rev) == 1, rev
        assert rev[0]["status"] == "revoked"
        assert rev[0]["updated_by"] == "cert:CN=dir_admin", rev[0]["updated_by"]
        # Default lookup is active-only
        assert lookup(db, cn="host_listed_user") == []
        print("  [OK] status flipped to revoked; updated_by stamped")

        try:
            set_identity_status(db, dir_admin_cert, admin_pk, fp_host, "suspended")
            raise AssertionError("invalid status must be rejected")
        except ValueError as e:
            assert "status" in str(e).lower() or "active" in str(e).lower(), e
            print(f"  [OK] invalid status rejected: {e}")

        # ------------------------------------------------------------------
        # 6. Immutability + trigger shield
        # ------------------------------------------------------------------
        print("\n--- 6. Immutability + trigger shield ---")
        upd = "UPDATE identities SET added_by = ? WHERE fingerprint = ?"
        evil_params = ["cert:CN=forger", fp_partner]
        sig = make_signed_payload(db, upd, evil_params, dir_admin_key)
        try:
            db.execute_signed(upd, evil_params, sig, dir_admin_cert)
            raise AssertionError("mutating added_by must be denied by immutability guard")
        except Exception as e:
            assert "immutable" in str(e).lower() or "added_by" in str(e).lower(), e
            print(f"  [OK] immutability guard: {e}")

        still = lookup(db, cn="partner_user", status=None)
        assert still[0]["added_by"] == "cert:CN=dir_admin"

        raw = sqlite3.connect(dest)
        try:
            raw.execute(
                "INSERT INTO identities (cn, fingerprint, cert_pem) "
                "VALUES ('raw', 'aa', 'pem')"
            )
            raise AssertionError("raw insert should fail on current_signer")
        except sqlite3.OperationalError as e:
            assert "current_signer" in str(e), e
            print(f"  [OK] raw write rejected: {e}")
        finally:
            raw.close()

        # ------------------------------------------------------------------
        # 7. Final replay_audit + cleanup
        # ------------------------------------------------------------------
        print("\n--- 7. Final replay_audit ---")
        report = replay_audit(db)
        print(format_report(report))
        assert report["ok"], f"final replay_audit must pass: {report}"
        print("  [OK] final replay_audit clean")

        db.close()
        print("\n==========================================")
        print("ALL DIRECTORY TESTS PASSED")
        print("==========================================")
    finally:
        # Cleanup everything we created (never touch ca.crt/ca.key if pre-existing
        # reuse; only remove tracked artifacts and temp trust dir).
        for path in artifacts:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass
        if trust_dir and os.path.isdir(trust_dir):
            shutil.rmtree(trust_dir, ignore_errors=True)


if __name__ == "__main__":
    run()
