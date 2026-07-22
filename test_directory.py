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
from datetime import datetime, timedelta, timezone

from mschf.directory import (
    create_directory_container,
    register_identity,
    set_identity_status,
    lookup,
    cert_fingerprint,
    attest_agent,
    revoke_attestation,
    lookup_attestations,
    verify_attestation,
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
        # 7. Owner→agent attestations
        # ------------------------------------------------------------------
        print("\n--- 7. Owner→agent attestations ---")

        # Human owner + agent certs (host CA)
        owner_cert, owner_key_pem = generate_user_cert(
            "human_owner", host_ca_cert, host_ca_key
        )
        agent_cert, agent_key_pem = generate_user_cert(
            "claude", host_ca_cert, host_ca_key
        )
        other_member_cert, other_member_key_pem = generate_user_cert(
            "other_member", host_ca_cert, host_ca_key
        )
        owner_pk = load_key(owner_key_pem)
        other_member_pk = load_key(other_member_key_pem)

        fp_owner = register_identity(
            db, dir_admin_cert, admin_pk, owner_cert, org="Host Org"
        )
        fp_agent = register_identity(
            db, dir_admin_cert, admin_pk, agent_cert, org="Host Org"
        )
        fp_other = register_identity(
            db, dir_admin_cert, admin_pk, other_member_cert, org="Host Org"
        )
        assert fp_owner == cert_fingerprint(owner_cert)
        assert fp_agent == cert_fingerprint(agent_cert)

        # Grant member role so owners can INSERT attestations
        for cert_pem, key_pem in (
            (owner_cert, owner_key_pem),
            (other_member_cert, other_member_key_pem),
            (partner_user_cert, partner_user_key),
        ):
            mid = db._get_identity(cert_pem)
            q = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
            sig = make_signed_payload(db, q, [mid, "member"], dir_admin_key)
            db.assign_user_role(mid, "member", sig, dir_admin_cert)

        # 7a. Happy path
        print("  --- 7a. Happy path ---")
        att_id = attest_agent(
            db,
            owner_cert,
            owner_pk,
            owner_pk,
            owner_cert,
            "claude",
            conditions="scope:dev-tracker",
            expires_at=None,
        )
        assert att_id is not None
        found = lookup_attestations(db, agent_cn="claude")
        assert len(found) == 1, found
        assert found[0]["owner_cn"] == "human_owner"
        assert found[0]["agent_fingerprint"] == fp_agent
        assert found[0]["owner_fingerprint"] == fp_owner
        assert found[0]["conditions"] == "scope:dev-tracker"
        assert found[0]["status"] == "active"
        assert found[0]["added_by"] == "cert:CN=human_owner"
        verdict = verify_attestation(db, found[0])
        assert verdict["valid"] is True, verdict
        print(f"  [OK] attest + lookup + verify valid (id={att_id})")

        # 7b. Refusals: self-attest, unregistered agent, revoked owner
        print("  --- 7b. Refusals ---")
        try:
            attest_agent(
                db, owner_cert, owner_pk, owner_pk, owner_cert, "human_owner"
            )
            raise AssertionError("self-attestation must be refused")
        except ValueError as e:
            assert "self" in str(e).lower(), e
            print(f"  [OK] self-attestation refused: {e}")

        try:
            attest_agent(
                db, owner_cert, owner_pk, owner_pk, owner_cert, "no_such_agent"
            )
            raise AssertionError("unregistered agent must be refused")
        except ValueError as e:
            assert "not registered" in str(e).lower() or "no_such" in str(e).lower(), e
            print(f"  [OK] unregistered agent refused: {e}")

        set_identity_status(db, dir_admin_cert, admin_pk, fp_owner, "revoked")
        try:
            attest_agent(
                db, dir_admin_cert, admin_pk, owner_pk, owner_cert, "claude"
            )
            raise AssertionError("revoked owner must be refused")
        except ValueError as e:
            assert "active" in str(e).lower() or "revoked" in str(e).lower(), e
            print(f"  [OK] revoked-registration owner refused: {e}")
        # Restore owner for later tests
        set_identity_status(db, dir_admin_cert, admin_pk, fp_owner, "active")

        # 7c. Tampered row (side container so main db stays audit-clean)
        print("  --- 7c. Tamper → verify invalid + replay_audit flags ---")
        tamper_dest = track("test_directory_tamper.msf")
        if os.path.exists(tamper_dest):
            os.remove(tamper_dest)
        create_directory_container(
            tamper_dest, identity, ca_cert_path=ca_cert_path, trust_dir=trust_dir
        )
        tdb = MSFStorage(tamper_dest, ca_cert_path=ca_cert_path, trust_dir=trust_dir)
        t_admin_pk = load_key(dir_admin_key)
        register_identity(tdb, dir_admin_cert, t_admin_pk, owner_cert)
        register_identity(tdb, dir_admin_cert, t_admin_pk, agent_cert)
        mid = tdb._get_identity(owner_cert)
        q = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
        sig = make_signed_payload(tdb, q, [mid, "member"], dir_admin_key)
        tdb.assign_user_role(mid, "member", sig, dir_admin_cert)
        attest_agent(
            tdb, owner_cert, owner_pk, owner_pk, owner_cert, "claude",
            conditions="original-conditions",
        )
        trow = lookup_attestations(tdb, agent_cn="claude")[0]
        assert verify_attestation(tdb, trow)["valid"] is True
        # Out-of-band edit via the storage connection (bypasses execute_signed /
        # ledger). Core-column freeze aborts a plain UPDATE of conditions, so
        # drop that guard first to simulate a raw page-level / pre-freeze
        # mutation; still a ledger-skipping change that verify + audit catch.
        tdb.conn.execute(
            "DROP TRIGGER IF EXISTS trg_agent_attestations_core_immutable"
        )
        tdb.conn.execute(
            "UPDATE agent_attestations SET conditions = ? WHERE id = ?",
            ("TAMPERED", trow["id"]),
        )
        tdb.conn.commit()
        trow2 = lookup_attestations(tdb, agent_cn="claude")[0]
        assert trow2["conditions"] == "TAMPERED"
        v_bad = verify_attestation(tdb, trow2)
        assert v_bad["valid"] is False, v_bad
        assert "signature" in v_bad["reason"].lower() or "mismatch" in v_bad["reason"].lower(), v_bad
        print(f"  [OK] tampered conditions → verify invalid: {v_bad['reason']}")
        treport = replay_audit(tdb)
        assert not treport["ok"], "tampered container must fail replay_audit"
        print("  [OK] replay_audit flags out-of-band tamper")
        tdb.close()

        # 7d. Expiry
        print("  --- 7d. Expiry ---")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        # Use partner_user as a second owner attesting the same agent (fresh pair)
        partner_pk = load_key(partner_user_key)
        # partner already registered and active from section 2
        exp_id = attest_agent(
            db,
            partner_user_cert,
            partner_pk,
            partner_pk,
            partner_user_cert,
            "claude",
            conditions="time-bound",
            expires_at=past,
        )
        exp_rows = [
            r for r in lookup_attestations(db, agent_cn="claude")
            if r["id"] == exp_id
        ]
        assert len(exp_rows) == 1
        v_exp = verify_attestation(db, exp_rows[0])
        assert v_exp["valid"] is False, v_exp
        assert "expir" in v_exp["reason"].lower(), v_exp
        print(f"  [OK] past expires_at → invalid: {v_exp['reason']}")

        before_expiry = datetime.now(timezone.utc) - timedelta(hours=2)
        v_early = verify_attestation(db, exp_rows[0], at_time=before_expiry)
        assert v_early["valid"] is True, v_early
        print("  [OK] at_time before expiry → valid")

        # Non-expired attestation for later clean audit
        attest_agent(
            db,
            owner_cert,
            owner_pk,
            owner_pk,
            owner_cert,
            "claude",
            conditions="still-good",
            expires_at=future,
        )

        # 7e. Revocation
        print("  --- 7e. Revocation ---")
        # directory_admin revokes the original happy-path attestation
        role_pk = load_key(role_admin_key)
        revoke_attestation(db, role_admin_cert, role_pk, att_id)
        rev_row = [
            r for r in lookup_attestations(db, agent_cn="claude", include_revoked=True)
            if r["id"] == att_id
        ][0]
        assert rev_row["status"] == "revoked"
        v_rev = verify_attestation(db, rev_row)
        assert v_rev["valid"] is False, v_rev
        assert "revok" in v_rev["reason"].lower() or "status" in v_rev["reason"].lower(), v_rev
        print(f"  [OK] directory_admin revoke → verify invalid: {v_rev['reason']}")

        # Owner creates a fresh attestation and revokes it themselves
        own_id = attest_agent(
            db, owner_cert, owner_pk, owner_pk, owner_cert, "claude",
            conditions="owner-will-revoke",
        )
        revoke_attestation(db, owner_cert, owner_pk, own_id)
        own_row = [
            r for r in lookup_attestations(db, include_revoked=True) if r["id"] == own_id
        ][0]
        assert own_row["status"] == "revoked"
        print("  [OK] owner revokes own attestation")

        # Unrelated member cannot revoke someone else's attestation
        # Re-attest so there is an active row owned by human_owner
        live_id = attest_agent(
            db, owner_cert, owner_pk, owner_pk, owner_cert, "claude",
            conditions="live-for-refuse",
        )
        try:
            revoke_attestation(db, other_member_cert, other_member_pk, live_id)
            raise AssertionError("unrelated member must not revoke")
        except PermissionError as e:
            print(f"  [OK] unrelated member revoke refused: {e}")
        still_live = [
            r for r in lookup_attestations(db, agent_cn="claude") if r["id"] == live_id
        ]
        assert len(still_live) == 1 and still_live[0]["status"] == "active"

        # 7f. Verification consults trust store, not directory membership
        print("  --- 7f. Trust store fail-closed ---")
        # partner_user already attested with past expiry; make a non-expired one
        partner_att = attest_agent(
            db,
            partner_user_cert,
            partner_pk,
            partner_pk,
            partner_user_cert,
            "claude",
            conditions="partner-owned",
            expires_at=future,
        )
        p_row = [
            r for r in lookup_attestations(db, agent_cn="claude") if r["id"] == partner_att
        ][0]
        assert verify_attestation(db, p_row)["valid"] is True

        # Remove partner CA from trust dir → verify must fail closed
        os.remove(partner_ca_path)
        v_untrusted = verify_attestation(
            db, p_row, ca_cert_path=ca_cert_path, trust_dir=trust_dir
        )
        assert v_untrusted["valid"] is False, v_untrusted
        assert (
            "trust" in v_untrusted["reason"].lower()
            or "chain" in v_untrusted["reason"].lower()
        ), v_untrusted
        print(f"  [OK] owner CA removed from trust dir → invalid: {v_untrusted['reason']}")
        # Restore partner CA for any remaining checks / audit of partner-signed ledger rows
        with open(partner_ca_path, "wb") as f:
            f.write(partner_ca_cert)
        assert verify_attestation(db, p_row)["valid"] is True
        print("  [OK] restoring partner CA restores verify")

        # Predates-attestations behavior (empty lookup / clear error)
        print("  --- 7g. Predates-attestations guard ---")
        bare = track("test_directory_bare.msf")
        if os.path.exists(bare):
            os.remove(bare)
        # Minimal: create container then drop the table out-of-band to simulate legacy
        create_directory_container(
            bare, identity, ca_cert_path=ca_cert_path, trust_dir=trust_dir
        )
        bdb = MSFStorage(bare, ca_cert_path=ca_cert_path, trust_dir=trust_dir)
        # Simulate pre-feature directory by renaming table away
        bdb.conn.execute("ALTER TABLE agent_attestations RENAME TO _agent_attestations_gone")
        bdb.conn.commit()
        assert lookup_attestations(bdb) == []
        try:
            attest_agent(
                bdb, dir_admin_cert, admin_pk, owner_pk, owner_cert, "claude"
            )
            raise AssertionError("must raise directory predates attestations")
        except RuntimeError as e:
            assert "predate" in str(e).lower() or "attestations" in str(e).lower(), e
            print(f"  [OK] predates guard: {e}")
        bdb.close()

        # Engine-level status / core-column guards (bypass API, use execute_signed)
        print("  --- 7h. Engine status + core-column guards ---")
        gate_id = attest_agent(
            db, owner_cert, owner_pk, owner_pk, owner_cert, "claude",
            conditions="engine-gate-target",
        )
        # Ensure an active row we can also revoke then try to re-activate
        gate_revoked_id = attest_agent(
            db, owner_cert, owner_pk, owner_pk, owner_cert, "claude",
            conditions="engine-gate-reactivate",
        )
        revoke_attestation(db, owner_cert, owner_pk, gate_revoked_id)

        def signed_status_update(cert_pem, key_pem, att_id, new_status):
            q = "UPDATE agent_attestations SET status = ? WHERE id = ?"
            params = [new_status, att_id]
            sig = make_signed_payload(db, q, params, key_pem)
            return db.execute_signed(q, params, sig, cert_pem)

        # 1. Non-owner member: active→revoked and revoked→active both refused
        for att_id, new_st, label in (
            (gate_id, "revoked", "active→revoked"),
            (gate_revoked_id, "active", "revoked→active"),
        ):
            try:
                signed_status_update(
                    other_member_cert, other_member_key_pem, att_id, new_st
                )
                raise AssertionError(
                    f"non-owner member status flip ({label}) must be refused"
                )
            except Exception as e:
                msg = str(e).lower()
                assert (
                    "status" in msg
                    or "owner" in msg
                    or "admin" in msg
                    or "unauthorized" in msg
                    or "denied" in msg
                ), e
                print(f"  [OK] non-owner member {label} refused: {e}")

        still_active = db.conn.execute(
            "SELECT status FROM agent_attestations WHERE id = ?", (gate_id,)
        ).fetchone()[0]
        assert still_active == "active", still_active
        still_revoked = db.conn.execute(
            "SELECT status FROM agent_attestations WHERE id = ?", (gate_revoked_id,)
        ).fetchone()[0]
        assert still_revoked == "revoked", still_revoked

        # 2. Owner-signed direct status UPDATE allowed (parity with API path)
        signed_status_update(owner_cert, owner_key_pem, gate_id, "revoked")
        assert (
            db.conn.execute(
                "SELECT status FROM agent_attestations WHERE id = ?", (gate_id,)
            ).fetchone()[0]
            == "revoked"
        )
        print("  [OK] owner-signed direct status UPDATE allowed")
        # restore a live row for any later checks
        signed_status_update(owner_cert, owner_key_pem, gate_id, "active")

        # 3. Raw unsigned UPDATE of status (NULL current_signer) aborted
        try:
            db.conn.execute(
                "UPDATE agent_attestations SET status = ? WHERE id = ?",
                ("revoked", gate_id),
            )
            db.conn.commit()
            raise AssertionError("raw unsigned status UPDATE must abort")
        except Exception as e:
            db.conn.rollback()
            msg = str(e).lower()
            assert (
                "status" in msg
                or "owner" in msg
                or "admin" in msg
                or "current_signer" in msg
            ), e
            print(f"  [OK] raw unsigned status UPDATE aborted: {e}")
        assert (
            db.conn.execute(
                "SELECT status FROM agent_attestations WHERE id = ?", (gate_id,)
            ).fetchone()[0]
            == "active"
        )

        # 4. Signed UPDATE of frozen core column refused even for directory_admin
        q_core = "UPDATE agent_attestations SET conditions = ? WHERE id = ?"
        core_params = ["FORGED-CONDITIONS", gate_id]
        sig_core = make_signed_payload(db, q_core, core_params, role_admin_key)
        try:
            db.execute_signed(q_core, core_params, sig_core, role_admin_cert)
            raise AssertionError("core-column UPDATE must be refused for directory_admin")
        except Exception as e:
            msg = str(e).lower()
            assert "immutable" in msg or "core" in msg or "conditions" in msg, e
            print(f"  [OK] directory_admin core-column UPDATE refused: {e}")
        cond_now = db.conn.execute(
            "SELECT conditions FROM agent_attestations WHERE id = ?", (gate_id,)
        ).fetchone()[0]
        assert cond_now == "engine-gate-target", cond_now

        # 7i. attestation_authz mirror stays correct across user_roles UPDATEs
        # (single sequenced trigger — sibling DELETE/INSERT order is undefined).
        print("  --- 7i. attestation_authz UPDATE-mirror ordering ---")
        promote_id = db._get_identity(other_member_cert)
        # Start as member (from 7 setup); mirror must not list them yet.
        in_mirror = db.conn.execute(
            "SELECT 1 FROM attestation_authz WHERE identity = ?", (promote_id,)
        ).fetchone()
        assert in_mirror is None, "member must not be in attestation_authz before promote"

        def signed_role_update(identity, new_role):
            q = "UPDATE user_roles SET role = ? WHERE identity = ?"
            params = [new_role, identity]
            sig = make_signed_payload(db, q, params, dir_admin_key)
            return db.execute_signed(q, params, sig, dir_admin_cert)

        # 1. Promote member → directory_admin via UPDATE → mirror + engine gate
        signed_role_update(promote_id, "directory_admin")
        in_mirror = db.conn.execute(
            "SELECT 1 FROM attestation_authz WHERE identity = ?", (promote_id,)
        ).fetchone()
        assert in_mirror is not None, (
            "promoted directory_admin must appear in attestation_authz after UPDATE"
        )
        print("  [OK] promote via UPDATE → mirror contains identity")

        signed_status_update(
            other_member_cert, other_member_key_pem, gate_id, "revoked"
        )
        assert (
            db.conn.execute(
                "SELECT status FROM agent_attestations WHERE id = ?", (gate_id,)
            ).fetchone()[0]
            == "revoked"
        )
        print("  [OK] promoted directory_admin status-flip on others' row succeeds")
        # restore for subsequent checks
        signed_status_update(
            other_member_cert, other_member_key_pem, gate_id, "active"
        )

        # 2. No-op re-grant (directory_admin → directory_admin) keeps mirror
        signed_role_update(promote_id, "directory_admin")
        in_mirror = db.conn.execute(
            "SELECT 1 FROM attestation_authz WHERE identity = ?", (promote_id,)
        ).fetchone()
        assert in_mirror is not None, (
            "no-op role UPDATE must not strip identity from attestation_authz"
        )
        # Same for bootstrap admin → admin
        admin_id = db._get_identity(dir_admin_cert)
        signed_role_update(admin_id, "admin")
        assert (
            db.conn.execute(
                "SELECT 1 FROM attestation_authz WHERE identity = ?", (admin_id,)
            ).fetchone()
            is not None
        ), "no-op admin→admin UPDATE must leave admin in mirror"
        print("  [OK] no-op re-grant UPDATE leaves privileged identities in mirror")

        # 3. Demote directory_admin → member → mirror gone → status-flip refused
        signed_role_update(promote_id, "member")
        in_mirror = db.conn.execute(
            "SELECT 1 FROM attestation_authz WHERE identity = ?", (promote_id,)
        ).fetchone()
        assert in_mirror is None, "demoted member must leave attestation_authz"
        try:
            signed_status_update(
                other_member_cert, other_member_key_pem, gate_id, "revoked"
            )
            raise AssertionError(
                "demoted member status flip on others' row must be refused"
            )
        except Exception as e:
            msg = str(e).lower()
            assert (
                "status" in msg
                or "owner" in msg
                or "admin" in msg
                or "unauthorized" in msg
                or "denied" in msg
            ), e
            print(f"  [OK] demote via UPDATE → mirror empty; status-flip refused: {e}")
        assert (
            db.conn.execute(
                "SELECT status FROM agent_attestations WHERE id = ?", (gate_id,)
            ).fetchone()[0]
            == "active"
        )

        # ------------------------------------------------------------------
        # 8. Final replay_audit (main directory, all clean ops)
        # ------------------------------------------------------------------
        print("\n--- 8. Final replay_audit ---")
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
