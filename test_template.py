"""Instantiate-from-template tests (headless, CI-safe — no toga at runtime).

Run: python test_template.py

Covers create_from_template: fresh uid, creator-as-admin, structure lift,
ui_spec/schema_spec re-signed by creator, no data/history copy, homed→unhomed,
tamper/pickled refusals, dest-exists, and schemaspec enforcement after instantiate.
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath("src"))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from mschf.audit import format_report, replay_audit
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert
from mschf.identity import Identity
from mschf.schemaspec import apply_schema_spec
from mschf.starter import create_starter_container
from mschf.storage import MSFStorage, canonical_payload
from mschf.template import TemplateError, check_template, create_from_template

# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

ARTIFACTS = [
    "tmpl_author.crt",
    "tmpl_author.key",
    "tmpl_creator.crt",
    "tmpl_creator.key",
    "template_starter.msf",
    "template_schema.msf",
    "template_homed.msf",
    "template_pickled.msf",
    "template_tampered.msf",
    "template_no_spec.msf",
    "template_orphan.msf",
    "template_garbage.bin",
    "inst_from_starter.msf",
    "inst_from_schema.msf",
    "inst_from_homed.msf",
    "inst_dup.msf",
    "inst_should_not_exist.msf",
    "tmpl_orphan_trust",  # directory (cleaned below if present)
]

SCHEMA_SPEC = {
    "v": 1,
    "objects": [
        {
            "name": "items",
            "fields": [
                {"name": "title", "type": "text", "rules": ["required"]},
            ],
            "access": {"member": ["read", "write"]},
        },
    ],
}


def cleanup():
    for path in ARTIFACTS:
        if not os.path.exists(path):
            continue
        if os.path.isdir(path):
            for name in os.listdir(path):
                try:
                    os.remove(os.path.join(path, name))
                except OSError:
                    pass
            try:
                os.rmdir(path)
            except OSError:
                pass
        else:
            os.remove(path)


def ensure_ca():
    ca_cert_path, ca_key_path = "ca.crt", "ca.key"
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        ca_pem, ca_key_pem = generate_selfsigned_cert("Temporary Root CA")
        with open(ca_cert_path, "wb") as f:
            f.write(ca_pem)
        with open(ca_key_path, "wb") as f:
            f.write(ca_key_pem)
    with open(ca_cert_path, "rb") as f:
        ca_cert = f.read()
    with open(ca_key_path, "rb") as f:
        ca_key = f.read()
    return ca_cert_path, ca_cert, ca_key


def write_identity(cn, ca_cert, ca_key):
    cert, key = generate_user_cert(cn, ca_cert, ca_key)
    with open(f"{cn}.crt", "wb") as f:
        f.write(cert)
    with open(f"{cn}.key", "wb") as f:
        f.write(key)
    return Identity.load(f"{cn}.crt", "ca.crt")


def load_key(path):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def sign_with(db, private_key, query, params):
    next_seq, prev_hash = db.get_chain_head()
    payload = canonical_payload(
        query, params, next_seq, prev_hash, db.container_uid
    )
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def signed_exec(db, private_key, cert_pem, query, params=None):
    params = params if params is not None else []
    sig = sign_with(db, private_key, query, params)
    return db.execute_signed(query, params, sig, cert_pem)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_instantiate_starter(author, creator, ca_cert_path):
    print("--- 1. Starter template → fresh app ---")
    tmpl = "template_starter.msf"
    dest = "inst_from_starter.msf"
    create_starter_container(tmpl, author, ca_cert_path)
    tmpl_db = MSFStorage(tmpl, ca_cert_path=ca_cert_path)
    tmpl_uid = tmpl_db.container_uid
    note_count = tmpl_db.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    assert note_count > 0, "template should have seed notes (not copied)"
    tmpl_db.close()

    summary = create_from_template(
        tmpl, dest, creator, "My Notes App", ca_cert_path=ca_cert_path
    )
    assert summary["app_name"] == "My Notes App"
    assert summary["creator_cn"] == "tmpl_creator"
    assert summary["container_uid"] != tmpl_uid
    print(f"  [OK] fresh uid {summary['container_uid'][:8]}… ≠ template {tmpl_uid[:8]}…")

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)
    assert db.container_uid == summary["container_uid"]
    assert db.container_uid != tmpl_uid

    role = db.conn.execute(
        "SELECT role FROM user_roles WHERE identity = ?",
        [f"cert:CN={creator.cn}"],
    ).fetchone()
    assert role and role[0] == "admin", role
    # Only the creator's bootstrap admin — no lifted user_roles from author.
    roles = db.conn.execute("SELECT identity, role FROM user_roles").fetchall()
    assert roles == [(f"cert:CN={creator.cn}", "admin")], roles
    print("  [OK] creator is sole admin (no lifted user_roles)")

    tables = {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    assert "notes" in tables
    triggers = {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
    }
    assert any("notes" in t for t in triggers), triggers
    print(f"  [OK] notes table + triggers present ({len(triggers)} triggers)")

    data_rows = db.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    assert data_rows == 0, f"v1 must not copy data rows, got {data_rows}"
    print("  [OK] no data rows in notes")

    assert db.get_manifest_item("name") == "My Notes App"
    ui_status = db.get_manifest_signature_status("ui_spec")
    assert ui_status["verified"], ui_status
    assert ui_status["signer"] == creator.cn, ui_status
    print(f"  [OK] ui_spec verified, signer={ui_status['signer']}")

    report = replay_audit(db)
    if not report["ok"]:
        print(format_report(report))
    assert report["ok"], "instantiated container must audit clean"
    print("  [OK] replay_audit clean")

    # Ledger is only the new authoring rows (no lifted history).
    n_tx = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    tdb = MSFStorage(tmpl, ca_cert_path=ca_cert_path)
    tmpl_n = tdb.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    tdb.close()
    assert n_tx < tmpl_n, (
        f"new ledger ({n_tx}) should be shorter than template with seed data ({tmpl_n})"
    )
    # No seed-note INSERT bodies in the new ledger.
    note_inserts = db.conn.execute(
        "SELECT COUNT(*) FROM transactions WHERE query LIKE 'INSERT INTO notes%'"
    ).fetchone()[0]
    assert note_inserts == 0, note_inserts
    print(f"  [OK] fresh ledger only ({n_tx} rows; no lifted note inserts)")

    # Never-copied tables empty / system-only as expected.
    assert db.conn.execute("SELECT COUNT(*) FROM source_code").fetchone()[0] == 0
    outbox = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sync_outbox'"
    ).fetchone()
    if outbox:
        assert db.conn.execute("SELECT COUNT(*) FROM sync_outbox").fetchone()[0] == 0
    print("  [OK] no source_code (and no outbox rows if table exists)")

    db.close()


def test_instantiate_schema_spec(author, creator, ca_cert_path):
    print("\n--- 2. schema_spec template → rules still enforce ---")
    tmpl = "template_schema.msf"
    dest = "inst_from_schema.msf"

    # Author a schema_spec container (with a tiny ui_spec so it's a full recipe).
    author_key = load_key(author.key_path)
    db = MSFStorage(tmpl, ca_cert_path=ca_cert_path)
    apply_schema_spec(db, author_key, author.cert_pem, SCHEMA_SPEC)
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    ui = json.dumps({"type": "box", "children": [{"type": "label", "text": "Items"}]})
    for key, value in (
        ("name", "Schema Template"),
        ("ui_spec", ui),
        ("description", "schema_spec fixture"),
        ("version", "1.0"),
    ):
        db.set_manifest_item(
            key, value, sign_with(db, author_key, q, [key, value]), author.cert_pem
        )
    # Seed a data row that must NOT be copied.
    signed_exec(
        db, author_key, author.cert_pem,
        "INSERT INTO items (title) VALUES (?)", ["seed row"],
    )
    assert db.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
    report = replay_audit(db)
    assert report["ok"], format_report(report)
    tmpl_uid = db.container_uid
    db.close()

    summary = create_from_template(
        tmpl, dest, creator, "Schema App", ca_cert_path=ca_cert_path
    )
    assert summary["container_uid"] != tmpl_uid

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)
    assert "items" in {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert db.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0

    schema_status = db.get_manifest_signature_status("schema_spec")
    assert schema_status["verified"], schema_status
    assert schema_status["signer"] == creator.cn, schema_status
    ui_status = db.get_manifest_signature_status("ui_spec")
    assert ui_status["verified"] and ui_status["signer"] == creator.cn, ui_status
    print(f"  [OK] schema_spec + ui_spec verified by creator ({creator.cn})")

    # Object-level rbac from access carried over.
    rbac = db.conn.execute(
        "SELECT level, target, role, permission FROM rbac_rules "
        "WHERE level='object' AND target='items'"
    ).fetchall()
    assert ("object", "items", "member", "read") in rbac
    assert ("object", "items", "member", "write") in rbac
    print(f"  [OK] rbac_rules lifted ({len(rbac)} object rules for items)")

    report = replay_audit(db)
    if not report["ok"]:
        print(format_report(report))
    assert report["ok"]
    print("  [OK] replay_audit clean")

    # Spot-check: required-empty refused (schemaspec train re-applied).
    creator_key = load_key(creator.key_path)
    try:
        signed_exec(
            db, creator_key, creator.cert_pem,
            "INSERT INTO items (title) VALUES (?)", ["   "],
        )
        raise AssertionError("required-empty should be refused")
    except Exception as e:
        msg = str(e).lower()
        assert (
            "check" in msg or "not null" in msg or "null" in msg or "required" in msg
        ), e
        print(f"  [OK] required-empty refused: {e}")

    # Valid insert works.
    signed_exec(
        db, creator_key, creator.cert_pem,
        "INSERT INTO items (title) VALUES (?)", ["ok item"],
    )
    assert db.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
    owner = db.conn.execute("SELECT created_by FROM items").fetchone()[0]
    assert owner == f"cert:CN={creator.cn}", owner
    print("  [OK] valid insert stamps creator as owner")
    db.close()


def test_homed_template_unhomes(author, creator, ca_cert_path):
    print("\n--- 3. Homed template → unhomed new app ---")
    tmpl = "template_homed.msf"
    dest = "inst_from_homed.msf"
    create_starter_container(tmpl, author, ca_cert_path)
    author_key = load_key(author.key_path)
    db = MSFStorage(tmpl, ca_cert_path=ca_cert_path)
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    for key, value in (
        ("sync_hub_url", "http://127.0.0.1:9999"),
        ("sync_hub_cn", "hub-test"),
    ):
        db.set_manifest_item(
            key, value, sign_with(db, author_key, q, [key, value]), author.cert_pem
        )
    assert db.get_manifest_item("sync_hub_cn") == "hub-test"
    db.close()

    create_from_template(
        tmpl, dest, creator, "Unhomed Clone", ca_cert_path=ca_cert_path
    )
    db = MSFStorage(dest, ca_cert_path=ca_cert_path)
    assert db.get_manifest_item("sync_hub_url") is None
    assert db.get_manifest_item("sync_hub_cn") is None
    print("  [OK] no sync_hub_* keys on new app")

    # Local signed writes accepted (unhomed).
    creator_key = load_key(creator.key_path)
    signed_exec(
        db, creator_key, creator.cert_pem,
        "INSERT INTO notes (body) VALUES (?)", ["local write ok"],
    )
    assert db.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 1
    print("  [OK] local signed write accepted on unhomed instance")
    db.close()


def test_refusals(author, creator, ca_cert_path):
    print("\n--- 4. Refusals: tamper, pickled code, dest-exists ---")

    # Tampered template
    tmpl = "template_tampered.msf"
    create_starter_container(tmpl, author, ca_cert_path)
    raw = sqlite3.connect(tmpl)
    raw.execute(
        "UPDATE manifest SET value = ? WHERE key = ?",
        (json.dumps({"type": "box", "children": [{"type": "label", "text": "evil"}]}), "ui_spec"),
    )
    raw.commit()
    raw.close()

    dest = "inst_should_not_exist.msf"
    if os.path.exists(dest):
        os.remove(dest)
    try:
        create_from_template(
            tmpl, dest, creator, "Should Fail", ca_cert_path=ca_cert_path
        )
        raise AssertionError("tampered template must be refused")
    except TemplateError as e:
        msg = str(e).lower()
        assert "audit" in msg or "verif" in msg or "tamper" in msg or "refusing" in msg, e
        # Refusal must name the failing category, not only a generic catch-all.
        assert (
            "table mismatch" in msg
            or "untrusted" in msg
            or "invalid signature" in msg
            or "chain break" in msg
            or "mismatch" in msg
        ), f"expected specific failing category, got: {e}"
        print(f"  [OK] tampered template refused with category: {str(e).split(chr(10), 1)[0]}")
    assert not os.path.exists(dest), "dest must not be created on refusal"
    print("  [OK] dest not created after tamper refusal")

    # Pickled source_code template
    pickled = "template_pickled.msf"
    if os.path.exists(pickled):
        os.remove(pickled)
    author_key = load_key(author.key_path)
    db = MSFStorage(pickled, ca_cert_path=ca_cert_path)
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    db.bootstrap_admin(
        q, ["name", "Pickled"],
        sign_with(db, author_key, q, ["name", "Pickled"]),
        author.cert_pem,
    )
    # Minimal callable stored as dill blob.
    import dill

    def _dummy(toga, host_api):
        return None

    blob = dill.dumps(_dummy)
    sc_q = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
    db.execute_signed(
        sc_q, ["main_app", blob],
        sign_with(db, author_key, sc_q, ["main_app", blob]),
        author.cert_pem,
    )
    db.set_manifest_item(
        "entry_point", "main_app",
        sign_with(db, author_key, q, ["entry_point", "main_app"]),
        author.cert_pem,
    )
    db.close()

    try:
        create_from_template(
            pickled, dest, creator, "Pickled Fail", ca_cert_path=ca_cert_path
        )
        raise AssertionError("pickled template must be refused")
    except TemplateError as e:
        assert "pickled" in str(e).lower() or "source_code" in str(e).lower(), e
        print(f"  [OK] pickled-code template refused: {e}")
    assert not os.path.exists(dest)
    print("  [OK] dest not created after pickled refusal")

    # Dest exists
    if not os.path.exists("template_starter.msf"):
        create_starter_container("template_starter.msf", author, ca_cert_path)
    if os.path.exists("inst_dup.msf"):
        os.remove("inst_dup.msf")
    create_starter_container("inst_dup.msf", author, ca_cert_path)
    try:
        create_from_template(
            "template_starter.msf", "inst_dup.msf", creator, "Dup",
            ca_cert_path=ca_cert_path,
        )
        raise AssertionError("dest-exists must raise FileExistsError")
    except FileExistsError as e:
        print(f"  [OK] dest-exists refused: {e}")


def _ensure_pickled_fixture(author, ca_cert_path):
    pickled = "template_pickled.msf"
    if os.path.exists(pickled):
        return pickled
    author_key = load_key(author.key_path)
    db = MSFStorage(pickled, ca_cert_path=ca_cert_path)
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    db.bootstrap_admin(
        q, ["name", "Pickled"],
        sign_with(db, author_key, q, ["name", "Pickled"]),
        author.cert_pem,
    )
    import dill

    def _dummy(toga, host_api):
        return None

    blob = dill.dumps(_dummy)
    sc_q = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
    db.execute_signed(
        sc_q, ["main_app", blob],
        sign_with(db, author_key, sc_q, ["main_app", blob]),
        author.cert_pem,
    )
    db.close()
    return pickled


def test_check_template_verdicts(author, creator, ca_cert_path):
    print("\n--- 5. check_template verdicts ---")

    # Declarative starter → eligible
    if not os.path.exists("template_starter.msf"):
        create_starter_container("template_starter.msf", author, ca_cert_path)
    v = check_template("template_starter.msf", ca_cert_path=ca_cert_path)
    assert v["eligible"] is True, v
    assert "declarative" in v["reason"].lower() or "verified" in v["reason"].lower(), v
    print(f"  [OK] starter eligible: {v['reason']}")

    # Pickled code → ineligible "pickled"
    pickled = _ensure_pickled_fixture(author, ca_cert_path)
    v = check_template(pickled, ca_cert_path=ca_cert_path)
    assert v["eligible"] is False, v
    assert "pickled" in v["reason"].lower(), v
    print(f"  [OK] pickled ineligible: {v['reason']}")

    # Tampered ui_spec (raw manifest edit) → ineligible naming the signature
    tampered = "template_tampered.msf"
    if not os.path.exists(tampered):
        create_starter_container(tampered, author, ca_cert_path)
        raw = sqlite3.connect(tampered)
        raw.execute(
            "UPDATE manifest SET value = ? WHERE key = ?",
            (
                json.dumps({"type": "box", "children": [{"type": "label", "text": "evil"}]}),
                "ui_spec",
            ),
        )
        raw.commit()
        raw.close()
    v = check_template(tampered, ca_cert_path=ca_cert_path)
    assert v["eligible"] is False, v
    assert "signature" in v["reason"].lower() or "ui_spec" in v["reason"].lower(), v
    print(f"  [OK] tampered ui_spec ineligible: {v['reason']}")

    # Garbage file → ineligible, no exception
    garbage = "template_garbage.bin"
    with open(garbage, "wb") as f:
        f.write(b"this is not a sqlite database at all\x00\x01\x02")
    v = check_template(garbage, ca_cert_path=ca_cert_path)
    assert v["eligible"] is False, v
    assert "not a valid container" in v["reason"].lower() or "valid" in v["reason"].lower(), v
    print(f"  [OK] garbage ineligible (no raise): {v['reason']}")

    # Missing declarative specs
    no_spec = "template_no_spec.msf"
    if os.path.exists(no_spec):
        os.remove(no_spec)
    author_key = load_key(author.key_path)
    db = MSFStorage(no_spec, ca_cert_path=ca_cert_path)
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    db.bootstrap_admin(
        q, ["name", "No Spec"],
        sign_with(db, author_key, q, ["name", "No Spec"]),
        author.cert_pem,
    )
    db.close()
    v = check_template(no_spec, ca_cert_path=ca_cert_path)
    assert v["eligible"] is False, v
    assert "no declarative spec" in v["reason"].lower(), v
    print(f"  [OK] missing specs ineligible: {v['reason']}")


def test_check_template_ca_orphan(author, ca_cert_path):
    print("\n--- 6. check_template CA-orphan (untrusted signer) ---")
    orphan = "template_orphan.msf"
    if os.path.exists(orphan):
        os.remove(orphan)
    create_starter_container(orphan, author, ca_cert_path)

    # Trust setup that does NOT include the authoring CA.
    trust_dir = "tmpl_orphan_trust"
    if os.path.isdir(trust_dir):
        for name in os.listdir(trust_dir):
            os.remove(os.path.join(trust_dir, name))
    else:
        os.makedirs(trust_dir, exist_ok=True)
    # Non-existent CA file + empty trust dir → no anchors → fail closed.
    foreign_ca = os.path.join(trust_dir, "missing_foreign_ca.crt")
    v = check_template(orphan, ca_cert_path=foreign_ca, trust_dir=trust_dir)
    assert v["eligible"] is False, v
    reason_l = v["reason"].lower()
    assert (
        "signature" in reason_l
        or "trust" in reason_l
        or "unverified" in reason_l
        or "ca" in reason_l
        or "signer" in reason_l
    ), v
    print(f"  [OK] CA-orphan ineligible: {v['reason']}")


def test_check_template_cheapness(author, ca_cert_path):
    print("\n--- 7. check_template does not call replay_audit ---")
    if not os.path.exists("template_starter.msf"):
        create_starter_container("template_starter.msf", author, ca_cert_path)

    import mschf.audit as audit_mod
    import mschf.template as template_mod

    original = audit_mod.replay_audit
    calls = {"n": 0}

    def _boom(*args, **kwargs):
        calls["n"] += 1
        raise AssertionError("replay_audit must not be called from check_template")

    audit_mod.replay_audit = _boom
    template_mod.replay_audit = _boom
    try:
        v = check_template("template_starter.msf", ca_cert_path=ca_cert_path)
        assert v["eligible"] is True, v
        assert calls["n"] == 0, calls
        print("  [OK] check_template completed without touching replay_audit")
    finally:
        audit_mod.replay_audit = original
        template_mod.replay_audit = original


def run():
    cleanup()
    ca_cert_path, ca_cert, ca_key = ensure_ca()
    author = write_identity("tmpl_author", ca_cert, ca_key)
    creator = write_identity("tmpl_creator", ca_cert, ca_key)
    assert author.is_valid and creator.is_valid
    assert author.cn != creator.cn

    test_instantiate_starter(author, creator, ca_cert_path)
    test_instantiate_schema_spec(author, creator, ca_cert_path)
    test_homed_template_unhomes(author, creator, ca_cert_path)
    test_refusals(author, creator, ca_cert_path)
    test_check_template_verdicts(author, creator, ca_cert_path)
    test_check_template_ca_orphan(author, ca_cert_path)
    test_check_template_cheapness(author, ca_cert_path)

    print("\n=== ALL TEMPLATE TESTS PASSED ===")
    assert "toga" not in sys.modules, "toga must not be imported by headless tests"
    cleanup()


if __name__ == "__main__":
    run()
