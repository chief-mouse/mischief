"""Integration tests for schema_spec compiler + authoring (headless).

Run: python test_schemaspec.py

Covers validation, deterministic compile, engine-level enforcement, evolution
(additive only), and replay_audit cleanliness. Does not import toga.
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
from mschf.gen_cert import (
    default_backend,
    generate_selfsigned_cert,
    generate_user_cert,
    serialization,
)
from mschf.schemaspec import (
    SchemaSpecError,
    apply_schema_spec,
    canonical_schema_json,
    compile_schema_spec,
    get_schema_spec,
    validate_schema_spec,
    verify_schema_spec,
)
from mschf.storage import MSFStorage, canonical_payload

DB_PATH = "test_schemaspec.msf"
ARTIFACTS = [
    DB_PATH,
    "schema_admin.crt",
    "schema_admin.key",
    "schema_member.crt",
    "schema_member.key",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


FULL_SPEC = {
    "v": 1,
    "objects": [
        {
            "name": "dev_tasks",
            "fields": [
                {"name": "title", "type": "text", "rules": ["required"]},
            ],
            "access": {"member": ["read", "write"]},
        },
        {
            "name": "expenses",
            "fields": [
                {"name": "title", "type": "text", "rules": ["required"]},
                {"name": "amount", "type": "real", "rules": ["required"]},
                {
                    "name": "state",
                    "type": "text",
                    "rules": [{"enum": ["draft", "submitted", "approved"]}],
                },
                {
                    "name": "code",
                    "type": "text",
                    "rules": ["unique"],
                },
                {
                    "name": "task_id",
                    "type": "integer",
                    "rules": [{"reference": "dev_tasks.id"}],
                },
                {
                    "name": "receipt",
                    "type": "text",
                    "rules": ["immutable_after_create"],
                },
            ],
            "object_rules": ["owner_only_update"],
            "access": {"member": ["read", "write"]},
        },
    ],
}


def cleanup():
    for path in ARTIFACTS:
        if os.path.exists(path):
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
    return cert, key


def load_key(pem_key_bytes):
    return load_pem_private_key(pem_key_bytes, password=None)


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


def chain_head(db):
    return db.get_chain_head()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_author_and_structure(db, admin_key, admin_cert):
    print("--- 1. Author container + apply full schema_spec ---")
    apply_schema_spec(db, admin_key, admin_cert, FULL_SPEC)

    # Tables + columns
    for table in ("dev_tasks", "expenses"):
        cols = {
            r[1]
            for r in db.conn.execute(f'PRAGMA table_info("{table}")').fetchall()
        }
        assert "id" in cols and "created_by" in cols and "updated_at" in cols, cols
        print(f"  [OK] table {table} has audit columns + id")

    exp_cols = {
        r[1] for r in db.conn.execute("PRAGMA table_info(expenses)").fetchall()
    }
    for c in ("title", "amount", "state", "code", "task_id", "receipt"):
        assert c in exp_cols, exp_cols

    # Triggers
    triggers = {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
    }
    for name in (
        "trg_expenses_insert_audit",
        "trg_expenses_update_audit",
        "trg_expenses_created_immutable",
        "trg_expenses_owner_only",
        "trg_expenses_receipt_immutable",
        "trg_dev_tasks_insert_audit",
    ):
        assert name in triggers, f"missing trigger {name}; have {triggers}"
    print(f"  [OK] {len(triggers)} triggers present (audit + rules)")

    # Unique index
    indexes = {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    assert "ux_expenses_code" in indexes, indexes
    print("  [OK] unique index ux_expenses_code")

    # RBAC seeds
    rbac = db.conn.execute(
        "SELECT level, target, role, permission FROM rbac_rules "
        "WHERE level='object' ORDER BY target, role, permission"
    ).fetchall()
    assert ("object", "expenses", "member", "read") in rbac
    assert ("object", "expenses", "member", "write") in rbac
    assert ("object", "dev_tasks", "member", "read") in rbac
    print(f"  [OK] object-level rbac_rules seeded ({len(rbac)} rows)")

    # Manifest
    stored = get_schema_spec(db)
    assert stored is not None
    assert stored["v"] == 1
    assert len(stored["objects"]) == 2
    status = verify_schema_spec(db)
    assert status["verified"], status
    assert status["signer"] == "schema_admin"
    print("  [OK] schema_spec manifest verified")

    report = replay_audit(db)
    if not report["ok"]:
        print(format_report(report))
    assert report["ok"], "clean authored container must pass replay_audit"
    print("  [OK] replay_audit clean after authoring")


def test_enforcement(db, admin_key, admin_cert, member_key, member_cert):
    print("\n--- 2. Engine-level enforcement (execute_signed + raw sqlite3) ---")

    # Seed a parent task for FK.
    signed_exec(
        db, admin_key, admin_cert,
        "INSERT INTO dev_tasks (title) VALUES (?)", ["parent task"],
    )
    task_id = db.conn.execute("SELECT id FROM dev_tasks").fetchone()[0]

    # Valid insert as admin (owner).
    signed_exec(
        db, admin_key, admin_cert,
        "INSERT INTO expenses (title, amount, state, code, task_id, receipt) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ["lunch", 12.5, "draft", "EXP-001", task_id, "r1.pdf"],
    )
    exp_id = db.conn.execute(
        "SELECT id FROM expenses WHERE code = ?", ["EXP-001"]
    ).fetchone()[0]
    owner = db.conn.execute(
        "SELECT created_by FROM expenses WHERE id = ?", [exp_id]
    ).fetchone()[0]
    assert owner == "cert:CN=schema_admin", owner
    print("  [OK] valid insert stamps created_by from current_signer()")

    # required-empty refused (text)
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO expenses (title, amount, state, code, task_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["   ", 1.0, "draft", "EXP-BLANK", task_id],
        )
        raise AssertionError("empty required text should be refused")
    except Exception as e:
        assert "CHECK" in str(e).upper() or "not null" in str(e).lower() or "null" in str(e).lower(), e
        print(f"  [OK] required-empty text refused: {e}")

    # required NULL real
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO expenses (title, amount, state, code, task_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["x", None, "draft", "EXP-NULLAMT", task_id],
        )
        raise AssertionError("NULL required real should be refused")
    except Exception as e:
        assert "NOT NULL" in str(e).upper() or "null" in str(e).lower(), e
        print(f"  [OK] required NULL real refused: {e}")

    # enum violation
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO expenses (title, amount, state, code, task_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["x", 1.0, "bogus", "EXP-ENUM", task_id],
        )
        raise AssertionError("enum violation should be refused")
    except Exception as e:
        assert "CHECK" in str(e).upper() or "constraint" in str(e).lower(), e
        print(f"  [OK] enum violation refused: {e}")

    # unique dup
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO expenses (title, amount, state, code, task_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["dup", 1.0, "draft", "EXP-001", task_id],
        )
        raise AssertionError("unique dup should be refused")
    except Exception as e:
        assert "unique" in str(e).lower(), e
        print(f"  [OK] unique dup refused: {e}")

    # reference / FK violation
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO expenses (title, amount, state, code, task_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["orphan", 1.0, "draft", "EXP-FK", 99999],
        )
        raise AssertionError("FK violation should be refused")
    except Exception as e:
        msg = str(e).lower()
        assert "foreign" in msg or "constraint" in msg or "reference" in msg, e
        print(f"  [OK] reference/FK violation refused: {e}")

    # immutable field change refused
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "UPDATE expenses SET receipt = ? WHERE id = ?",
            ["changed.pdf", exp_id],
        )
        raise AssertionError("immutable receipt change should be refused")
    except Exception as e:
        assert "immutable" in str(e).lower() or "receipt" in str(e).lower(), e
        print(f"  [OK] immutable_after_create refused: {e}")

    # Grant member role so non-owner has write path through RBAC.
    member_id = db._get_identity(member_cert)
    signed_exec(
        db, admin_key, admin_cert,
        "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
        [member_id, "member"],
    )
    # Database-level write for member (object write alone is not enough).
    for params in (
        ["database", "*", "member", "read"],
        ["database", "*", "member", "write"],
    ):
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            params,
        )

    # owner_only: non-owner signed UPDATE refused
    try:
        signed_exec(
            db, member_key, member_cert,
            "UPDATE expenses SET amount = ? WHERE id = ?",
            [99.0, exp_id],
        )
        raise AssertionError("non-owner update should be refused")
    except Exception as e:
        assert "owner" in str(e).lower() or "abort" in str(e).lower(), e
        print(f"  [OK] owner_only_update non-owner refused: {e}")

    # owner allowed
    signed_exec(
        db, admin_key, admin_cert,
        "UPDATE expenses SET amount = ? WHERE id = ?",
        [15.0, exp_id],
    )
    amt = db.conn.execute(
        "SELECT amount FROM expenses WHERE id = ?", [exp_id]
    ).fetchone()[0]
    assert float(amt) == 15.0, amt
    print("  [OK] owner update allowed")

    # raw unsigned sqlite3 UPDATE → NULL signer refused
    # Use a fresh connection that does NOT register current_signer — either
    # "no such function" or the owner_only RAISE with NULL IS NOT owner.
    raw = sqlite3.connect(DB_PATH)
    raw.execute("PRAGMA foreign_keys = ON")
    try:
        raw.execute("UPDATE expenses SET amount = 1.0 WHERE id = ?", (exp_id,))
        raw.commit()
        raise AssertionError("raw unsigned UPDATE should be refused")
    except Exception as e:
        msg = str(e).lower()
        assert (
            "current_signer" in msg
            or "owner" in msg
            or "abort" in msg
            or "no such function" in msg
        ), e
        print(f"  [OK] raw unsigned UPDATE refused (NULL signer): {e}")
    finally:
        raw.close()

    report = replay_audit(db)
    assert report["ok"], format_report(report)
    print("  [OK] replay_audit still clean after enforcement trials")


def test_determinism(db, admin_key, admin_cert):
    print("\n--- 3. Determinism + manifest integrity ---")
    a = compile_schema_spec(FULL_SPEC)
    b = compile_schema_spec(FULL_SPEC)
    assert a == b, "compile must be byte-identical for the same spec"
    assert all(isinstance(sql, str) and isinstance(p, list) for sql, p in a)
    print(f"  [OK] compile twice → identical train ({len(a)} statements)")

    # Canonical JSON (sort_keys + compact separators)
    j1 = canonical_schema_json(FULL_SPEC)
    j2 = canonical_schema_json(FULL_SPEC)
    assert j1 == j2
    assert j1 == json.dumps(FULL_SPEC, sort_keys=True, separators=(",", ":"))
    stored_raw = db.get_manifest_item("schema_spec")
    assert stored_raw == j1
    print("  [OK] manifest JSON is canonical (sort_keys)")

    status = verify_schema_spec(db)
    assert status["verified"] and status["signer"] == "schema_admin"
    print("  [OK] verify_schema_spec reports verified with signer")

    # Out-of-band manifest edit → not verified + audit flags container
    head_before_tamper = chain_head(db)
    raw = sqlite3.connect(DB_PATH)
    raw.execute(
        "UPDATE manifest SET value = ? WHERE key = 'schema_spec'",
        ['{"v":1,"objects":[]}'],
    )
    raw.commit()
    raw.close()

    # Re-open to see tampered value through storage connection cache... same conn.
    # MSFStorage shares its connection; force re-read.
    status2 = verify_schema_spec(db)
    assert not status2["verified"], status2
    print(f"  [OK] OOB manifest edit → verified=False ({status2.get('error')})")

    report = replay_audit(db)
    assert not report["ok"], "tampered schema_spec must fail replay_audit"
    print("  [OK] replay_audit flags OOB manifest edit")

    # Restore signed value so later tests see a clean container.
    # We cannot re-sign easily without advancing chain; restore via raw to the
    # previously signed bytes — that re-matches the ledger params so verify
    # passes again and audit is clean.
    raw = sqlite3.connect(DB_PATH)
    raw.execute(
        "UPDATE manifest SET value = ? WHERE key = 'schema_spec'",
        [j1],
    )
    raw.commit()
    raw.close()
    status3 = verify_schema_spec(db)
    assert status3["verified"], status3
    report = replay_audit(db)
    assert report["ok"], format_report(report)
    # Chain head must be unchanged by OOB edits.
    assert chain_head(db) == head_before_tamper
    print("  [OK] restored signed schema_spec; audit clean again")


def test_evolution(db, admin_key, admin_cert):
    print("\n--- 4. Evolution (additive) + refusals ---")

    # --- add optional field, add object, add rule (unique via trigger/index) ---
    # Insert a row that would violate a not-yet-applied unique rule on a new
    # field? Better: add unique rule to an existing nullable field that already
    # has duplicate-capable values... We use a new optional field then later
    # add unique; and insert pre-rule free-form values.

    # First: add a new object `tags` and an optional field notes on expenses.
    evolved = json.loads(json.dumps(FULL_SPEC))
    evolved["objects"].append({
        "name": "tags",
        "fields": [
            {"name": "label", "type": "text", "rules": ["required"]},
        ],
        "access": {"member": ["read"]},
    })
    # Add optional field `notes` to expenses
    for obj in evolved["objects"]:
        if obj["name"] == "expenses":
            obj["fields"].append({"name": "notes", "type": "text", "rules": []})
            break

    apply_schema_spec(db, admin_key, admin_cert, evolved)
    assert "notes" in {
        r[1] for r in db.conn.execute("PRAGMA table_info(expenses)").fetchall()
    }
    assert "tags" in {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    print("  [OK] evolution: new object + optional field applied")

    # Insert a row with notes=NULL (fine). Then add required rule via evolution
    # using trigger form — pre-existing NULL rows predate the rule; replay must
    # still pass (trigger not present historically when those rows were written
    # is handled by replay: triggers are ledger-ordered).
    # Actually required triggers fire on UPDATE/INSERT only, not on existing
    # rows. Insert a violating-by-new-rule value BEFORE the rule lands:
    # Use enum on notes — insert 'weird' then add enum that excludes it.
    signed_exec(
        db, admin_key, admin_cert,
        "UPDATE expenses SET notes = ? WHERE code = ?",
        ["legacy-free-text", "EXP-001"],
    )
    print("  [OK] pre-rule row written with notes='legacy-free-text'")

    evolved2 = json.loads(json.dumps(evolved))
    for obj in evolved2["objects"]:
        if obj["name"] == "expenses":
            for f in obj["fields"]:
                if f["name"] == "notes":
                    f["rules"] = [{"enum": ["a", "b", "c"]}]
                    break
    apply_schema_spec(db, admin_key, admin_cert, evolved2)

    # New inserts with bad enum refuse; old row remains.
    legacy = db.conn.execute(
        "SELECT notes FROM expenses WHERE code = ?", ["EXP-001"]
    ).fetchone()[0]
    assert legacy == "legacy-free-text", legacy
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO expenses (title, amount, state, code, task_id, notes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ["n", 1.0, "draft", "EXP-NEWENUM", 1, "nope"],
        )
        raise AssertionError("new enum rule should refuse bad insert")
    except Exception as e:
        assert "abort" in str(e).lower() or "must be one of" in str(e).lower() or "notes" in str(e).lower(), e
        print(f"  [OK] new enum rule enforces on new writes: {e}")

    report = replay_audit(db)
    assert report["ok"], format_report(report)
    print("  [OK] replay_audit clean; legacy row predates new enum rule")

    # --- Refusals: retype, remove field, required-on-nonempty ---
    head = chain_head(db)

    # Retype
    bad = json.loads(json.dumps(evolved2))
    for obj in bad["objects"]:
        if obj["name"] == "expenses":
            for f in obj["fields"]:
                if f["name"] == "amount":
                    f["type"] = "integer"
    try:
        apply_schema_spec(db, admin_key, admin_cert, bad)
        raise AssertionError("retype should raise SchemaSpecError")
    except SchemaSpecError as e:
        assert "rebuild" in str(e).lower() or "retyped" in str(e).lower(), e
        print(f"  [OK] retype refused: {e}")
    assert chain_head(db) == head, "chain head must not advance on refused evolution"

    # Remove field
    head = chain_head(db)
    bad = json.loads(json.dumps(evolved2))
    for obj in bad["objects"]:
        if obj["name"] == "expenses":
            obj["fields"] = [f for f in obj["fields"] if f["name"] != "receipt"]
    try:
        apply_schema_spec(db, admin_key, admin_cert, bad)
        raise AssertionError("remove field should raise SchemaSpecError")
    except SchemaSpecError as e:
        assert "rebuild" in str(e).lower() or "removed" in str(e).lower(), e
        print(f"  [OK] remove field refused: {e}")
    assert chain_head(db) == head

    # required on non-empty table
    head = chain_head(db)
    bad = json.loads(json.dumps(evolved2))
    for obj in bad["objects"]:
        if obj["name"] == "expenses":
            obj["fields"].append({
                "name": "must_have",
                "type": "text",
                "rules": ["required"],
            })
    try:
        apply_schema_spec(db, admin_key, admin_cert, bad)
        raise AssertionError("required new field on non-empty should refuse")
    except SchemaSpecError as e:
        assert "rebuild" in str(e).lower() or "non-empty" in str(e).lower() or "required" in str(e).lower(), e
        print(f"  [OK] required-on-nonempty refused: {e}")
    assert chain_head(db) == head
    print("  [OK] refused evolutions leave chain head unchanged")


def test_validation_errors(db, admin_key, admin_cert):
    print("\n--- 5. Spec validation errors (no signing) ---")
    head = chain_head(db)

    cases = [
        (
            "unknown rule",
            {
                "v": 1,
                "objects": [{
                    "name": "t1",
                    "fields": [
                        {"name": "a", "type": "text", "rules": ["not_a_real_rule"]},
                    ],
                }],
            },
            "unknown rule",
        ),
        (
            "dup field",
            {
                "v": 1,
                "objects": [{
                    "name": "t2",
                    "fields": [
                        {"name": "a", "type": "text"},
                        {"name": "a", "type": "integer"},
                    ],
                }],
            },
            "duplicate field",
        ),
        (
            "reserved object name transactions",
            {
                "v": 1,
                "objects": [{
                    "name": "transactions",
                    "fields": [{"name": "a", "type": "text"}],
                }],
            },
            "reserved",
        ),
        (
            "reserved field created_by",
            {
                "v": 1,
                "objects": [{
                    "name": "t3",
                    "fields": [{"name": "created_by", "type": "text"}],
                }],
            },
            "reserved",
        ),
        (
            "bad reference format",
            {
                "v": 1,
                "objects": [{
                    "name": "t4",
                    "fields": [
                        {
                            "name": "fk",
                            "type": "integer",
                            "rules": [{"reference": "not_a_valid_ref"}],
                        },
                    ],
                }],
            },
            "malformed reference",
        ),
    ]

    for label, spec, needle in cases:
        try:
            apply_schema_spec(db, admin_key, admin_cert, spec)
            raise AssertionError(f"{label}: expected SchemaSpecError")
        except SchemaSpecError as e:
            assert needle.lower() in str(e).lower(), (label, e)
            print(f"  [OK] {label}: {e}")
        assert chain_head(db) == head, f"chain moved after {label}"

    # validate_schema_spec alone also raises
    try:
        validate_schema_spec({"v": 1, "objects": []})
        raise AssertionError("empty objects should fail")
    except SchemaSpecError:
        print("  [OK] validate_schema_spec rejects empty objects")
    assert chain_head(db) == head
    print("  [OK] all validation failures leave chain head unchanged")


def run():
    cleanup()
    ca_cert_path, ca_cert, ca_key = ensure_ca()
    admin_cert, admin_key_pem = write_identity("schema_admin", ca_cert, ca_key)
    member_cert, member_key_pem = write_identity("schema_member", ca_cert, ca_key)
    admin_key = load_key(admin_key_pem)
    member_key = load_key(member_key_pem)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = MSFStorage(DB_PATH, ca_cert_path=ca_cert_path)

    try:
        test_author_and_structure(db, admin_key, admin_cert)
        test_enforcement(db, admin_key, admin_cert, member_key, member_cert)
        test_determinism(db, admin_key, admin_cert)
        test_evolution(db, admin_key, admin_cert)
        test_validation_errors(db, admin_key, admin_cert)
    finally:
        db.close()

    print("\n--- Gate: toga must not be imported ---")
    assert "toga" not in sys.modules, "toga was imported — tests must stay headless"
    print("  [OK] 'toga' not in sys.modules")

    print("\n=== ALL schema_spec TESTS PASSED ===")


if __name__ == "__main__":
    run()
