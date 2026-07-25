"""No-code editor v1 tests (headless, CI-safe — no toga at runtime).

Run: python test_editor.py

Covers validation, signed saves, helpers, additive schema evolution via
save_schema_spec, rebuild refusal (chain head untouched), and homed-replica
refusal. Ends with assert that toga was never imported.
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath("src"))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from mschf.audit import format_report, replay_audit
from mschf.declarative import resolve_ui_mode
from mschf.editor import (
    HOMED_EDIT_REFUSAL,
    EditorError,
    helper_add_list_view,
    helper_add_object,
    helper_add_rule,
    load_spec_texts,
    save_schema_spec,
    save_ui_spec,
    validate_schema_spec_text,
    validate_ui_spec_text,
)
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert
from mschf.schemaspec import SchemaSpecError, apply_schema_spec, get_schema_spec
from mschf.storage import MSFStorage, canonical_payload

# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

DB_PATH = "test_editor.msf"
HOMED_PATH = "test_editor_homed.msf"
ARTIFACTS = [
    DB_PATH,
    HOMED_PATH,
    "editor_admin.crt",
    "editor_admin.key",
]

BASE_UI_SPEC = {
    "type": "box",
    "direction": "column",
    "margin": 12,
    "children": [
        {
            "type": "label",
            "text": "Editor Fixture",
            "font_size": 16,
            "bold": True,
        },
        {
            "type": "table",
            "id": "items_table",
            "headings": ["Id", "Title"],
            "query": {
                "sql": "SELECT id, title FROM items ORDER BY id",
                "params": [],
            },
            "columns": [0, 1],
            "flex": 1,
        },
        {
            "type": "box",
            "direction": "row",
            "children": [
                {
                    "type": "text_input",
                    "id": "item_title",
                    "placeholder": "Title",
                    "flex": 1,
                },
                {
                    "type": "button",
                    "text": "Add",
                    "action": {
                        "kind": "exec",
                        "sql": "INSERT INTO items (title) VALUES (?)",
                        "args": [{"input": "item_title"}],
                        "then_refresh": ["items_table"],
                        "status": "status_line",
                    },
                },
            ],
        },
        {"type": "status", "id": "status_line"},
    ],
}

BASE_SCHEMA_SPEC = {
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


def author_fixture(ca_cert_path, admin_key, admin_cert, dest=DB_PATH):
    """Author a declarative container with ui_spec + schema_spec as admin."""
    if os.path.exists(dest):
        os.remove(dest)

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)

    # Bootstrap admin via first signed write, then apply schema + ui.
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    params = ["name", "Editor Fixture"]
    sig = sign_with(db, admin_key, q, params)
    db.bootstrap_admin(q, params, sig, admin_cert)

    apply_schema_spec(db, admin_key, admin_cert, BASE_SCHEMA_SPEC)

    ui_json = json.dumps(BASE_UI_SPEC, sort_keys=True)
    save_ui_spec(db, admin_key, admin_cert, ui_json)

    report = replay_audit(db)
    assert report["ok"], format_report(report)
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_validation(db, admin_key, admin_cert):
    print("--- 2. Validation (malformed / unknown / schema violations) ---")
    head = chain_head(db)

    # Malformed JSON
    errs = validate_ui_spec_text("{not json")
    assert errs and "JSON" in errs[0], errs
    errs = validate_schema_spec_text("][")
    assert errs and "JSON" in errs[0], errs
    print("  [OK] malformed JSON returns errors")

    # Unknown declarative construct
    bad_ui = json.dumps({"type": "spaceship", "id": "x"})
    errs = validate_ui_spec_text(bad_ui)
    assert errs and "unknown" in errs[0].lower(), errs
    print(f"  [OK] unknown widget: {errs[0]}")

    # schemaspec violation
    bad_schema = json.dumps({
        "v": 1,
        "objects": [{
            "name": "t",
            "fields": [{"name": "a", "type": "text", "rules": ["not_a_real_rule"]}],
        }],
    })
    errs = validate_schema_spec_text(bad_schema)
    assert errs and "unknown rule" in errs[0].lower(), errs
    print(f"  [OK] schemaspec violation: {errs[0]}")

    # Invalid input never signs — chain head unchanged after refused saves
    try:
        save_ui_spec(db, admin_key, admin_cert, bad_ui)
        raise AssertionError("save_ui_spec should refuse invalid ui_spec")
    except EditorError as e:
        assert "validation" in str(e).lower(), e
        print(f"  [OK] save_ui_spec refused invalid: {e}")
    assert chain_head(db) == head, "chain head must not advance on refused ui save"

    try:
        save_schema_spec(db, admin_key, admin_cert, bad_schema)
        raise AssertionError("save_schema_spec should refuse invalid schema")
    except EditorError as e:
        assert "validation" in str(e).lower(), e
        print(f"  [OK] save_schema_spec refused invalid: {e}")
    assert chain_head(db) == head, "chain head must not advance on refused schema save"

    # Valid texts return empty error lists
    assert validate_ui_spec_text(json.dumps(BASE_UI_SPEC, sort_keys=True)) == []
    assert validate_schema_spec_text(json.dumps(BASE_SCHEMA_SPEC)) == []
    print("  [OK] valid specs return no errors")


def test_save_ui_spec(db, admin_key, admin_cert):
    print("\n--- 3. Save ui_spec ---")
    edited = json.loads(json.dumps(BASE_UI_SPEC))
    edited["children"][0]["text"] = "Editor Fixture — edited"
    text = json.dumps(edited, indent=2)

    save_ui_spec(db, admin_key, admin_cert, text)

    status = db.get_manifest_signature_status("ui_spec")
    assert status["verified"], status
    assert status["signer"] == "editor_admin", status
    print(f"  [OK] ui_spec verified, signer={status['signer']}")

    stored = json.loads(db.get_manifest_item("ui_spec"))
    assert stored["children"][0]["text"] == "Editor Fixture — edited"
    # Canonical sort_keys form
    assert db.get_manifest_item("ui_spec") == json.dumps(edited, sort_keys=True)
    print("  [OK] stored value is sort_keys-canonicalized")

    report = replay_audit(db)
    assert report["ok"], format_report(report)
    print("  [OK] replay_audit clean")

    mode, payload = resolve_ui_mode(db)
    assert mode == "declarative", mode
    assert payload["children"][0]["text"] == "Editor Fixture — edited"
    print("  [OK] resolve_ui_mode still declarative")


def test_save_schema_spec(db, admin_key, admin_cert):
    print("\n--- 4. Save schema_spec (additive + rebuild refusal) ---")

    # Additive: new optional field + new rule on existing field
    evolved = json.loads(json.dumps(BASE_SCHEMA_SPEC))
    for obj in evolved["objects"]:
        if obj["name"] == "items":
            obj["fields"].append({"name": "notes", "type": "text", "rules": []})
            obj["fields"].append({
                "name": "code",
                "type": "text",
                "rules": ["unique"],
            })
    save_schema_spec(
        db, admin_key, admin_cert, json.dumps(evolved, indent=2)
    )

    cols = {
        r[1] for r in db.conn.execute("PRAGMA table_info(items)").fetchall()
    }
    assert "notes" in cols and "code" in cols, cols
    print("  [OK] additive fields notes + code applied")

    # Unique rule enforced via crafted signed write
    signed_exec(
        db, admin_key, admin_cert,
        "INSERT INTO items (title, code) VALUES (?, ?)",
        ["one", "C1"],
    )
    try:
        signed_exec(
            db, admin_key, admin_cert,
            "INSERT INTO items (title, code) VALUES (?, ?)",
            ["two", "C1"],
        )
        raise AssertionError("duplicate code should be refused")
    except Exception as e:
        msg = str(e).lower()
        assert "unique" in msg or "constraint" in msg, e
        print(f"  [OK] unique rule enforced: {e}")

    stored = get_schema_spec(db)
    assert any(
        f.get("name") == "notes"
        for o in stored["objects"] if o["name"] == "items"
        for f in o["fields"]
    )
    status = db.get_manifest_signature_status("schema_spec")
    assert status["verified"] and status["signer"] == "editor_admin", status
    print("  [OK] schema_spec verified with admin signer")

    report = replay_audit(db)
    assert report["ok"], format_report(report)
    print("  [OK] replay_audit clean after additive evolution")

    # Rebuild-class edit refused; chain head untouched
    head = chain_head(db)
    bad = json.loads(json.dumps(evolved))
    for obj in bad["objects"]:
        if obj["name"] == "items":
            for f in obj["fields"]:
                if f["name"] == "title":
                    f["type"] = "integer"  # retype → rebuild
    try:
        save_schema_spec(db, admin_key, admin_cert, json.dumps(bad))
        raise AssertionError("retype should be refused")
    except SchemaSpecError as e:
        assert "rebuild" in str(e).lower() or "retyped" in str(e).lower(), e
        print(f"  [OK] rebuild-class edit refused with schemaspec message: {e}")
    assert chain_head(db) == head, "chain head must be untouched on refusal"
    print("  [OK] chain head unchanged after refused evolution")


def test_helpers():
    print("\n--- 5. Helpers (round-trip validators) ---")

    # add_object → schema valid
    schema = json.loads(json.dumps(BASE_SCHEMA_SPEC))
    schema2 = helper_add_object(
        schema,
        "tags",
        [("label", "text", ["required"]), ("color", "text", [])],
    )
    assert schema is not schema2  # no mutate
    assert any(o["name"] == "tags" for o in schema2["objects"])
    assert not any(o["name"] == "tags" for o in schema["objects"])
    errs = validate_schema_spec_text(json.dumps(schema2))
    assert errs == [], errs
    print("  [OK] helper_add_object → valid schema_spec (input not mutated)")

    # add_list_view → ui valid, no id collisions, INSERT targets object
    ui = json.loads(json.dumps(BASE_UI_SPEC))
    ui2 = helper_add_list_view(ui, "tags", ["label", "color"])
    assert ui is not ui2
    errs = validate_ui_spec_text(json.dumps(ui2))
    assert errs == [], errs

    # Collect ids — no duplicates (collect_ids raises on dup)
    from mschf.editor import collect_ids
    ids = collect_ids(ui2)
    assert "tags_table" in ids
    assert "tags_status" in ids
    assert "tags_label_input" in ids
    assert "tags_color_input" in ids

    # Find INSERT action targeting tags
    def find_insert(node, found=None):
        if found is None:
            found = []
        if isinstance(node, dict):
            action = node.get("action")
            if isinstance(action, dict) and action.get("kind") == "exec":
                sql = action.get("sql") or ""
                if sql.upper().startswith("INSERT") and "tags" in sql:
                    found.append(action)
            for c in node.get("children") or []:
                find_insert(c, found)
        return found

    inserts = find_insert(ui2)
    assert inserts, "expected an INSERT action for tags"
    assert "INSERT INTO tags" in inserts[0]["sql"]
    assert "then_refresh" in inserts[0] and inserts[0]["then_refresh"]
    print("  [OK] helper_add_list_view → valid ui, ids unique, INSERT targets tags")

    # Second list view must not collide ids
    ui3 = helper_add_list_view(ui2, "tags", ["label"])
    ids3 = collect_ids(ui3)
    assert len(ids3) == len(set(ids3.keys()))
    assert validate_ui_spec_text(json.dumps(ui3)) == []
    print("  [OK] second list view avoids id collisions")

    # add_rule field + object forms
    schema3 = helper_add_rule(schema2, "items", "title", "unique")
    title_rules = None
    for o in schema3["objects"]:
        if o["name"] == "items":
            for f in o["fields"]:
                if f["name"] == "title":
                    title_rules = f["rules"]
    assert "unique" in title_rules, title_rules
    assert validate_schema_spec_text(json.dumps(schema3)) == []
    print("  [OK] helper_add_rule field-level → valid")

    schema4 = helper_add_rule(schema3, "items", None, "owner_only_update")
    for o in schema4["objects"]:
        if o["name"] == "items":
            assert "owner_only_update" in o.get("object_rules", [])
    assert validate_schema_spec_text(json.dumps(schema4)) == []
    print("  [OK] helper_add_rule object-level → valid")

    # Unknown object/field errors cleanly
    try:
        helper_add_rule(schema2, "nope", "x", "required")
        raise AssertionError("expected EditorError for unknown object")
    except EditorError as e:
        assert "unknown object" in str(e).lower(), e
        print(f"  [OK] unknown object: {e}")
    try:
        helper_add_rule(schema2, "items", "nope", "required")
        raise AssertionError("expected EditorError for unknown field")
    except EditorError as e:
        assert "unknown field" in str(e).lower(), e
        print(f"  [OK] unknown field: {e}")


def test_homed(ca_cert_path, admin_key, admin_cert):
    print("\n--- 6. Homed replica: save refused; load_spec_texts works ---")
    db = author_fixture(ca_cert_path, admin_key, admin_cert, dest=HOMED_PATH)

    # Plant sync_hub_cn via raw authoring (unsigned container_meta-style
    # would not work for manifest — use signed write BEFORE we treat as
    # homed, then reopen; actually setting sync_hub_cn makes further
    # local writes refuse. Set it last with a signed write while still
    # unhomed, then subsequent saves must refuse.
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    signed_exec(db, admin_key, admin_cert, q, ["sync_hub_cn", "hub.example"])
    assert db.get_manifest_item("sync_hub_cn") == "hub.example"

    texts = load_spec_texts(db)
    assert texts["ui_spec"] is not None
    assert texts["schema_spec"] is not None
    assert "items" in texts["schema_spec"] or "title" in texts["schema_spec"]
    print("  [OK] load_spec_texts works on homed replica")

    head = chain_head(db)
    try:
        save_ui_spec(
            db, admin_key, admin_cert,
            json.dumps(BASE_UI_SPEC, sort_keys=True),
        )
        raise AssertionError("save_ui_spec should refuse homed container")
    except EditorError as e:
        assert "hub" in str(e).lower() or "homed" in str(e).lower(), e
        assert "edit the hub" in str(e).lower() or HOMED_EDIT_REFUSAL in str(e) or (
            "hub-routed" in str(e).lower()
        ), e
        print(f"  [OK] save_ui_spec refused: {e}")
    assert chain_head(db) == head

    try:
        save_schema_spec(
            db, admin_key, admin_cert,
            json.dumps(BASE_SCHEMA_SPEC),
        )
        raise AssertionError("save_schema_spec should refuse homed container")
    except EditorError as e:
        assert "hub" in str(e).lower() or "homed" in str(e).lower(), e
        print(f"  [OK] save_schema_spec refused: {e}")
    assert chain_head(db) == head
    print("  [OK] chain head unchanged after homed refusals")

    db.close()


def main():
    cleanup()
    ca_cert_path, ca_cert, ca_key = ensure_ca()
    admin_cert, admin_key_pem = write_identity("editor_admin", ca_cert, ca_key)
    admin_key = load_key(admin_key_pem)

    print("--- 1. Fixture: declarative container as admin ---")
    db = author_fixture(ca_cert_path, admin_key, admin_cert)
    mode, _ = resolve_ui_mode(db)
    assert mode == "declarative"
    assert get_schema_spec(db) is not None
    texts = load_spec_texts(db)
    assert texts["ui_spec"] and texts["schema_spec"]
    print("  [OK] fixture authored (ui_spec + schema_spec, declarative mode)")

    test_validation(db, admin_key, admin_cert)
    test_save_ui_spec(db, admin_key, admin_cert)
    test_save_schema_spec(db, admin_key, admin_cert)
    test_helpers()
    test_homed(ca_cert_path, admin_key, admin_cert)

    db.close()
    print("\n=== ALL EDITOR TESTS PASSED ===")

    assert "toga" not in sys.modules, (
        "toga was imported — test_editor must stay headless (CI runs without toga)"
    )
    print("  [OK] toga not in sys.modules")


if __name__ == "__main__":
    main()
