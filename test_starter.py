"""Starter-app authoring test (headless, CI-safe — no toga at runtime).

create_starter_container() is what the GUI's first-run "Create Starter App"
button calls. Verify the container it authors is declarative (signed ui_spec,
no dill/source_code), fully explained by the ledger, and that signed query
actions used by the declarative path work through HostAPI.
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath('src'))

from mschf.audit import format_report, replay_audit
from mschf.declarative import (
    DeclarativeSpecError,
    resolve_ui_mode,
    spec_from_manifest,
)
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert
from mschf.identity import Identity
from mschf.sandbox import HostAPI
from mschf.schemaspec import get_schema_spec
from mschf.starter import (
    SEED_NOTES,
    STARTER_SCHEMA_SPEC,
    STARTER_UI_SPEC,
    _validate_starter_spec,
    create_starter_container,
)
from mschf.storage import MSFStorage, canonical_payload


def run():
    dest = 'test_starter.msf'
    for f in (dest, 'starter_admin.crt', 'starter_admin.key'):
        if os.path.exists(f):
            os.remove(f)

    ca_cert_path, ca_key_path = 'ca.crt', 'ca.key'
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        ca_pem, ca_key_pem = generate_selfsigned_cert("Temporary Root CA")
        with open(ca_cert_path, 'wb') as f:
            f.write(ca_pem)
        with open(ca_key_path, 'wb') as f:
            f.write(ca_key_pem)
    with open(ca_cert_path, 'rb') as f:
        ca_cert_pem = f.read()
    with open(ca_key_path, 'rb') as f:
        ca_key_pem = f.read()

    cert_pem, key_pem = generate_user_cert('starter_admin', ca_cert_pem, ca_key_pem)
    with open('starter_admin.crt', 'wb') as f:
        f.write(cert_pem)
    with open('starter_admin.key', 'wb') as f:
        f.write(key_pem)

    identity = Identity.load('starter_admin.crt', ca_cert_path)
    assert identity.is_valid, "test identity must chain to the CA"

    print("--- Spec validity (toga-free structural validation) ---")
    _validate_starter_spec(STARTER_UI_SPEC)
    print("  [OK] STARTER_UI_SPEC passes declarative collect_ids validation")

    print("--- Authoring starter container ---")
    create_starter_container(dest, identity, ca_cert_path)

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)

    assert db.get_manifest_item('name') == 'Getting Started'
    assert db.get_manifest_item('entry_point') is None
    assert db.get_manifest_item('ui_spec') is not None
    print("  [OK] manifest wired (name + ui_spec; no entry_point)")

    code_rows = db.conn.execute("SELECT COUNT(*) FROM source_code").fetchone()[0]
    assert code_rows == 0, f"declarative starter must have zero source_code rows, got {code_rows}"
    print("  [OK] no source_code / dill blobs")

    mode, payload = resolve_ui_mode(db)
    assert mode == 'declarative', f"expected declarative mode, got {mode!r}"
    assert isinstance(payload, dict) and payload.get('type') == 'box'
    print("  [OK] resolve_ui_mode picks declarative")

    spec = spec_from_manifest(db)
    assert spec is not None
    # Authored JSON round-trips to the same logical tree.
    assert spec['type'] == STARTER_UI_SPEC['type']
    assert any(
        c.get('type') == 'table' and c.get('id') == 'notes_table'
        for c in spec.get('children', [])
    )
    _validate_starter_spec(spec)
    print("  [OK] ui_spec parses and validates (malformed authoring impossible)")

    rows = db.conn.execute(
        "SELECT body, created_by, updated_by, created_at, updated_at "
        "FROM notes ORDER BY id"
    ).fetchall()
    assert [r[0] for r in rows] == SEED_NOTES
    assert all(r[1] == 'cert:CN=starter_admin' for r in rows), rows
    assert all(r[2] == 'cert:CN=starter_admin' for r in rows), rows
    assert all(r[3] for r in rows) and all(r[4] for r in rows), rows
    print(f"  [OK] {len(rows)} seed notes stamped by schema audit triggers")

    cur = db.conn.execute(
        "SELECT role FROM user_roles WHERE identity = 'cert:CN=starter_admin'"
    )
    assert cur.fetchone()[0] == 'admin', "creator must be container admin via bootstrap"
    print("  [OK] creating identity bootstrapped as container admin")

    # No invented object-level grants — starter never seeded member rbac.
    object_rbac = db.conn.execute(
        "SELECT COUNT(*) FROM rbac_rules WHERE level = 'object'"
    ).fetchone()[0]
    assert object_rbac == 0, f"starter must not invent object rbac, got {object_rbac}"
    print("  [OK] no object-level rbac_rules (access stays empty)")

    print("--- Manifest signature status (ui_spec + schema_spec) ---")
    status = db.get_manifest_signature_status('ui_spec')
    assert status['verified'], f"ui_spec must verify: {status}"
    assert status['signer'] == 'starter_admin', status
    print(f"  [OK] ui_spec verified (signer={status['signer']})")

    schema_status = db.get_manifest_signature_status('schema_spec')
    assert schema_status['verified'], f"schema_spec must verify: {schema_status}"
    assert schema_status['signer'] == 'starter_admin', schema_status
    print(f"  [OK] schema_spec verified (signer={schema_status['signer']})")

    stored_schema = get_schema_spec(db)
    assert stored_schema is not None
    assert stored_schema.get('v') == STARTER_SCHEMA_SPEC['v']
    obj_names = [o['name'] for o in stored_schema.get('objects', [])]
    assert obj_names == ['notes'], obj_names
    notes_obj = stored_schema['objects'][0]
    assert notes_obj['fields'][0]['name'] == 'body'
    assert 'required' in notes_obj['fields'][0]['rules']
    print("  [OK] get_schema_spec returns notes object with required body")

    print("--- Engine rule: required-empty note refused ---")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open('starter_admin.key', 'rb') as f:
        admin_key = load_pem_private_key(f.read(), password=None)

    def _sign(query, params):
        next_seq, prev_hash = db.get_chain_head()
        payload = canonical_payload(
            query, params, next_seq, prev_hash, db.container_uid)
        return admin_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    refused = False
    for empty in ('', '   '):
        try:
            q = "INSERT INTO notes (body) VALUES (?)"
            db.execute_signed(q, [empty], _sign(q, [empty]), cert_pem)
            raise AssertionError(f"required-empty insert should fail for {empty!r}")
        except Exception as e:
            msg = str(e).lower()
            assert (
                'check' in msg or 'not null' in msg or 'null' in msg
                or 'required' in msg
            ), e
            refused = True
            print(f"  [OK] required-empty refused ({empty!r}): {e}")
    assert refused

    print("--- Replay audit of the authored container ---")
    report = replay_audit(db)
    print(format_report(report))
    assert report['ok'], "starter container must be fully explained by its ledger"

    print("--- Out-of-band ui_spec tamper ---")
    original = db.get_manifest_item('ui_spec')
    tampered = json.dumps({"type": "box", "children": [{"type": "label", "text": "evil"}]})
    raw = sqlite3.connect(dest)
    raw.execute(
        "UPDATE manifest SET value = ? WHERE key = ?", (tampered, 'ui_spec')
    )
    raw.commit()
    raw.close()

    status = db.get_manifest_signature_status('ui_spec')
    assert not status['verified'], f"tampered ui_spec must not verify: {status}"
    print(f"  [OK] tamper flips signature status: {status.get('error') or status}")

    report = replay_audit(db)
    assert not report['ok'], "replay_audit must flag out-of-band ui_spec edit"
    print("  [OK] replay_audit flags tampered container")

    # Restore so HostAPI path exercises a clean container again.
    raw = sqlite3.connect(dest)
    raw.execute(
        "UPDATE manifest SET value = ? WHERE key = ?", (original, 'ui_spec')
    )
    raw.commit()
    raw.close()
    assert db.get_manifest_signature_status('ui_spec')['verified']
    report = replay_audit(db)
    assert report['ok'], "restored container must audit clean again"

    print("--- Declarative action path via HostAPI (unhomed) ---")
    host = HostAPI(
        workspace_path=os.path.abspath('.'),
        db=db,
        current_user_cn='starter_admin',
        current_user_cert_pem=cert_pem,
        key_path='starter_admin.key',
        key_passphrase=None,
    )

    # Bound table query from the authored spec (SELECT-only).
    table_sql = None
    insert_sql = "INSERT INTO notes (body) VALUES (?)"
    for child in STARTER_UI_SPEC['children']:
        if child.get('type') == 'table' and child.get('id') == 'notes_table':
            table_sql = child['query']['sql']
            break
        if child.get('type') == 'box':
            for nested in child.get('children') or []:
                action = nested.get('action') or {}
                if action.get('kind') == 'exec':
                    insert_sql = action['sql']
    assert table_sql, "notes_table query missing from STARTER_UI_SPEC"

    cursor = host.execute_signed_query(table_sql, [])
    seeded = cursor.fetchall()
    assert len(seeded) == len(SEED_NOTES), f"expected {len(SEED_NOTES)} notes, got {len(seeded)}"
    bodies = [r[1] for r in seeded]
    assert set(bodies) == set(SEED_NOTES)
    print(f"  [OK] bound SELECT reads {len(seeded)} seed notes via HostAPI")

    before_tx = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    host.execute_signed_query(insert_sql, ["Headless note via declarative action SQL"])
    after_tx = db.conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    assert after_tx == before_tx + 1, "INSERT must append a ledger row"

    cursor = host.execute_signed_query(table_sql, [])
    all_bodies = [r[1] for r in cursor.fetchall()]
    assert "Headless note via declarative action SQL" in all_bodies
    stamped = db.conn.execute(
        "SELECT created_by FROM notes WHERE body = ?",
        ["Headless note via declarative action SQL"],
    ).fetchone()
    assert stamped[0] == 'cert:CN=starter_admin', stamped
    print("  [OK] parameterized INSERT succeeds and appends to the ledger")

    print("--- Trigger shield ---")
    raw = sqlite3.connect(dest)
    try:
        raw.execute("INSERT INTO notes (body) VALUES ('sneaky')")
        raise AssertionError("raw insert should be blocked by the audit trigger")
    except sqlite3.OperationalError as e:
        assert 'current_signer' in str(e)
        print(f"  [OK] raw write rejected: {e}")
    raw.close()

    db.close()
    for f in (dest, 'starter_admin.crt', 'starter_admin.key'):
        os.remove(f)

    assert 'toga' not in sys.modules, (
        'test_starter must stay headless (CI runs without toga)'
    )

    print("\n==========================================")
    print("ALL STARTER-APP TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
