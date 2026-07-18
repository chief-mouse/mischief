"""Starter-app authoring test (headless, CI-safe — no toga at runtime).

create_starter_container() is what the GUI's first-run "Create Starter App"
button calls. Verify the container it authors is a first-class citizen:
manifest wired, code blob signed and verified, ledger fully explains the
data (replay audit passes), attribution stamped by trigger from the signing
identity, and raw out-of-band writes blocked by the trigger shield.
"""
import sys
import os
sys.path.insert(0, os.path.abspath('src'))

import sqlite3
from mschf.storage import MSFStorage
from mschf.identity import Identity
from mschf.starter import create_starter_container, SEED_NOTES
from mschf.audit import replay_audit, format_report
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert


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

    print("--- Authoring starter container ---")
    create_starter_container(dest, identity, ca_cert_path)

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)

    assert db.get_manifest_item('entry_point') == 'main_app'
    assert db.get_manifest_item('name') == 'Getting Started'
    print("  [OK] manifest wired")

    status = db.get_code_signature_status('main_app')
    assert status['verified'], f"code signature not verified: {status['error']}"
    assert status['signer'] == 'starter_admin'
    print(f"  [OK] code blob signed and verified (signer={status['signer']})")

    code_func = db.get_code('main_app')
    assert callable(code_func), "starter code must unpickle to a callable"
    print("  [OK] code blob unpickles to a callable (by-value, no module dependency)")

    rows = db.conn.execute("SELECT body, created_by FROM notes ORDER BY id").fetchall()
    assert [r[0] for r in rows] == SEED_NOTES
    assert all(r[1] == 'cert:CN=starter_admin' for r in rows), rows
    print(f"  [OK] {len(rows)} seed notes stamped by trigger from the signing identity")

    cur = db.conn.execute("SELECT role FROM user_roles WHERE identity = 'cert:CN=starter_admin'")
    assert cur.fetchone()[0] == 'admin', "creator must be container admin via bootstrap"
    print("  [OK] creating identity bootstrapped as container admin")

    print("--- Replay audit of the authored container ---")
    report = replay_audit(db)
    print(format_report(report))
    assert report['ok'], "starter container must be fully explained by its ledger"

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
    print("\n==========================================")
    print("ALL STARTER-APP TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
