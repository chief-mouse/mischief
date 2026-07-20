import sys
import os
sys.path.insert(0, os.path.abspath('src'))

from mschf.storage import MSFStorage, canonical_payload
from mschf.gen_cert import generate_selfsigned_cert, default_backend, serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Helper to sign payloads against the container's current chain head.
def make_signed_payload(db, query, params, pem_key_bytes):
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(query, params, next_seq, prev_hash)
    private_key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())
    return private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())

def run_rbac_test():
    db_path = 'test_rbac.msf'
    if os.path.exists(db_path):
        os.remove(db_path)

    print("--- Generating Cryptographic Identities ---")
    # Load Root CA
    ca_cert_path = 'ca.crt'
    ca_key_path = 'ca.key'
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        # Generate temporary root CA if not present
        pem_ca_cert, pem_ca_key = generate_selfsigned_cert("Temporary Root CA")
        with open(ca_cert_path, 'wb') as f:
            f.write(pem_ca_cert)
        with open(ca_key_path, 'wb') as f:
            f.write(pem_ca_key)
            
    with open(ca_cert_path, 'rb') as f:
        ca_cert_pem = f.read()
    with open(ca_key_path, 'rb') as f:
        ca_key_pem = f.read()
        
    from mschf.gen_cert import generate_user_cert
    admin_cert, admin_key = generate_user_cert('system_admin', ca_cert_pem, ca_key_pem)
    support_cert, support_key = generate_user_cert('support_staff', ca_cert_pem, ca_key_pem)
    hacker_cert, hacker_key = generate_selfsigned_cert('malicious_hacker')

    print("\n--- Initializing MSF Storage ---")
    db = MSFStorage(db_path)

    admin_id = db._get_identity(admin_cert)
    support_id = db._get_identity(support_cert)
    hacker_id = db._get_identity(hacker_cert)

    print(f"Admin Identity:   {admin_id}")
    print(f"Support Identity: {support_id}")
    print(f"Hacker Identity:  {hacker_id}")

    print("\n--- Step 1: Bootstrapping Root Admin ---")
    sig = make_signed_payload(db, "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", ['entry_point', 'main'], admin_key)
    db.bootstrap_admin("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", ['entry_point', 'main'], sig, admin_cert)

    cursor = db.conn.cursor()
    cursor.execute("SELECT role FROM user_roles WHERE identity = ?", (admin_id,))
    assert cursor.fetchone()[0] == 'admin', "Auto-bootstrapping failed!"
    print("✓ Root Admin auto-bootstrapped successfully!")

    print("\n--- Step 2: Provisioning Guest / Support User ---")
    sig = make_signed_payload(db, "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)", [support_id, 'support'], admin_key)
    db.assign_user_role(support_id, 'support', sig, admin_cert)
    
    cursor.execute("SELECT role FROM user_roles WHERE identity = ?", (support_id,))
    assert cursor.fetchone()[0] == 'support'
    print("✓ Assigned 'support' role to support_staff")

    print("\n--- Step 3: Setting Up RBAC Rules (Admin Only) ---")
    # Grant 'support' database-level full permission (both read and write)
    sig = make_signed_payload(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['database', '*', 'support', '*'], admin_key)
    db.add_rbac_rule('database', '*', 'support', '*', sig, admin_cert)

    # Let 'support' read 'customer_dashboard'
    sig = make_signed_payload(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['view', 'customer_dashboard', 'support', 'read'], admin_key)
    db.add_rbac_rule('view', 'customer_dashboard', 'support', 'read', sig, admin_cert)

    # Create the dynamic 'tickets' table
    sig = make_signed_payload(db, "CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)", [], admin_key)
    db.create_object_table('tickets', {'title': 'TEXT'}, sig, admin_cert)

    # Allow 'support' role to read (SELECT) from 'tickets' table
    sig = make_signed_payload(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['object', 'tickets', 'support', 'read'], admin_key)
    db.add_rbac_rule('object', 'tickets', 'support', 'read', sig, admin_cert)

    print("✓ Created tables and configured RBAC rules successfully.")

    print("\n--- Step 4: Verification of View Permissions ---")
    assert db.check_view_permission('customer_dashboard', support_cert) is True, "Support should have access to customer_dashboard"
    assert db.check_view_permission('admin_panel', support_cert) is False, "Support should NOT have access to admin_panel"
    assert db.check_view_permission('customer_dashboard', hacker_cert) is False, "Hacker should NOT have access to customer_dashboard"
    
    assert db.check_view_permission('admin_panel', admin_cert) is True, "Admin should bypass and have access to admin_panel"
    print("✓ View level permissions verified!")

    print("\n--- Step 5: Verification of Field-Level Permissions ---")
    sig = make_signed_payload(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['field', 'tickets.title', 'support', 'read'], admin_key)
    db.add_rbac_rule('field', 'tickets.title', 'support', 'read', sig, admin_cert)

    assert db.check_field_permission('tickets', 'title', 'read', support_cert) is True, "Support should read ticket title"
    assert db.check_field_permission('tickets', 'customer_ssn', 'read', support_cert) is False, "Support should NOT read customer ssn"
    assert db.check_field_permission('tickets', 'customer_ssn', 'read', admin_cert) is True, "Admin should bypass and read customer ssn"
    print("✓ Field level permissions verified!")

    print("\n--- Step 6: Verification of Object-Level Query Enforcement ---")
    assert db.check_permission(support_id, 'object', 'tickets', 'read') is True, "Support should have read permission on tickets"

    # Support attempts to insert into tickets - Rejected by Object-level RBAC (since they have 'database:write' but no 'object:tickets:write')!
    print("Checking unauthorized object-level write rejection...")
    sig_fail = make_signed_payload(db, "INSERT INTO tickets (title) VALUES (?)", ['Broken pipe'], support_key)
    try:
        db.execute_signed("INSERT INTO tickets (title) VALUES (?)", ['Broken pipe'], sig_fail, support_cert)
        raise AssertionError("Security breach: Support user inserted into tickets without permission!")
    except PermissionError as e:
        print(f"✓ Rejection verified: {e}")
        assert "table 'tickets'" in str(e), f"Expected table 'tickets' error, got: {e}"

    # Hacker attempts any signed transaction - Rejected at Database level (since they have no permissions)!
    print("Checking hacker/unregistered transaction rejection...")
    sig_hack = make_signed_payload(db, "INSERT INTO tickets (title) VALUES (?)", ['Hacked'], hacker_key)
    try:
        db.execute_signed("INSERT INTO tickets (title) VALUES (?)", ['Hacked'], sig_hack, hacker_cert)
        raise AssertionError("Security breach: Hacker signed transaction allowed!")
    except PermissionError as e:
        print(f"✓ Rejection verified: {e}")
        assert "Chain Verification Failed" in str(e), f"Expected chain verification error, got: {e}"

    # Hacker attempts a read query - Rejected with Chain Verification Failed
    print("Checking hacker read query rejection...")
    sig_hack_read = make_signed_payload(db, "SELECT * FROM tickets", [], hacker_key)
    try:
        db.execute_signed("SELECT * FROM tickets", [], sig_hack_read, hacker_cert)
        raise AssertionError("Security breach: Hacker read allowed!")
    except PermissionError as e:
        print(f"✓ Rejection verified: {e}")
        assert "Chain Verification Failed" in str(e), f"Expected chain verification error, got: {e}"

    # Admin attempts same insertion - Allowed!
    print("Checking admin authorized write...")
    sig_ok = make_signed_payload(db, "INSERT INTO tickets (title) VALUES (?)", ['Urgent issue'], admin_key)
    db.execute_signed("INSERT INTO tickets (title) VALUES (?)", ['Urgent issue'], sig_ok, admin_cert)
    print("✓ Authorized write verified!")

    # Verify data in database
    cursor.execute("SELECT title FROM tickets")
    rows = cursor.fetchall()
    assert len(rows) == 1 and rows[0][0] == 'Urgent issue', f"Expected ['Urgent issue'], got {rows}"
    print("✓ Schema integrity and transaction verification matches exact expected output!")

    db.close()
    if os.path.exists(db_path):
        os.remove(db_path)
    print("\n==========================================")
    print("🔥 ALL RBAC INTEGRATION TESTS PASSED! 🔥")
    print("==========================================")

if __name__ == '__main__':
    run_rbac_test()
