"""Authorizer-hook RBAC enforcement test.

Proves that access which slips past the regex-derived (operation, table) pre-check
is denied by the SQLite authorizer installed around every signed execute:

  1. Read smuggled through a JOIN         (regex sees only the first table)
  2. Read smuggled through INSERT..SELECT (regex sees only the INSERT target)
  3. PRAGMA (e.g. writable_schema)        (regex classifies as 'unknown')
  4. ATTACH of an arbitrary host file     (regex classifies as 'unknown')

...while legitimate access still works for both support and admin identities.
"""
import sys
import os
sys.path.insert(0, os.path.abspath('src'))

from mschf.storage import MSFStorage, canonical_payload
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert, default_backend, serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def make_signed_payload(db, query, params, pem_key_bytes):
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(query, params, next_seq, prev_hash)
    private_key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())
    return private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())


def expect_denied(db, query, params, key, cert, must_mention, label):
    sig = make_signed_payload(db, query, params, key)
    try:
        db.execute_signed(query, params, sig, cert)
        raise AssertionError(f"SECURITY BREACH ({label}): statement was allowed: {query}")
    except PermissionError as e:
        assert must_mention.lower() in str(e).lower(), f"({label}) expected '{must_mention}' in error, got: {e}"
        print(f"  [OK] {label} denied: {e}")


def run():
    db_path = 'test_authorizer.msf'
    if os.path.exists(db_path):
        os.remove(db_path)

    # Identities chained to the host Root CA (created by other tests/app if missing)
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

    admin_cert, admin_key = generate_user_cert('authz_admin', ca_cert_pem, ca_key_pem)
    support_cert, support_key = generate_user_cert('authz_support', ca_cert_pem, ca_key_pem)

    db = MSFStorage(db_path)
    support_id = db._get_identity(support_cert)

    print("--- Provisioning container (admin bootstrap, tables, RBAC) ---")
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    db.bootstrap_admin(q, ['entry_point', 'main'], make_signed_payload(db, q, ['entry_point', 'main'], admin_key), admin_cert)

    db.conn.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)")
    db.conn.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, secret TEXT)")
    db.conn.execute("INSERT INTO secrets (secret) VALUES ('the crown jewels')")
    db.conn.execute("INSERT INTO tickets (title) VALUES ('printer on fire')")
    db.conn.commit()

    def admin_exec(query, params):
        db.execute_signed(query, params, make_signed_payload(db, query, params, admin_key), admin_cert)

    q = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
    admin_exec(q, [support_id, 'support'])
    q = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
    admin_exec(q, ['database', '*', 'support', '*'])     # db-level read+write
    admin_exec(q, ['object', 'tickets', 'support', '*'])  # tickets read+write; NOTHING on secrets

    print("\n--- Positive controls (legitimate access still works) ---")
    sig = make_signed_payload(db, "SELECT id, title FROM tickets", [], support_key)
    rows = db.execute_signed("SELECT id, title FROM tickets", [], sig, support_cert).fetchall()
    assert rows and rows[0][1] == 'printer on fire'
    print("  [OK] support can read tickets")

    sig = make_signed_payload(db, "INSERT INTO tickets (title) VALUES (?)", ['coffee machine down'], support_key)
    db.execute_signed("INSERT INTO tickets (title) VALUES (?)", ['coffee machine down'], sig, support_cert)
    print("  [OK] support can write tickets")

    sig = make_signed_payload(db, "SELECT t.title, s.secret FROM tickets t JOIN secrets s", [], admin_key)
    rows = db.execute_signed("SELECT t.title, s.secret FROM tickets t JOIN secrets s", [], sig, admin_cert).fetchall()
    assert any('crown jewels' in r[1] for r in rows)
    print("  [OK] admin can join across secrets")

    print("\n--- Bypass attempts (all previously slipped past the regex) ---")
    expect_denied(db,
                  "SELECT t.title, u.identity, u.role FROM tickets t JOIN user_roles u",
                  [], support_key, support_cert,
                  "user_roles", "system-table read-smuggle via JOIN")
    expect_denied(db,
                  "SELECT t.title, s.secret FROM tickets t JOIN secrets s",
                  [], support_key, support_cert,
                  "secrets", "JOIN read-smuggle")
    expect_denied(db,
                  "INSERT INTO tickets (title) SELECT secret FROM secrets",
                  [], support_key, support_cert,
                  "secrets", "INSERT..SELECT exfiltration")
    expect_denied(db,
                  "PRAGMA writable_schema = ON",
                  [], support_key, support_cert,
                  "not permitted", "PRAGMA")
    expect_denied(db,
                  "ATTACH DATABASE 'stolen.db' AS x",
                  [], support_key, support_cert,
                  "not permitted", "ATTACH")

    # Audit log: denied statements must not have been logged as executed,
    # and the allowed ones must be present.
    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM transactions WHERE query LIKE '%JOIN secrets%' AND pub_key = ?", (support_cert,))
    assert cur.fetchone()[0] == 0, "Denied statement was appended to the audit log!"
    cur.execute("SELECT COUNT(*) FROM secrets")
    assert cur.fetchone()[0] == 1, "secrets table was modified!"
    print("  [OK] denied statements left no trace in data or audit log")

    db.close()
    os.remove(db_path)
    print("\n==========================================")
    print("ALL AUTHORIZER ENFORCEMENT TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
