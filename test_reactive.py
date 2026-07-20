"""Reactive-redraw plumbing test (headless).

Covers the two delivery paths used by the GUI:
  1. In-process: MSFStorage.on_commit fires after mutating signed transactions
     only — signed reads also commit (audit row) but must NOT notify, or two
     open documents would redraw each other forever.
  2. Cross-connection: the change marker used by MSF.check_external_change
     (PRAGMA data_version + high-water mark of non-SELECT ledger rows)
     distinguishes real mutations from audit-of-reads churn.
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
    payload_bytes = canonical_payload(
        query, params, next_seq, prev_hash, db.container_uid)
    key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())
    return key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())


def change_marker(db):
    """Mirror of MSF._current_change_marker (msf.py)."""
    dv = db.conn.execute("PRAGMA data_version").fetchone()[0]
    wid = db.conn.execute(
        "SELECT IFNULL(MAX(id), 0) FROM transactions WHERE query NOT LIKE 'SELECT%'"
    ).fetchone()[0]
    return (dv, wid)


def run():
    db_path = 'test_reactive.msf'
    if os.path.exists(db_path):
        os.remove(db_path)

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
    admin_cert, admin_key = generate_user_cert('reactive_admin', ca_cert_pem, ca_key_pem)

    writer = MSFStorage(db_path)      # e.g. the document window running the micro-app
    observer = MSFStorage(db_path)    # e.g. a second window / the GUI's view of a CLI-written file

    events = []
    writer.on_commit = lambda storage: events.append(storage.filename)

    def signed(db, query, params, bootstrap=False):
        sig = make_signed_payload(db, query, params, admin_key)
        if bootstrap:
            return db.bootstrap_admin(query, params, sig, admin_cert)
        return db.execute_signed(query, params, sig, admin_cert)

    print("--- 1. on_commit fires for mutating transactions ---")
    writer.conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)")
    writer.conn.commit()
    signed(writer, "INSERT INTO notes (body) VALUES (?)", ['hello'], bootstrap=True)
    assert events == [db_path], f"expected one commit event, got {events}"
    print("  [OK] mutating signed transaction notified")

    print("--- 2. on_commit does NOT fire for signed reads ---")
    signed(writer, "SELECT id, body FROM notes", []).fetchall()
    assert events == [db_path], f"signed read must not notify, got {events}"
    print("  [OK] signed read stayed silent (audit row committed, no notify)")

    print("--- 3. observer's marker detects the external write ---")
    base = change_marker(observer)
    signed(writer, "INSERT INTO notes (body) VALUES (?)", ['from other connection'])
    after = change_marker(observer)
    assert after[0] != base[0], "data_version should move on another connection's write"
    assert after[1] > base[1], "write high-water mark should advance"
    rows = observer.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    assert rows == 2, "observer should see committed data"
    print(f"  [OK] marker moved {base} -> {after}; observer sees {rows} rows -> would redraw")

    print("--- 4. external signed READ moves data_version but not the write mark ---")
    base = change_marker(observer)
    signed(writer, "SELECT COUNT(*) FROM notes", []).fetchall()
    after = change_marker(observer)
    assert after[0] != base[0], "read's audit row still changes the file"
    assert after[1] == base[1], "write high-water mark must not move on reads"
    print(f"  [OK] marker moved {base} -> {after}: baseline advances, NO redraw (loop prevented)")

    writer.close()
    observer.close()
    os.remove(db_path)
    print("\n==========================================")
    print("ALL REACTIVE-REDRAW TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
