"""Reactive-redraw plumbing test (headless).

Covers the two delivery paths used by the GUI:
  1. In-process: MSFStorage.on_commit fires after mutating signed transactions
     only — signed reads also commit (audit row) but must NOT notify, or two
     open documents would redraw each other forever.
  2. Cross-connection: the change marker used by MSF.check_external_change
     (PRAGMA data_version + high-water mark of non-SELECT ledger rows)
     distinguishes real mutations from audit-of-reads churn.
  3. Sync-status line staleness: connectivity / outbox-pending can change with
     no data_version bump; record_sync_render_facts + is_sync_render_stale
     (and MSF.sync_render_stale wrappers) detect that for the ~2s poll.
"""
import os
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath('src'))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert, default_backend, serialization
from mschf.hub import MSFHub
from mschf.syncstate import (
    is_sync_render_stale,
    record_sync_render_facts,
)
from mschf.storage import MSFStorage, canonical_payload
from mschf import sync as msync

# Regression gate: CI runs this suite without toga installed.
assert 'toga' not in sys.modules, 'test_reactive must stay headless (CI runs without toga)'


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


def _load_key(pem_bytes):
    return serialization.load_pem_private_key(
        pem_bytes, password=None, backend=default_backend()
    )


def _signed_exec(db, cert_pem, key_pem, query, params, bootstrap=False):
    sig = make_signed_payload(db, query, params, key_pem)
    if bootstrap:
        return db.bootstrap_admin(query, params, sig, cert_pem)
    return db.execute_signed(query, params, sig, cert_pem)


def _headless_sync_render_stale(db, rendered, thread):
    """Mirror of MSF.sync_render_stale without instantiating a Toga Document."""
    try:
        if not db:
            return False
        status = msync.sync_status(db)  # no probe
        connected = False
        if thread is not None:
            connected = bool(getattr(thread, 'connected', False))
        return is_sync_render_stale(rendered, status, connected)
    except Exception:
        return False


def _headless_record_redraw(db, thread):
    """Mirror of the recording side of MSF._sync_status_text during redraw."""
    status = msync.sync_status(db)  # no probe — same dict drives the line
    connected = bool(getattr(thread, 'connected', False)) if thread is not None else False
    return record_sync_render_facts(status, connected)


def run_change_marker_tests():
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


def run_sync_render_stale_tests():
    """Homed-container + threaded hub: connectivity/outbox staleness without Toga."""
    artifacts = []
    tmp_dirs = []
    hub = None
    hub_thread = None

    def track(path):
        artifacts.append(path)
        return path

    try:
        ca_cert_path, ca_key_path = 'ca.crt', 'ca.key'
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            ca_pem, ca_key_pem = generate_selfsigned_cert('Temporary Root CA')
            with open(ca_cert_path, 'wb') as f:
                f.write(ca_pem)
            with open(ca_key_path, 'wb') as f:
                f.write(ca_key_pem)
        with open(ca_cert_path, 'rb') as f:
            ca_cert_pem = f.read()
        with open(ca_key_path, 'rb') as f:
            ca_key_pem = f.read()

        hub_cert, hub_key = generate_user_cert('hub_svc', ca_cert_pem, ca_key_pem)
        admin_cert, admin_key = generate_user_cert('reactive_sync_admin', ca_cert_pem, ca_key_pem)
        hub_cert_path = track('reactive_hub_svc.crt')
        hub_key_path = track('reactive_hub_svc.key')
        with open(hub_cert_path, 'wb') as f:
            f.write(hub_cert)
        with open(hub_key_path, 'wb') as f:
            f.write(hub_key)

        # Author a minimal homed container (same shape as test_hub_sync).
        hub_dir = tempfile.mkdtemp(prefix='mschf_reactive_hub_')
        tmp_dirs.append(hub_dir)
        container_id = 'reactive_notes'
        hub_msf = os.path.join(hub_dir, f'{container_id}.msf')

        db = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        db.conn.execute(
            "CREATE TABLE notes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)"
        )
        db.conn.commit()
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'],
            bootstrap=True,
        )
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_cn', 'hub_svc'],
        )
        db.close()

        hub = MSFHub(
            hub_dir, hub_cert_path, hub_key_path,
            host='127.0.0.1', port=0, ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url
        hub_cn = 'hub_svc'
        admin_private = _load_key(admin_key)

        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_url', hub_url],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )

        spoke_dir = tempfile.mkdtemp(prefix='mschf_reactive_spoke_')
        tmp_dirs.append(spoke_dir)
        spoke_path = os.path.join(spoke_dir, f'{container_id}.msf')
        spoke = msync.bootstrap(
            hub_url, container_id, spoke_path,
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert msync.homing(spoke)[1] == 'hub_svc'

        # Fake subscriber-thread namespace (document would set thread.connected).
        thr = SimpleNamespace(connected=False)

        print("--- 5. connected flag flip → sync_render_stale ---")
        rendered = _headless_record_redraw(spoke, thr)
        assert rendered is not None and rendered['connected'] is False
        assert _headless_sync_render_stale(spoke, rendered, thr) is False
        thr.connected = True  # subscriber recovered; no data_version change
        assert _headless_sync_render_stale(spoke, rendered, thr) is True, (
            'live flag flip must mark status line stale'
        )
        rendered = _headless_record_redraw(spoke, thr)
        assert rendered['connected'] is True
        assert _headless_sync_render_stale(spoke, rendered, thr) is False, (
            'after re-record, matching live flag is not stale'
        )
        print("  [OK] offline→live recorded; re-record clears staleness")

        print("--- 6. unhomed document → always False ---")
        unhomed_dir = tempfile.mkdtemp(prefix='mschf_reactive_unhomed_')
        tmp_dirs.append(unhomed_dir)
        unhomed_path = os.path.join(unhomed_dir, 'plain.msf')
        unhomed = MSFStorage(unhomed_path, ca_cert_path=ca_cert_path)
        st = msync.sync_status(unhomed)
        assert st['homed'] is False
        # Even with a fake "rendered offline" snapshot and a live thread flag.
        fake_rendered = {'connected': False, 'outbox_pending': 0}
        thr_live = SimpleNamespace(connected=True)
        assert is_sync_render_stale(fake_rendered, st, True) is False
        assert _headless_sync_render_stale(unhomed, fake_rendered, thr_live) is False
        assert record_sync_render_facts(st, True) is None
        unhomed.close()
        print("  [OK] unhomed never reports stale")

        print("--- 7. outbox-pending delta → sync_render_stale ---")
        thr.connected = True
        rendered = _headless_record_redraw(spoke, thr)
        assert rendered['outbox_pending'] == 0
        assert _headless_sync_render_stale(spoke, rendered, thr) is False
        # Offline queue insert is unsigned DDL on this connection; pending count
        # changes without a GUI data_version path for "another connection's"
        # outbox, and the status line must still refresh.
        msync.queue_intent(
            spoke, 'reactive_sync_admin',
            "INSERT INTO notes (body) VALUES (?)",
            ['queued-while-offline'],
        )
        st = msync.sync_status(spoke)
        assert st['outbox_pending'] >= 1
        assert _headless_sync_render_stale(spoke, rendered, thr) is True, (
            'pending outbox growth must mark status line stale'
        )
        rendered = _headless_record_redraw(spoke, thr)
        assert rendered['outbox_pending'] >= 1
        assert _headless_sync_render_stale(spoke, rendered, thr) is False
        print(f"  [OK] outbox_pending delta detected; re-record clears (pending={rendered['outbox_pending']})")

        print("--- 8. never-raises guard (db=None / missing thread) ---")
        assert _headless_sync_render_stale(None, rendered, thr) is False
        assert is_sync_render_stale(None, None, True) is False
        # Missing thread: connected treated as False; if rendered was live, stale.
        thr.connected = True
        rendered = _headless_record_redraw(spoke, thr)
        assert _headless_sync_render_stale(spoke, rendered, None) is True  # live→False
        assert _headless_sync_render_stale(
            spoke,
            {'connected': False, 'outbox_pending': rendered['outbox_pending']},
            None,
        ) is False
        # Garbage inputs must not raise.
        assert is_sync_render_stale('bad', 123, None) is False
        assert is_sync_render_stale(
            {'connected': True},
            {'homed': True, 'outbox_pending': 'x'},
            True,
        ) is False
        print("  [OK] db=None / missing thread / garbage → False, no exception")

        spoke.close()
    finally:
        if hub is not None:
            try:
                hub.shutdown()
            except Exception:
                pass
            try:
                hub.server_close()
            except Exception:
                pass
        if hub_thread is not None:
            hub_thread.join(timeout=2)
        for p in artifacts:
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except Exception:
                pass
        for d in tmp_dirs:
            try:
                import shutil
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass


def run():
    run_change_marker_tests()
    run_sync_render_stale_tests()
    print("\n==========================================")
    print("ALL REACTIVE-REDRAW TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
