"""Container identity binding tests (payload format v3).

Proves that every newly signed ledger row embeds the container's unique
``container_uid``, so a captured genesis-starting chain cannot be replayed
into another empty container. Also covers mint-on-open, whole-file replica
legitimacy, mixed v2→v3 upgrade, format-downgrade detection, and sync
write-through with uid mismatch refusal.

Run: python test_container_binding.py
"""
import json
import os
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.abspath('src'))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from mschf.audit import replay_audit, format_report
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert
from mschf.hub import MSFHub
from mschf.storage import (
    MSFStorage,
    PAYLOAD_FMT_V3,
    canonical_payload,
    ledger_row_hash,
)
from mschf import sync as msync


def _load_key(pem_bytes):
    return serialization.load_pem_private_key(
        pem_bytes, password=None, backend=default_backend()
    )


def make_signed_payload(db, query, params, pem_key_bytes, container_uid=None):
    """Sign against db's chain head. Defaults to v3 (with container_uid)."""
    key = _load_key(pem_key_bytes)
    next_seq, prev_hash = db.get_chain_head()
    uid = db.container_uid if container_uid is None else container_uid
    payload = canonical_payload(query, params, next_seq, prev_hash, uid)
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def signed_exec(db, cert_pem, key_pem, query, params, bootstrap=False):
    sig = make_signed_payload(db, query, params, key_pem)
    if bootstrap:
        return db.bootstrap_admin(query, params, sig, cert_pem)
    return db.execute_signed(query, params, sig, cert_pem)


def ensure_host_ca():
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
    return ca_cert_path, ca_cert_pem, ca_key_pem


def run():
    artifacts = []
    tmp_dirs = []
    hub = None

    def track(path):
        artifacts.append(path)
        return path

    try:
        print('--- Host CA ---')
        ca_cert_path, ca_cert_pem, ca_key_pem = ensure_host_ca()
        print('  [OK] host CA ready')

        admin_cert, admin_key = generate_user_cert('bind_admin', ca_cert_pem, ca_key_pem)
        nonadmin_cert, nonadmin_key = generate_user_cert(
            'bind_user', ca_cert_pem, ca_key_pem)

        # ==================================================================
        # 1. Fresh container mints a uid
        # ==================================================================
        print('\n=== 1. Fresh container mints a uid ===')
        path_a = track('test_container_binding_a.msf')
        if os.path.exists(path_a):
            os.remove(path_a)

        db_a = MSFStorage(path_a, ca_cert_path=ca_cert_path)
        uid_a = db_a.container_uid
        assert uid_a is not None, 'container_uid must be set after open'
        assert len(uid_a) == 32, f'expected 32 hex chars, got {len(uid_a)}: {uid_a!r}'
        assert all(c in '0123456789abcdef' for c in uid_a), f'not hex: {uid_a!r}'
        print(f'  [OK] minted container_uid={uid_a}')

        db_a.close()
        db_a = MSFStorage(path_a, ca_cert_path=ca_cert_path)
        assert db_a.container_uid == uid_a, 'reopen must return the same uid'
        print('  [OK] reopen returns the same uid')

        # container_meta is raw-sqlite visible.
        raw_uid = db_a.conn.execute(
            "SELECT value FROM container_meta WHERE key = 'container_uid'"
        ).fetchone()[0]
        assert raw_uid == uid_a
        print('  [OK] container_meta visible via raw sqlite')

        # Bootstrap admin, grant non-admin a writer role, then deny non-admin
        # signed write to container_meta (system table, admin-only).
        signed_exec(
            db_a, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'],
            bootstrap=True,
        )
        for level, target, role, perm in [
            ('database', '*', 'writer', 'read'),
            ('database', '*', 'writer', 'write'),
        ]:
            signed_exec(
                db_a, admin_cert, admin_key,
                "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
                [level, target, role, perm],
            )
        signed_exec(
            db_a, admin_cert, admin_key,
            "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
            ['cert:CN=bind_user', 'writer'],
        )

        try:
            signed_exec(
                db_a, nonadmin_cert, nonadmin_key,
                "INSERT OR REPLACE INTO container_meta (key, value) VALUES (?, ?)",
                ['container_uid', 'deadbeef' * 4],
            )
            raise AssertionError('non-admin write to container_meta should be denied')
        except PermissionError as e:
            assert 'not permitted' in str(e).lower() or 'denied' in str(e).lower() \
                or 'admin' in str(e).lower() or 'system table' in str(e).lower(), str(e)
            print(f'  [OK] non-admin signed write to container_meta denied: {e}')

        # Author a few more writes so A has a multi-row v3 ledger.
        db_a.conn.execute(
            "CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        )
        db_a.conn.commit()
        signed_exec(
            db_a, admin_cert, admin_key,
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            ['object', 'items', 'writer', 'write'],
        )
        signed_exec(
            db_a, admin_cert, admin_key,
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            ['object', 'items', 'writer', 'read'],
        )
        for name in ('alpha', 'beta', 'gamma'):
            signed_exec(
                db_a, admin_cert, admin_key,
                "INSERT INTO items (name) VALUES (?)", [name],
            )

        # All new rows should be payload_fmt=3.
        fmts = [r[0] for r in db_a.conn.execute(
            "SELECT payload_fmt FROM transactions WHERE seq IS NOT NULL ORDER BY seq"
        )]
        assert all(f == PAYLOAD_FMT_V3 for f in fmts), f'expected all v3, got {fmts}'
        print(f'  [OK] {len(fmts)} ledger rows stamped payload_fmt={PAYLOAD_FMT_V3}')

        report_a = replay_audit(db_a)
        assert report_a['ok'], format_report(report_a)
        print('  [OK] author container A audit passes')

        # ==================================================================
        # 2. Genesis replay now fails
        # ==================================================================
        print('\n=== 2. Genesis replay into another empty container fails ===')
        path_b = track('test_container_binding_b.msf')
        if os.path.exists(path_b):
            os.remove(path_b)
        db_b = MSFStorage(path_b, ca_cert_path=ca_cert_path)
        uid_b = db_b.container_uid
        assert uid_b != uid_a, 'fresh container must mint a distinct uid'
        print(f'  [OK] container B has distinct uid={uid_b}')

        # Capture A's first chained row (query/params/signature/pub_key).
        row1 = db_a.conn.execute(
            "SELECT query, params, signature, pub_key, seq, prev_hash, payload_fmt "
            "FROM transactions WHERE seq IS NOT NULL ORDER BY seq LIMIT 1"
        ).fetchone()
        q1, params1_str, sig1, pub1, seq1, prev1, fmt1 = row1
        params1 = json.loads(params1_str) if params1_str else []
        assert seq1 == 1 and prev1 == '' and fmt1 == PAYLOAD_FMT_V3

        try:
            db_b.execute_signed(q1, params1, sig1, pub1)
            raise AssertionError('transplanted genesis row should fail signature check')
        except PermissionError as e:
            msg = str(e)
            assert 'signed against the current chain head' in msg, msg
            assert uid_b in msg or 'container=' in msg, msg
            print(f'  [OK] execute_signed of A row 1 on B denied: {e}')

        # Raw-splice A's ledger + user tables into B and audit → not ok.
        path_splice = track('test_container_binding_splice.msf')
        if os.path.exists(path_splice):
            os.remove(path_splice)
        shutil.copy2(path_b, path_splice)
        db_b.close()
        db_a.close()  # release file locks before raw sqlite copy (Windows)

        # Open A and splice destinations with raw sqlite.
        src = __import__('sqlite3').connect(path_a)
        dst = __import__('sqlite3').connect(path_splice)
        # Clear B's empty-ish ledger/system state that would conflict, then
        # copy A's transactions + user data while leaving B's container_uid.
        for table in ('transactions', 'user_roles', 'rbac_rules', 'manifest', 'items'):
            try:
                dst.execute(f'DELETE FROM {table}')
            except Exception:
                pass
        # Ensure items schema exists on splice target.
        dst.execute(
            "CREATE TABLE IF NOT EXISTS items "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        )
        for table in ('transactions', 'user_roles', 'rbac_rules', 'manifest', 'items'):
            cols = [r[1] for r in src.execute(f'PRAGMA table_info({table})')]
            if not cols:
                continue
            col_list = ', '.join(cols)
            for row in src.execute(f'SELECT {col_list} FROM {table}'):
                placeholders = ', '.join('?' * len(cols))
                dst.execute(
                    f'INSERT INTO {table} ({col_list}) VALUES ({placeholders})',
                    row,
                )
        dst.commit()
        # Confirm uids still differ.
        splice_uid = dst.execute(
            "SELECT value FROM container_meta WHERE key = 'container_uid'"
        ).fetchone()[0]
        assert splice_uid == uid_b
        src.close()
        dst.close()

        db_splice = MSFStorage(path_splice, ca_cert_path=ca_cert_path)
        assert db_splice.container_uid == uid_b
        report_splice = replay_audit(db_splice)
        assert not report_splice['ok'], 'raw-spliced ledger must fail audit against B uid'
        assert report_splice['transactions']['invalid_signatures'], \
            'expected invalid_signatures on transplanted v3 rows'
        print(
            f"  [OK] raw-splice audit failed "
            f"({len(report_splice['transactions']['invalid_signatures'])} invalid sigs)"
        )
        db_splice.close()

        # ==================================================================
        # 3. Whole-file copy is still legitimate
        # ==================================================================
        print('\n=== 3. Whole-file copy is a legitimate replica ===')
        path_copy = track('test_container_binding_copy.msf')
        if os.path.exists(path_copy):
            os.remove(path_copy)
        shutil.copy2(path_a, path_copy)
        db_copy = MSFStorage(path_copy, ca_cert_path=ca_cert_path)
        assert db_copy.container_uid == uid_a
        report_copy = replay_audit(db_copy)
        assert report_copy['ok'], format_report(report_copy)
        print('  [OK] byte-copy shares uid and audit passes')
        db_copy.close()

        # ==================================================================
        # 4. Legacy/v2 upgrade path + format-downgrade
        # ==================================================================
        print('\n=== 4. Mixed v2→v3 ledger verifies; v2-after-v3 is a chain break ===')
        path_mixed = track('test_container_binding_mixed.msf')
        if os.path.exists(path_mixed):
            os.remove(path_mixed)

        db_m = MSFStorage(path_mixed, ca_cert_path=ca_cert_path)
        uid_m = db_m.container_uid
        admin_key_obj = _load_key(admin_key)

        # Hand-craft v2 rows (no container in payload, payload_fmt NULL) via
        # raw SQL insert after signing with the v2 canonical form. Also apply
        # the SQL so the live state matches the ledger for audit.
        def insert_v2_row(query, params, next_seq, prev_hash):
            payload = canonical_payload(query, params, next_seq, prev_hash)  # no uid
            sig = admin_key_obj.sign(payload, padding.PKCS1v15(), hashes.SHA256())
            # Execute SQL with active signer so state matches (no authorizer
            # needed for authoring fixture — raw path).
            db_m._active_signer = db_m._get_identity(admin_cert)
            try:
                if params:
                    db_m.conn.execute(query, params)
                else:
                    db_m.conn.execute(query)
            finally:
                db_m._active_signer = None
            db_m.conn.execute(
                "INSERT INTO transactions "
                "(query, params, signature, pub_key, seq, prev_hash, payload_fmt) "
                "VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (query, json.dumps(params), sig, admin_cert, next_seq, prev_hash),
            )
            db_m.conn.commit()
            return ledger_row_hash(payload, sig)

        # Bootstrap admin outside the ledger (mirrors bootstrap_admin side effect)
        # then record a v2 bootstrap write.
        db_m.conn.execute(
            "INSERT INTO user_roles (identity, role) VALUES (?, 'admin')",
            (db_m._get_identity(admin_cert),),
        )
        db_m.conn.commit()

        h = insert_v2_row(
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'],
            1, '',
        )
        h = insert_v2_row(
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            ['database', '*', 'writer', 'read'],
            2, h,
        )
        print('  [OK] hand-crafted v2 tail (2 rows, payload_fmt NULL)')

        # Now a normal v3 signed write continues the chain.
        signed_exec(
            db_m, admin_cert, admin_key,
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            ['database', '*', 'writer', 'write'],
        )
        fmts_m = list(db_m.conn.execute(
            "SELECT seq, payload_fmt FROM transactions WHERE seq IS NOT NULL ORDER BY seq"
        ))
        assert fmts_m[0][1] is None and fmts_m[1][1] is None
        assert fmts_m[2][1] == PAYLOAD_FMT_V3
        report_mixed = replay_audit(db_m)
        assert report_mixed['ok'], format_report(report_mixed)
        print('  [OK] mixed v2→v3 ledger verifies (audit ok)')

        # Format downgrade: append a v2-signed row after v3 via raw SQL.
        next_seq, prev_hash = db_m.get_chain_head()
        dq = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
        dp = ['object', 'items', 'writer', 'read']
        dpayload = canonical_payload(dq, dp, next_seq, prev_hash)  # v2, no uid
        dsig = admin_key_obj.sign(dpayload, padding.PKCS1v15(), hashes.SHA256())
        db_m.conn.execute(dq, dp)
        db_m.conn.execute(
            "INSERT INTO transactions "
            "(query, params, signature, pub_key, seq, prev_hash, payload_fmt) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (dq, json.dumps(dp), dsig, admin_cert, next_seq, prev_hash),
        )
        db_m.conn.commit()

        report_down = replay_audit(db_m)
        assert not report_down['ok'], 'v2-after-v3 must fail audit'
        breaks = report_down['transactions']['chain_breaks']
        assert any('format downgrade' in b.get('error', '') for b in breaks), breaks
        print(f'  [OK] format downgrade flagged: {breaks}')
        db_m.close()

        # ==================================================================
        # 5. Sync end-to-end
        # ==================================================================
        print('\n=== 5. Sync: bootstrap shares uid; mismatch raises; write-through works ===')
        hub_dir = tempfile.mkdtemp(prefix='mschf_bind_hub_')
        tmp_dirs.append(hub_dir)
        container_id = 'bind_notes'
        hub_msf = os.path.join(hub_dir, f'{container_id}.msf')

        hub_cert, hub_key = generate_user_cert('bind_hub', ca_cert_pem, ca_key_pem)
        hub_cert_path = track('bind_hub.crt')
        hub_key_path = track('bind_hub.key')
        with open(hub_cert_path, 'wb') as f:
            f.write(hub_cert)
        with open(hub_key_path, 'wb') as f:
            f.write(hub_key)

        hub_db = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        hub_uid = hub_db.container_uid
        hub_db.conn.execute(
            "CREATE TABLE notes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)"
        )
        hub_db.conn.commit()
        signed_exec(
            hub_db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'],
            bootstrap=True,
        )
        signed_exec(
            hub_db, admin_cert, admin_key,
            "INSERT INTO notes (body) VALUES (?)",
            ['seed note'],
        )
        signed_exec(
            hub_db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_cn', 'bind_hub'],
        )
        hub_db.close()

        hub = MSFHub(
            hub_dir, hub_cert_path, hub_key_path,
            host='127.0.0.1', port=0, ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        hub_url = hub.url
        hub_cn = 'bind_hub'
        print(f'  hub at {hub_url}')

        spoke_path = track(os.path.join(
            tempfile.mkdtemp(prefix='mschf_bind_spoke_'), f'{container_id}.msf'))
        tmp_dirs.append(os.path.dirname(spoke_path))

        spoke = msync.bootstrap(
            hub_url, container_id, spoke_path,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        assert spoke.container_uid == hub_uid, \
            f'replica uid {spoke.container_uid!r} != hub {hub_uid!r}'
        print(f'  [OK] bootstrap replica shares uid={hub_uid}')

        # Mismatched expected_container_uid must raise before signing.
        admin_private = _load_key(admin_key)
        try:
            msync.sign_and_submit(
                hub_url, container_id, admin_private, admin_cert.decode('utf-8'),
                "INSERT INTO notes (body) VALUES (?)",
                ['should not submit'],
                expected_hub_cn=hub_cn,
                ca_cert_path=ca_cert_path,
                expected_container_uid='0' * 32,
            )
            raise AssertionError('mismatched expected_container_uid should raise')
        except PermissionError as e:
            assert 'container_uid' in str(e), str(e)
            print(f'  [OK] mismatched expected_container_uid raised: {e}')

        # Normal write-through + pull.
        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert.decode('utf-8'),
            "INSERT INTO notes (body) VALUES (?)",
            ['synced note'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
            expected_container_uid=spoke.container_uid,
        )
        result = msync.pull_and_apply(
            spoke, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        assert result['applied'] >= 1, result
        bodies = [r[0] for r in spoke.conn.execute(
            "SELECT body FROM notes ORDER BY id")]
        assert 'synced note' in bodies, bodies
        report_spoke = replay_audit(spoke)
        assert report_spoke['ok'], format_report(report_spoke)
        print(f'  [OK] write-through + pull; spoke audit ok ({result["applied"]} applied)')

        spoke.close()
        print('\nALL container-binding tests passed.')

    finally:
        if hub is not None:
            try:
                hub.shutdown()
                hub.server_close()
            except Exception:
                pass
        for d in tmp_dirs:
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
        for p in artifacts:
            for candidate in (p, p + '.head'):
                try:
                    if os.path.isfile(candidate):
                        os.remove(candidate)
                except Exception:
                    pass


if __name__ == '__main__':
    run()
