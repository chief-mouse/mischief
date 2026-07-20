"""Hub-and-spoke ledger sync integration tests.

Run: python test_hub_sync.py

Covers bootstrap, write-through with attribution triggers, multi-spoke
convergence, stale-head retry, bad signature / untrusted signer rejection,
head attestation + sidecar anti-truncation, and datetime replay fidelity.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from datetime import datetime

sys.path.insert(0, os.path.abspath('src'))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from mschf.audit import replay_audit, format_report
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert
from mschf.hub import MSFHub
from mschf.storage import MSFStorage, PAYLOAD_FMT_V3, canonical_payload, make_json_serializable
from mschf import sync as msync


# Minimal insert-stamp trigger (same pattern as AUDIT_TRIGGERS / starter).
NOTES_TRIGGERS = [
    """CREATE TRIGGER trg_notes_insert_audit AFTER INSERT ON notes
       BEGIN
         UPDATE notes SET
           created_at = COALESCE(NEW.created_at, datetime('now')),
           created_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
]


def _load_key(pem_bytes):
    return serialization.load_pem_private_key(
        pem_bytes, password=None, backend=default_backend()
    )


def _sign(db, key_pem, query, params):
    key = _load_key(key_pem)
    next_seq, prev_hash = db.get_chain_head()
    payload = canonical_payload(
        query, params, next_seq, prev_hash, db.container_uid)
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256()), next_seq, prev_hash


def _signed_exec(db, cert_pem, key_pem, query, params, bootstrap=False):
    sig, _, _ = _sign(db, key_pem, query, params)
    if bootstrap:
        return db.bootstrap_admin(query, params, sig, cert_pem)
    return db.execute_signed(query, params, sig, cert_pem)


def _ledger_fingerprint(storage):
    """Comparable ledger view: (query, params, signature, seq, prev_hash) per row."""
    rows = storage.conn.execute(
        "SELECT query, params, signature, seq, prev_hash FROM transactions "
        "WHERE seq IS NOT NULL ORDER BY seq"
    ).fetchall()
    return rows


def run():
    artifacts = []  # paths to clean (never ca.crt / ca.key)
    tmp_dirs = []
    hub = None
    hub_thread = None
    spoke_a = None
    spoke_b = None
    hub_storage = None

    def track(path):
        artifacts.append(path)
        return path

    try:
        # ------------------------------------------------------------------
        # Host CA (reuse; never overwrite)
        # ------------------------------------------------------------------
        print('--- Host CA ---')
        ca_cert_path, ca_key_path = 'ca.crt', 'ca.key'
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            ca_pem, ca_key_pem = generate_selfsigned_cert('Temporary Root CA')
            with open(ca_cert_path, 'wb') as f:
                f.write(ca_pem)
            with open(ca_key_path, 'wb') as f:
                f.write(ca_key_pem)
            print('Generated temporary host ca.crt / ca.key')
        else:
            print('Reusing existing host ca.crt / ca.key')

        with open(ca_cert_path, 'rb') as f:
            ca_cert_pem = f.read()
        with open(ca_key_path, 'rb') as f:
            ca_key_pem = f.read()

        # ------------------------------------------------------------------
        # Identities: hub_svc, sync_admin, sync_user
        # ------------------------------------------------------------------
        print('--- Issue hub_svc / sync_admin / sync_user certs ---')
        hub_cert, hub_key = generate_user_cert('hub_svc', ca_cert_pem, ca_key_pem)
        admin_cert, admin_key = generate_user_cert('sync_admin', ca_cert_pem, ca_key_pem)
        user_cert, user_key = generate_user_cert('sync_user', ca_cert_pem, ca_key_pem)

        hub_cert_path = track('hub_svc.crt')
        hub_key_path = track('hub_svc.key')
        with open(hub_cert_path, 'wb') as f:
            f.write(hub_cert)
        with open(hub_key_path, 'wb') as f:
            f.write(hub_key)
        # Keep admin/user in memory only (no host identity files required).

        # ------------------------------------------------------------------
        # Author a fresh container in a temp hub dir
        # ------------------------------------------------------------------
        print('--- Author hub container (notes + triggers + RBAC + homing) ---')
        hub_dir = tempfile.mkdtemp(prefix='mschf_hub_')
        tmp_dirs.append(hub_dir)
        container_id = 'sync_notes'
        hub_msf = os.path.join(hub_dir, f'{container_id}.msf')

        db = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        # Unsigned schema (tables pre-seeded at authoring; triggers are signed).
        db.conn.execute(
            "CREATE TABLE notes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "body TEXT NOT NULL, "
            "created_at TEXT DEFAULT (datetime('now')), "
            "created_by TEXT)"
        )
        db.conn.commit()

        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'none'],
            bootstrap=True,
        )
        for ddl in NOTES_TRIGGERS:
            _signed_exec(db, admin_cert, admin_key, ddl, [])

        # Homing keys (manifest).
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_cn', 'hub_svc'],
        )
        # sync_hub_url filled after we know the port.

        # RBAC: role writer with db read/write + object rules on notes.
        for level, target, role, perm in [
            ('database', '*', 'writer', 'read'),
            ('database', '*', 'writer', 'write'),
            ('object', 'notes', 'writer', 'write'),
            ('object', 'notes', 'writer', 'read'),
        ]:
            _signed_exec(
                db, admin_cert, admin_key,
                "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
                [level, target, role, perm],
            )
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
            ['cert:CN=sync_user', 'writer'],
        )
        # Seed one note as admin so the container is non-empty.
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT INTO notes (body) VALUES (?)",
            ['seed note from admin'],
        )
        db.close()

        # ------------------------------------------------------------------
        # Start hub on ephemeral port
        # ------------------------------------------------------------------
        print('--- Start hub ---')
        hub = MSFHub(
            hub_dir,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        # Wait until the server is bound.
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url
        print(f'Hub listening at {hub_url}')

        user_private = _load_key(user_key)
        admin_private = _load_key(admin_key)
        hub_cn = 'hub_svc'

        # Homing URL via hub HTTP (keeps all hub writes on the server path).
        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_url', hub_url],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )

        # Separate connection for hub-side assertions (not the hub's own handle).
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)

        # ==================================================================
        # 1. Bootstrap
        # ==================================================================
        print('\n=== 1. Bootstrap spoke A ===')
        spoke_a_dir = tempfile.mkdtemp(prefix='mschf_spoke_a_')
        tmp_dirs.append(spoke_a_dir)
        spoke_a_path = os.path.join(spoke_a_dir, f'{container_id}.msf')

        spoke_a = msync.bootstrap(
            hub_url, container_id, spoke_a_path,
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        report = replay_audit(spoke_a)
        print(format_report(report))
        assert report['ok'], 'bootstrap replica must pass replay_audit'

        hub_head = hub_storage.get_chain_head()
        local_head = spoke_a.get_chain_head()
        assert local_head == hub_head, f'heads mismatch: local={local_head} hub={hub_head}'

        sidecar = msync.load_attested_head(spoke_a_path)
        assert sidecar is not None, 'bootstrap must write .head sidecar'
        assert sidecar['next_seq'] == local_head[0]
        assert sidecar['prev_hash'] == local_head[1]
        print(f'  [OK] bootstrap audit clean; heads match {local_head}')

        # Homing helper
        url, cn = msync.homing(spoke_a)
        assert cn == 'hub_svc', cn
        assert url == hub_url, url
        print(f'  [OK] homing → url={url!r} cn={cn!r}')

        # ==================================================================
        # 2. Write-through
        # ==================================================================
        print('\n=== 2. Write-through (sync_user INSERT) ===')
        resp = msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['hello from sync_user'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert 'next_seq' in resp and 'attestation' in resp
        print(f'  hub accepted; new head next_seq={resp["next_seq"]}')

        result = msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert result['applied'] >= 1, result
        print(f'  spoke A applied {result["applied"]} row(s)')

        row = spoke_a.conn.execute(
            "SELECT body, created_by, created_at FROM notes WHERE body = ?",
            ['hello from sync_user'],
        ).fetchone()
        assert row is not None, 'INSERT missing on spoke A'
        assert row[1] == 'cert:CN=sync_user', f'created_by={row[1]!r}'
        print(f'  [OK] created_by stamped during replay: {row[1]}')

        report = replay_audit(spoke_a)
        assert report['ok'], format_report(report)
        assert spoke_a.get_chain_head() == hub_storage.get_chain_head()
        print('  [OK] replica audit clean; local head == hub head')

        # ==================================================================
        # 3. Second spoke
        # ==================================================================
        print('\n=== 3. Second spoke bootstrap + second write ===')
        spoke_b_dir = tempfile.mkdtemp(prefix='mschf_spoke_b_')
        tmp_dirs.append(spoke_b_dir)
        spoke_b_path = os.path.join(spoke_b_dir, f'{container_id}.msf')

        spoke_b = msync.bootstrap(
            hub_url, container_id, spoke_b_path,
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        report = replay_audit(spoke_b)
        assert report['ok'], format_report(report)
        note_count = spoke_b.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        assert note_count >= 2, f'spoke B should have seed + user note, got {note_count}'
        print(f'  [OK] spoke B bootstrap has {note_count} notes')

        msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['second write for both spokes'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        msync.pull_and_apply(spoke_a, hub_url, container_id, expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path)
        msync.pull_and_apply(spoke_b, hub_url, container_id, expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path)

        fp_a = _ledger_fingerprint(spoke_a)
        fp_b = _ledger_fingerprint(spoke_b)
        assert fp_a == fp_b, f'ledgers diverge:\n A={fp_a}\n B={fp_b}'
        assert spoke_a.get_chain_head() == spoke_b.get_chain_head() == hub_storage.get_chain_head()
        print(f'  [OK] both spokes byte-identical on ledger ({len(fp_a)} chained rows)')

        # ==================================================================
        # 4. Stale head
        # ==================================================================
        print('\n=== 4. Stale head → 409; sign_and_submit retries ===')
        old_seq, old_prev = hub_storage.get_chain_head()
        stale_query = "INSERT INTO notes (body) VALUES (?)"
        stale_params = ['stale-signed note']
        # Sign against current head, then advance the head with another write.
        payload = canonical_payload(
            stale_query, stale_params, old_seq, old_prev, hub_storage.container_uid)
        stale_sig = user_private.sign(payload, padding.PKCS1v15(), hashes.SHA256())

        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['advance head past stale'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        # Now the stale signature is against an old head.
        try:
            msync.submit(
                hub_url, container_id, stale_query, stale_params, stale_sig, user_cert,
                seq=old_seq, prev_hash=old_prev,
            )
            raise AssertionError('stale submit should raise StaleHead')
        except msync.StaleHead as e:
            assert e.head and 'next_seq' in e.head, e.head
            print(f'  [OK] direct submit → StaleHead (detail={e})')

        # Retry path succeeds.
        resp = msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            stale_query, stale_params,
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert 'next_seq' in resp
        print('  [OK] sign_and_submit retry path succeeded')

        # ==================================================================
        # 5. Bad signature rejected
        # ==================================================================
        print('\n=== 5. Bad signature → 403, ledger unchanged ===')
        before_head = hub_storage.get_chain_head()
        before_count = hub_storage.conn.execute(
            "SELECT COUNT(*) FROM transactions"
        ).fetchone()[0]
        q = "INSERT INTO notes (body) VALUES (?)"
        p = ['should not land']
        nseq, nprev = hub_storage.get_chain_head()
        good_payload = canonical_payload(
            q, p, nseq, nprev, hub_storage.container_uid)
        good_sig = bytearray(user_private.sign(good_payload, padding.PKCS1v15(), hashes.SHA256()))
        good_sig[-1] ^= 0xFF  # corrupt
        try:
            msync.submit(
                hub_url, container_id, q, p, bytes(good_sig), user_cert,
                seq=nseq, prev_hash=nprev,
            )
            raise AssertionError('corrupt signature should be rejected')
        except PermissionError as e:
            print(f'  [OK] rejected: {e}')
        after_head = hub_storage.get_chain_head()
        after_count = hub_storage.conn.execute(
            "SELECT COUNT(*) FROM transactions"
        ).fetchone()[0]
        assert after_head == before_head
        assert after_count == before_count
        print('  [OK] hub ledger unchanged')

        # ==================================================================
        # 6. Untrusted signer rejected
        # ==================================================================
        print('\n=== 6. Untrusted (rogue CA) signer → 403 Chain Verification ===')
        rogue_ca, rogue_ca_key = generate_selfsigned_cert('Rogue CA')
        rogue_cert, rogue_key_pem = generate_user_cert('rogue_user', rogue_ca, rogue_ca_key)
        rogue_key = _load_key(rogue_key_pem)
        nseq, nprev = hub_storage.get_chain_head()
        rq = "INSERT INTO notes (body) VALUES (?)"
        rp = ['rogue insert']
        rpayload = canonical_payload(
            rq, rp, nseq, nprev, hub_storage.container_uid)
        rsig = rogue_key.sign(rpayload, padding.PKCS1v15(), hashes.SHA256())
        try:
            msync.submit(
                hub_url, container_id, rq, rp, rsig, rogue_cert.decode('utf-8'),
                seq=nseq, prev_hash=nprev,
            )
            raise AssertionError('rogue signer should be rejected')
        except PermissionError as e:
            assert 'Chain Verification' in str(e), str(e)
            print(f'  [OK] rejected: {e}')

        # ==================================================================
        # 7. Head attestation
        # ==================================================================
        print('\n=== 7. Head attestation + sidecar anti-truncation ===')
        try:
            msync.fetch_head(
                hub_url, container_id,
                expected_hub_cn='wrong_cn',
                ca_cert_path=ca_cert_path,
            )
            raise AssertionError('wrong expected_hub_cn should raise')
        except PermissionError as e:
            assert 'does not match expected' in str(e) or 'CN' in str(e), str(e)
            print(f'  [OK] wrong expected_hub_cn raises: {e}')

        # Pull on spoke A so sidecar updates after the writes above.
        pre_side = msync.load_attested_head(spoke_a_path)
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        post_side = msync.load_attested_head(spoke_a_path)
        assert post_side is not None
        assert post_side['next_seq'] == spoke_a.get_chain_head()[0]
        assert post_side['next_seq'] >= (pre_side['next_seq'] if pre_side else 0)
        print(f'  [OK] sidecar updated to next_seq={post_side["next_seq"]}')

        # Fabricated regressed head: hand-write sidecar with higher seq.
        fake = {
            'container': container_id,
            'next_seq': post_side['next_seq'] + 100,
            'prev_hash': 'deadbeef' * 8,
            'attestation': post_side.get('attestation'),
        }
        with open(msync.head_sidecar_path(spoke_a_path), 'w', encoding='utf-8') as f:
            json.dump(fake, f)
        try:
            msync.pull_and_apply(
                spoke_a, hub_url, container_id,
                expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
            )
            raise AssertionError('regressed head should raise')
        except PermissionError as e:
            assert 'does not extend' in str(e) or 'truncation' in str(e).lower() or 'fork' in str(e).lower(), str(e)
            print(f'  [OK] fabricated higher sidecar raises: {e}')
        # Restore a valid sidecar for cleanup hygiene.
        msync.store_attested_head(spoke_a_path, {
            'container': container_id,
            'next_seq': spoke_a.get_chain_head()[0],
            'prev_hash': spoke_a.get_chain_head()[1],
            'attestation': post_side.get('attestation'),
        })

        # ==================================================================
        # 8. Timestamps
        # ==================================================================
        print('\n=== 8. Timestamp fidelity + datetime restored ===')
        # Ensure spoke A is fully caught up, then compare a known row's timestamp
        # against the hub ledger timestamp for its INSERT.
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        # Find the INSERT for 'hello from sync_user' on both sides.
        hub_txn = hub_storage.conn.execute(
            "SELECT timestamp, seq FROM transactions "
            "WHERE query LIKE 'INSERT INTO notes%' AND params LIKE '%hello from sync_user%' "
            "ORDER BY seq LIMIT 1"
        ).fetchone()
        assert hub_txn is not None
        hub_ts, hub_seq = hub_txn

        local_txn = spoke_a.conn.execute(
            "SELECT timestamp FROM transactions WHERE seq = ?", (hub_seq,)
        ).fetchone()
        assert local_txn is not None
        assert local_txn[0] == hub_ts, f'timestamp mismatch hub={hub_ts!r} local={local_txn[0]!r}'
        print(f'  [OK] replicated ledger timestamp matches hub: {hub_ts}')

        # Row created_at should equal the ledger timestamp (datetime override).
        note_row = spoke_a.conn.execute(
            "SELECT created_at FROM notes WHERE body = ?",
            ['hello from sync_user'],
        ).fetchone()
        assert note_row is not None
        assert note_row[0] == hub_ts, (
            f'created_at={note_row[0]!r} should equal hub ledger ts={hub_ts!r} '
            '(datetime override during replay)'
        )
        print(f'  [OK] notes.created_at equals ledger timestamp (override worked)')

        # After apply, built-in datetime('now') returns current time again.
        time.sleep(0.05)
        now_val = spoke_a.conn.execute("SELECT datetime('now')").fetchone()[0]
        try:
            parsed = datetime.strptime(now_val, '%Y-%m-%d %H:%M:%S')
            # sqlite datetime('now') is UTC; allow a generous window.
            utc_now = datetime.utcnow()
            assert abs((utc_now - parsed).total_seconds()) < 120, (
                f"datetime('now')={now_val!r} not near utc now={utc_now}"
            )
            print(f"  [OK] datetime('now') restored → {now_val}")
        except ValueError:
            raise AssertionError(f"datetime('now') returned non-timestamp: {now_val!r}")

        # ------------------------------------------------------------------
        # 9. Malicious hub: RBAC-violating chained row refused on pull
        # ------------------------------------------------------------------
        print('\n=== 9. Malicious hub RBAC row → pull PermissionError ===')
        # Positive control: clean container has zero rbac_violations.
        clean_report = replay_audit(spoke_a)
        assert clean_report['ok']
        assert not clean_report['transactions'].get('rbac_violations'), (
            clean_report['transactions'].get('rbac_violations')
        )
        print('  [OK] clean spoke has zero rbac_violations')

        pre_head = spoke_a.get_chain_head()
        pre_roles = list(spoke_a.conn.execute(
            "SELECT identity, role FROM user_roles ORDER BY identity"
        ).fetchall())

        # Craft a properly-signed, correctly-chained v3 row by low-priv
        # sync_user (notes-only writer) that escalates via user_roles.
        poison_q = (
            "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
        )
        poison_params = ['cert:CN=evil', 'admin']
        next_seq, prev_hash = hub_storage.get_chain_head()
        payload = canonical_payload(
            poison_q, poison_params, next_seq, prev_hash,
            hub_storage.container_uid,
        )
        poison_sig = user_private.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        params_str = json.dumps(make_json_serializable(poison_params))
        pub_key_val = (
            user_cert.decode('utf-8') if isinstance(user_cert, bytes) else user_cert
        )

        # Raw sqlite3 on the hub container: insert ledger row AND execute its
        # effect so hub tables/ledger stay self-consistent (bypasses
        # execute_signed / writer-side RBAC — colluding hub scenario).
        raw_hub = sqlite3.connect(hub_msf)
        raw_hub.execute(poison_q, poison_params)
        raw_hub.execute(
            "INSERT INTO transactions "
            "(query, params, signature, pub_key, timestamp, seq, prev_hash, "
            "payload_fmt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (poison_q, params_str, poison_sig, pub_key_val, ts,
             next_seq, prev_hash, PAYLOAD_FMT_V3),
        )
        raw_hub.commit()
        raw_hub.close()

        # Refresh our assertion handle and the hub's cached storage so both
        # see the poison (raw write was on a separate connection).
        hub_storage.close()
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        if container_id in hub._storages:
            try:
                hub._storages[container_id].close()
            except Exception:
                pass
            del hub._storages[container_id]

        try:
            msync.pull_and_apply(
                spoke_a, hub_url, container_id,
                expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
            )
            raise AssertionError(
                'pull_and_apply should refuse RBAC-violating hub row'
            )
        except PermissionError as e:
            assert 'rbac' in str(e).lower(), e
            print(f'  [OK] pull refused: {e}')

        assert spoke_a.get_chain_head() == pre_head, (
            f'replica head changed after rollback: '
            f'{spoke_a.get_chain_head()} vs {pre_head}'
        )
        post_roles = list(spoke_a.conn.execute(
            "SELECT identity, role FROM user_roles ORDER BY identity"
        ).fetchall())
        assert post_roles == pre_roles, (
            f'user_roles changed: {post_roles} vs {pre_roles}'
        )
        assert not any(r[0] == 'cert:CN=evil' for r in post_roles)
        print('  [OK] replica user_roles and head unchanged (rollback)')

        report = replay_audit(hub_storage)
        print(format_report(report))
        assert not report['ok'], 'poisoned hub must fail replay_audit'
        violations = report['transactions']['rbac_violations']
        assert violations, 'expected rbac_violations on hub file'
        print(f'  [OK] hub replay_audit rbac_violations: {violations}')

        print('\n=== ALL hub/sync tests passed ===')
        return 0

    finally:
        # Shutdown hub
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

        for s in (spoke_a, spoke_b):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        if hub_storage is not None:
            try:
                hub_storage.close()
            except Exception:
                pass

        # Cleanup generated certs and temp dirs (never ca.*)
        for path in artifacts:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        # Sidecars live under tmp dirs and are removed with them.


if __name__ == '__main__':
    sys.exit(run() or 0)
