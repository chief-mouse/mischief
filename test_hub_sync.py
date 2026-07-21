"""Hub-and-spoke ledger sync integration tests.

Run: python test_hub_sync.py

Covers bootstrap, write-through with attribution triggers, multi-spoke
convergence, stale-head retry, bad signature / untrusted signer rejection,
head attestation (container_meta) anti-truncation, legacy .head migration,
and datetime replay fidelity.
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

        # RBAC: role writer with db read/write + object rules on notes.
        # Author these *before* sync_hub_cn so the homed-write guard does not
        # block offline authoring (guard fires once the hub CN is set).
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
        # Homing keys last (manifest). sync_hub_url filled after we know the port.
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_cn', 'hub_svc'],
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

        attested = msync.load_attested_head(spoke_a)
        assert attested is not None, 'bootstrap must store hub_attestation in container_meta'
        assert attested['next_seq'] == local_head[0]
        assert attested['prev_hash'] == local_head[1]
        assert not os.path.isfile(f'{spoke_a_path}.head'), (
            'bootstrap must not create a .head sidecar'
        )
        print(f'  [OK] bootstrap audit clean; heads match {local_head}; '
              f'hub_attestation in container_meta')

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
        # 7. Head attestation (container_meta) + anti-truncation
        # ==================================================================
        print('\n=== 7. Head attestation + container_meta anti-truncation ===')
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

        # Pull on spoke A so hub_attestation updates after the writes above.
        pre_att = msync.load_attested_head(spoke_a)
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        post_att = msync.load_attested_head(spoke_a)
        assert post_att is not None
        assert post_att['next_seq'] == spoke_a.get_chain_head()[0]
        assert post_att['next_seq'] >= (pre_att['next_seq'] if pre_att else 0)
        # (a) no .head sidecar; container_meta matches hub head
        assert not os.path.isfile(f'{spoke_a_path}.head'), (
            'pull must not create a .head sidecar'
        )
        hub_head_now = hub_storage.get_chain_head()
        assert post_att['next_seq'] == hub_head_now[0]
        assert post_att['prev_hash'] == hub_head_now[1]
        meta_row = spoke_a.conn.execute(
            "SELECT value FROM container_meta WHERE key = 'hub_attestation'"
        ).fetchone()
        assert meta_row is not None and meta_row[0]
        meta_parsed = json.loads(meta_row[0])
        assert meta_parsed['next_seq'] == post_att['next_seq']
        assert meta_parsed['prev_hash'] == post_att['prev_hash']
        print(f'  [OK] hub_attestation updated to next_seq={post_att["next_seq"]} '
              f'(no .head file; matches hub)')

        # (c) Fabricated regressed head: raw-write container_meta with higher seq.
        fake = {
            'container': container_id,
            'next_seq': post_att['next_seq'] + 100,
            'prev_hash': 'deadbeef' * 8,
            'attestation': post_att.get('attestation'),
        }
        spoke_a.conn.execute(
            "INSERT OR REPLACE INTO container_meta (key, value) VALUES (?, ?)",
            ('hub_attestation', json.dumps(fake, sort_keys=True)),
        )
        spoke_a.conn.commit()
        try:
            msync.pull_and_apply(
                spoke_a, hub_url, container_id,
                expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
            )
            raise AssertionError('regressed head should raise')
        except PermissionError as e:
            assert (
                'does not extend' in str(e)
                or 'truncation' in str(e).lower()
                or 'fork' in str(e).lower()
            ), str(e)
            print(f'  [OK] fabricated higher container_meta attestation raises: {e}')
        # Restore a valid attestation for subsequent tests.
        msync.store_attested_head(spoke_a, {
            'container': container_id,
            'next_seq': spoke_a.get_chain_head()[0],
            'prev_hash': spoke_a.get_chain_head()[1],
            'attestation': post_att.get('attestation'),
        })

        # (b) Legacy .head sidecar migration: wipe meta key, hand-write sidecar,
        # pull imports into container_meta and deletes the sidecar file.
        print('\n=== 7b. Legacy .head sidecar → container_meta migration ===')
        spoke_a.conn.execute(
            "DELETE FROM container_meta WHERE key = 'hub_attestation'"
        )
        spoke_a.conn.commit()
        assert msync.load_attested_head(spoke_a) is None
        legacy_side = {
            'container': container_id,
            'next_seq': spoke_a.get_chain_head()[0],
            'prev_hash': spoke_a.get_chain_head()[1],
            'attestation': post_att.get('attestation'),
        }
        legacy_path = f'{spoke_a_path}.head'
        with open(legacy_path, 'w', encoding='utf-8') as f:
            json.dump(legacy_side, f)
        assert os.path.isfile(legacy_path)
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        assert not os.path.isfile(legacy_path), 'migration must delete readable sidecar'
        migrated = msync.load_attested_head(spoke_a)
        assert migrated is not None, 'migration must import into container_meta'
        assert migrated['next_seq'] == spoke_a.get_chain_head()[0]
        assert migrated['prev_hash'] == spoke_a.get_chain_head()[1]
        print(f'  [OK] legacy sidecar imported (next_seq={migrated["next_seq"]}) '
              f'and file removed')

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

        # ------------------------------------------------------------------
        # 10–15 below need a clean hub again. Rebuild a fresh container + hub
        # so the poison above does not pollute event/outbox/guard tests.
        # ------------------------------------------------------------------
        print('\n=== Rebuild clean hub for event-driven / outbox tests ===')
        for s in (spoke_a, spoke_b, hub_storage):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        spoke_a = spoke_b = hub_storage = None
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

        hub_dir2 = tempfile.mkdtemp(prefix='mschf_hub2_')
        tmp_dirs.append(hub_dir2)
        container_id = 'sync_notes'
        hub_msf = os.path.join(hub_dir2, f'{container_id}.msf')

        db = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
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
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT INTO notes (body) VALUES (?)",
            ['seed note from admin'],
        )
        _signed_exec(
            db, admin_cert, admin_key,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_cn', 'hub_svc'],
        )
        db.close()

        hub = MSFHub(
            hub_dir2,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url
        hub_cn = 'hub_svc'
        print(f'  Clean hub at {hub_url}')

        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_url', hub_url],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)

        spoke_a_dir = tempfile.mkdtemp(prefix='mschf_spoke_a2_')
        tmp_dirs.append(spoke_a_dir)
        spoke_a_path = os.path.join(spoke_a_dir, f'{container_id}.msf')
        spoke_a = msync.bootstrap(
            hub_url, container_id, spoke_a_path,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        spoke_b_dir = tempfile.mkdtemp(prefix='mschf_spoke_b2_')
        tmp_dirs.append(spoke_b_dir)
        spoke_b_path = os.path.join(spoke_b_dir, f'{container_id}.msf')
        spoke_b = msync.bootstrap(
            hub_url, container_id, spoke_b_path,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )

        # ==================================================================
        # 10. Long-poll events
        # ==================================================================
        print('\n=== 10. Long-poll events ===')
        # (a) events with since_seq behind returns immediately
        local_max = hub_storage.conn.execute(
            "SELECT IFNULL(MAX(seq), 0) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        t0 = time.monotonic()
        code, data = msync._http_json(
            'GET',
            msync._url(
                hub_url, 'containers', container_id, 'events',
                query={'since_seq': 0, 'timeout': 25},
            ),
            timeout=30,
        )
        elapsed_a = time.monotonic() - t0
        assert code == 200, data
        assert data.get('rows'), 'expected rows when since_seq behind'
        assert elapsed_a < 2.0, f'behind since_seq should return immediately, took {elapsed_a:.2f}s'
        print(f'  [OK] (a) since_seq behind → immediate rows ({len(data["rows"])}) in {elapsed_a:.3f}s')

        # (b) parked events answered within ~2s of concurrent submit
        since_now = hub_storage.get_chain_head()[0] - 1  # max seq = next-1
        # Use actual max seq as since_seq so wait is empty until new submit
        since_now = hub_storage.conn.execute(
            "SELECT IFNULL(MAX(seq), 0) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        result_box = {}

        def _parked_events():
            t_start = time.monotonic()
            c, d = msync._http_json(
                'GET',
                msync._url(
                    hub_url, 'containers', container_id, 'events',
                    query={'since_seq': since_now, 'timeout': 25},
                ),
                timeout=35,
            )
            result_box['code'] = c
            result_box['data'] = d
            result_box['elapsed'] = time.monotonic() - t_start

        park_thread = threading.Thread(target=_parked_events, daemon=True)
        park_thread.start()
        time.sleep(0.3)  # ensure the long-poll is waiting
        msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['wake long-poll'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        park_thread.join(timeout=10)
        assert park_thread.is_alive() is False, 'parked events request did not complete'
        assert result_box.get('code') == 200, result_box
        assert result_box.get('data', {}).get('rows'), result_box
        assert result_box['elapsed'] < 5.0, (
            f'parked request should wake on submit, elapsed={result_box["elapsed"]:.2f}s'
        )
        print(f'  [OK] (b) parked events woke in {result_box["elapsed"]:.3f}s '
              f'({len(result_box["data"]["rows"])} row(s))')

        # (c) timeout returns empty rows, HTTP 200
        since_tip = hub_storage.conn.execute(
            "SELECT IFNULL(MAX(seq), 0) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        # Refresh hub assertion handle after concurrent submit
        hub_storage.close()
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        since_tip = hub_storage.conn.execute(
            "SELECT IFNULL(MAX(seq), 0) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        t0 = time.monotonic()
        code, data = msync._http_json(
            'GET',
            msync._url(
                hub_url, 'containers', container_id, 'events',
                query={'since_seq': since_tip, 'timeout': 1},
            ),
            timeout=10,
        )
        elapsed_c = time.monotonic() - t0
        assert code == 200, data
        assert data.get('rows') == [], data
        assert elapsed_c >= 0.8, f'timeout should wait ~1s, got {elapsed_c:.2f}s'
        print(f'  [OK] (c) timeout → empty rows HTTP 200 in {elapsed_c:.3f}s')

        # ==================================================================
        # 11. Threaded-hub serialization
        # ==================================================================
        print('\n=== 11. Threaded concurrent sign_and_submit ===')
        n_threads = 6
        before_max = hub_storage.conn.execute(
            "SELECT IFNULL(MAX(seq), 0) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        errors = []
        barrier = threading.Barrier(n_threads)

        def _concurrent_submit(i):
            try:
                barrier.wait(timeout=10)
                msync.sign_and_submit(
                    hub_url, container_id, user_private, user_cert,
                    "INSERT INTO notes (body) VALUES (?)",
                    [f'concurrent-{i}'],
                    expected_hub_cn=hub_cn,
                    ca_cert_path=ca_cert_path,
                    max_retries=12,
                )
            except Exception as e:
                errors.append((i, e))

        threads = [
            threading.Thread(target=_concurrent_submit, args=(i,), daemon=True)
            for i in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, f'concurrent submits failed: {errors}'
        hub_storage.close()
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        seqs = [
            r[0] for r in hub_storage.conn.execute(
                "SELECT seq FROM transactions WHERE seq IS NOT NULL AND seq > ? ORDER BY seq",
                (before_max,),
            ).fetchall()
        ]
        assert len(seqs) == n_threads, f'expected {n_threads} new rows, got {seqs}'
        assert seqs == list(range(before_max + 1, before_max + 1 + n_threads)), seqs
        report = replay_audit(hub_storage)
        assert report['ok'], format_report(report)
        print(f'  [OK] {n_threads} concurrent submits → sequential seqs {seqs}; audit clean')

        # ==================================================================
        # 12. Subscribe
        # ==================================================================
        print('\n=== 12. Subscribe long-poll propagation ===')
        msync.pull_and_apply(
            spoke_b, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        # Close main handle so the subscriber thread owns the only writer.
        spoke_b.close()
        spoke_b = None
        applied_events = []
        stop_event = threading.Event()

        def _on_applied(result):
            applied_events.append(result)

        def _sub_loop():
            # Open MSFStorage in this thread (sqlite thread-affinity).
            sub = MSFStorage(spoke_b_path, ca_cert_path=ca_cert_path)
            try:
                msync.subscribe(
                    sub,
                    hub_url,
                    container_id,
                    stop_event,
                    expected_hub_cn=hub_cn,
                    on_applied=_on_applied,
                    ca_cert_path=ca_cert_path,
                    timeout=5,
                )
            finally:
                try:
                    sub.close()
                except Exception:
                    pass

        sub_thread = threading.Thread(target=_sub_loop, daemon=True)
        sub_thread.start()
        time.sleep(0.4)
        msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['subscribe-propagation'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not applied_events:
            time.sleep(0.1)
        assert applied_events, 'on_applied never fired'
        stop_event.set()
        sub_thread.join(timeout=8)
        assert not sub_thread.is_alive(), 'subscribe thread did not stop'
        # Re-open and confirm the write landed.
        spoke_b = MSFStorage(spoke_b_path, ca_cert_path=ca_cert_path)
        row = spoke_b.conn.execute(
            "SELECT body FROM notes WHERE body = ?",
            ['subscribe-propagation'],
        ).fetchone()
        assert row is not None, 'subscribe did not apply write to replica'
        print(f'  [OK] subscribe applied write; on_applied fired '
              f'({len(applied_events)} time(s)); stop_event clean')

        # ==================================================================
        # 13. Homed-write guard
        # ==================================================================
        print('\n=== 13. Homed-write guard ===')
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        try:
            _signed_exec(
                spoke_a, user_cert, user_key,
                "INSERT INTO notes (body) VALUES (?)",
                ['local-fork-attempt'],
            )
            raise AssertionError('homed replica should refuse local execute_signed')
        except PermissionError as e:
            assert 'hub_svc' in str(e) or 'hub' in str(e).lower(), str(e)
            assert 'MSCHF_ALLOW_LOCAL_WRITES' in str(e), str(e)
            print(f'  [OK] direct execute_signed → PermissionError: {e}')

        # Escape hatch: env allows local append (then discard that container).
        fork_dir = tempfile.mkdtemp(prefix='mschf_fork_')
        tmp_dirs.append(fork_dir)
        fork_path = os.path.join(fork_dir, f'{container_id}.msf')
        import shutil as _shutil
        _shutil.copy2(spoke_a_path, fork_path)
        prev_env = os.environ.get('MSCHF_ALLOW_LOCAL_WRITES')
        os.environ['MSCHF_ALLOW_LOCAL_WRITES'] = '1'
        try:
            fork_db = MSFStorage(fork_path, ca_cert_path=ca_cert_path)
            _signed_exec(
                fork_db, user_cert, user_key,
                "INSERT INTO notes (body) VALUES (?)",
                ['forced-local-append'],
            )
            body = fork_db.conn.execute(
                "SELECT body FROM notes WHERE body = ?",
                ['forced-local-append'],
            ).fetchone()
            assert body is not None
            fork_db.close()
            print('  [OK] MSCHF_ALLOW_LOCAL_WRITES=1 allows local append')
        finally:
            if prev_env is None:
                os.environ.pop('MSCHF_ALLOW_LOCAL_WRITES', None)
            else:
                os.environ['MSCHF_ALLOW_LOCAL_WRITES'] = prev_env

        # Hub's own storage (allow_homed_writes=True) still accepts submits.
        msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['hub-still-accepts'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        hub_storage.close()
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        assert hub_storage.conn.execute(
            "SELECT COUNT(*) FROM notes WHERE body = ?",
            ['hub-still-accepts'],
        ).fetchone()[0] == 1
        print('  [OK] hub storage still accepts submits via execute_signed path')

        # ==================================================================
        # 14. Outbox
        # ==================================================================
        print('\n=== 14. Outbox offline queue + flush ===')
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        pre_ledger = hub_storage.conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        spoke_pre_ledger = spoke_a.conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]

        # Stop hub → hub_write queues.
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
        hub = None
        hub_thread = None
        time.sleep(0.15)

        qw = msync.hub_write(
            spoke_a, hub_url, container_id,
            user_private, user_cert, 'sync_user',
            "INSERT INTO notes (body) VALUES (?)",
            ['offline-queued-note'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert qw['status'] == 'queued', qw
        box = msync.list_outbox(spoke_a)
        assert any(
            r['status'] == 'pending' and 'offline-queued-note' in json.dumps(r['params'])
            for r in box
        ), box
        spoke_post = spoke_a.conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        assert spoke_post == spoke_pre_ledger, (
            'queued write must not append a local ledger row'
        )
        print(f'  [OK] hub down → hub_write queued (id={qw.get("outbox_id")}); '
              f'no local ledger growth')

        # Restart hub on same dir/port? Port was ephemeral — rebind and update
        # hub_url. Outbox flush takes explicit hub_url.
        hub = MSFHub(
            hub_dir2,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url
        print(f'  Hub restarted at {hub_url}')

        summary = msync.flush_outbox(
            spoke_a, hub_url, container_id,
            user_private, user_cert, 'sync_user',
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert summary['flushed'] >= 1, summary
        assert summary['remaining'] == 0, summary
        assert not any(r['status'] == 'pending' for r in msync.list_outbox(spoke_a))
        hub_storage.close()
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        assert hub_storage.conn.execute(
            "SELECT COUNT(*) FROM notes WHERE body = ?",
            ['offline-queued-note'],
        ).fetchone()[0] == 1
        assert spoke_a.conn.execute(
            "SELECT COUNT(*) FROM notes WHERE body = ?",
            ['offline-queued-note'],
        ).fetchone()[0] == 1
        print(f'  [OK] flush_outbox → {summary}; note on hub + replica; outbox empty')

        # Ordering: two intents flush in id order.
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
        hub = None
        hub_thread = None
        time.sleep(0.1)

        id1 = msync.queue_intent(
            spoke_a, 'sync_user',
            "INSERT INTO notes (body) VALUES (?)",
            ['order-first'],
        )
        id2 = msync.queue_intent(
            spoke_a, 'sync_user',
            "INSERT INTO notes (body) VALUES (?)",
            ['order-second'],
        )
        assert id1 < id2

        hub = MSFHub(
            hub_dir2,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url

        summary = msync.flush_outbox(
            spoke_a, hub_url, container_id,
            user_private, user_cert, 'sync_user',
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert summary['flushed'] == 2, summary
        hub_storage.close()
        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        # Confirm both landed; ordering via ledger seq of matching inserts.
        seq_first = hub_storage.conn.execute(
            "SELECT seq FROM transactions WHERE params LIKE ? ORDER BY seq LIMIT 1",
            ['%order-first%'],
        ).fetchone()[0]
        seq_second = hub_storage.conn.execute(
            "SELECT seq FROM transactions WHERE params LIKE ? ORDER BY seq LIMIT 1",
            ['%order-second%'],
        ).fetchone()[0]
        assert seq_first < seq_second, (seq_first, seq_second)
        print(f'  [OK] two intents flushed in id order '
              f'(seq {seq_first} < {seq_second})')

        # Failure: RBAC-denied intent + valid behind it → first failed, second not submitted.
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
        hub = None
        hub_thread = None
        time.sleep(0.1)

        msync.queue_intent(
            spoke_a, 'sync_user',
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            ['object', 'notes', 'hacker', 'write'],
        )
        msync.queue_intent(
            spoke_a, 'sync_user',
            "INSERT INTO notes (body) VALUES (?)",
            ['should-not-submit-yet'],
        )

        hub = MSFHub(
            hub_dir2,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url

        pre_should = hub_storage.conn.execute(
            "SELECT COUNT(*) FROM notes WHERE body = ?",
            ['should-not-submit-yet'],
        ).fetchone()[0]
        # Close assertion handle so hub can open exclusive-ish; reopen after.
        hub_storage.close()
        hub_storage = None

        summary = msync.flush_outbox(
            spoke_a, hub_url, container_id,
            user_private, user_cert, 'sync_user',
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert summary['failed'] == 1, summary
        assert summary['remaining'] >= 1, summary
        assert summary['stopped_on'] == 'permission', summary
        box = msync.list_outbox(spoke_a)
        failed_rows = [r for r in box if r['status'] == 'failed']
        pending_rows = [r for r in box if r['status'] == 'pending']
        assert failed_rows and failed_rows[0]['error'], failed_rows
        assert any(
            'should-not-submit-yet' in json.dumps(r['params']) for r in pending_rows
        ), pending_rows

        hub_storage = MSFStorage(hub_msf, ca_cert_path=ca_cert_path)
        post_should = hub_storage.conn.execute(
            "SELECT COUNT(*) FROM notes WHERE body = ?",
            ['should-not-submit-yet'],
        ).fetchone()[0]
        assert post_should == pre_should, 'second intent must not have been submitted'
        report = replay_audit(spoke_a)
        assert report['ok'], format_report(report)
        print(f'  [OK] RBAC failure marks intent failed, stops flush; '
              f'audit clean (outbox excluded): {summary}')

        # Clear remaining pending so status counts stay sane.
        spoke_a.conn.execute(
            "DELETE FROM sync_outbox WHERE status = 'pending'"
        )
        spoke_a.conn.commit()

        # ==================================================================
        # 15. sync_status
        # ==================================================================
        print('\n=== 15. sync_status ===')
        # Unhomed container
        unhomed_path = os.path.join(
            tempfile.mkdtemp(prefix='mschf_unhomed_'), 'plain.msf')
        tmp_dirs.append(os.path.dirname(unhomed_path))
        unhomed = MSFStorage(unhomed_path, ca_cert_path=ca_cert_path)
        st = msync.sync_status(unhomed)
        assert st['homed'] is False
        assert st['hub_cn'] is None or st['hub_cn'] == ''
        assert st['reachable'] is None
        assert st['in_sync'] is None
        unhomed.close()
        print('  [OK] unhomed: homed=False, no probe fields')

        # Homed + in-sync (probe)
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        st = msync.sync_status(
            spoke_a, probe_hub_url=hub_url, expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert st['homed'] is True
        assert st['hub_cn'] == 'hub_svc'
        assert st['reachable'] is True
        assert st['in_sync'] is True
        assert st['local_next_seq'] is not None
        print(f'  [OK] homed+in-sync: {st}')

        # Homed + behind: advance hub without pulling
        msync.sign_and_submit(
            hub_url, container_id, user_private, user_cert,
            "INSERT INTO notes (body) VALUES (?)",
            ['status-behind-marker'],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        st = msync.sync_status(
            spoke_a, probe_hub_url=hub_url, expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert st['reachable'] is True
        assert st['in_sync'] is False
        print(f'  [OK] homed+behind: in_sync=False')

        # Pending outbox count
        msync.queue_intent(
            spoke_a, 'sync_user',
            "INSERT INTO notes (body) VALUES (?)",
            ['status-pending'],
        )
        st = msync.sync_status(spoke_a)
        assert st['outbox_pending'] >= 1
        print(f'  [OK] outbox_pending={st["outbox_pending"]}')

        # Homed + unreachable (stop hub)
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
        hub = None
        hub_thread = None
        time.sleep(0.1)
        st = msync.sync_status(
            spoke_a, probe_hub_url=hub_url, expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        assert st['reachable'] is False
        assert st['in_sync'] is None
        print(f'  [OK] hub stopped → reachable=False: {st}')

        # ==================================================================
        # 16. HostAPI product routing on a homed replica
        # ==================================================================
        print('\n=== 16. HostAPI on homed replica (unsigned read + hub_write) ===')
        # Restart hub for product-path tests (section 15 left it stopped).
        hub = MSFHub(
            hub_dir2,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url
        # Refresh spoke so sync_hub_url may be stale; pull first, then rewrite URL
        # via hub so the replica's manifest matches the new port.
        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_url', hub_url],
            expected_hub_cn=hub_cn,
            ca_cert_path=ca_cert_path,
        )
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        # Write user key to a temp file for HostAPI key_path.
        user_key_path = track(os.path.join(spoke_a_dir, 'sync_user.key'))
        with open(user_key_path, 'wb') as f:
            f.write(user_key)
        user_cert_str = (
            user_cert.decode('utf-8') if isinstance(user_cert, bytes) else user_cert
        )

        from mschf.sandbox import HostAPI, HubWriteResult

        api = HostAPI(
            spoke_a_dir,
            db=spoke_a,
            current_user_cn='sync_user',
            current_user_cert_pem=user_cert_str,
            key_path=user_key_path,
            key_passphrase=None,
        )

        # (a) SELECT works unsigned — no new local ledger row.
        pre_ledger = spoke_a.conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        cur = api.execute_signed_query("SELECT body FROM notes ORDER BY id")
        bodies = [r[0] for r in cur.fetchall()]
        assert bodies, 'SELECT should return rows'
        post_ledger = spoke_a.conn.execute(
            "SELECT COUNT(*) FROM transactions WHERE seq IS NOT NULL"
        ).fetchone()[0]
        assert post_ledger == pre_ledger, (
            'homed SELECT must not append a local ledger row'
        )
        print(f'  [OK] unsigned SELECT returned {len(bodies)} row(s); ledger unchanged')

        # (b) Viewer without object read → PermissionError
        viewer_cert, viewer_key = generate_user_cert(
            'sync_viewer', ca_cert_pem, ca_key_pem
        )
        # Grant database read only (no object read on notes) via hub.
        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
            ['database', '*', 'viewer', 'read'],
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        msync.sign_and_submit(
            hub_url, container_id, admin_private, admin_cert,
            "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
            ['cert:CN=sync_viewer', 'viewer'],
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        viewer_key_path = track(os.path.join(spoke_a_dir, 'sync_viewer.key'))
        with open(viewer_key_path, 'wb') as f:
            f.write(viewer_key)
        viewer_api = HostAPI(
            spoke_a_dir,
            db=spoke_a,
            current_user_cn='sync_viewer',
            current_user_cert_pem=(
                viewer_cert.decode('utf-8')
                if isinstance(viewer_cert, bytes) else viewer_cert
            ),
            key_path=viewer_key_path,
            key_passphrase=None,
        )
        try:
            viewer_api.execute_signed_query("SELECT body FROM notes")
            raise AssertionError('viewer without object read should raise')
        except PermissionError as e:
            assert 'notes' in str(e).lower() or 'read' in str(e).lower(), str(e)
            print(f'  [OK] viewer without object read → PermissionError: {e}')

        # (c) Mutation returns committed; row arrives via pull.
        pre_bodies = set(
            r[0] for r in spoke_a.conn.execute("SELECT body FROM notes").fetchall()
        )
        wr = api.execute_signed_query(
            "INSERT INTO notes (body) VALUES (?)",
            ['hostapi-committed-note'],
        )
        assert isinstance(wr, HubWriteResult), type(wr)
        assert wr.status == 'committed', wr
        assert wr.seq is not None
        post_bodies = set(
            r[0] for r in spoke_a.conn.execute("SELECT body FROM notes").fetchall()
        )
        assert 'hostapi-committed-note' in post_bodies - pre_bodies
        print(f'  [OK] mutation committed (seq={wr.seq}); row on replica')

        # (d) Hub stopped → queued; outbox holds it; flush after restart commits.
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
        hub = None
        hub_thread = None
        time.sleep(0.15)

        qw = api.execute_signed_query(
            "INSERT INTO notes (body) VALUES (?)",
            ['hostapi-queued-note'],
        )
        assert isinstance(qw, HubWriteResult)
        assert qw.status == 'queued', qw
        assert qw.seq is None
        box = msync.list_outbox(spoke_a)
        assert any(
            r['status'] == 'pending'
            and 'hostapi-queued-note' in json.dumps(r['params'])
            for r in box
        ), box
        print(f'  [OK] hub down → HostAPI mutation queued; outbox holds it')

        hub = MSFHub(
            hub_dir2,
            hub_cert_path,
            hub_key_path,
            host='127.0.0.1',
            port=0,
            ca_cert_path=ca_cert_path,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if hub.httpd.server_port:
                break
            time.sleep(0.02)
        hub_url = hub.url
        # Flush with the new URL (manifest may still have old port; flush takes url).
        summary = msync.flush_outbox(
            spoke_a, hub_url, container_id,
            user_private, user_cert, 'sync_user',
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        assert summary['flushed'] >= 1, summary
        assert spoke_a.conn.execute(
            "SELECT COUNT(*) FROM notes WHERE body = ?",
            ['hostapi-queued-note'],
        ).fetchone()[0] == 1
        print(f'  [OK] flush after restart → committed; note on replica: {summary}')

        # ==================================================================
        # 17. msf.py headless: status-line builder + subscriber own-connection
        # ==================================================================
        print('\n=== 17. msf format_sync_status_line + subscriber own-connection ===')
        from mschf.msf import format_sync_status_line, _sync_subscriber_main

        # Status-line combinations (no network).
        assert format_sync_status_line({'homed': False}, True) is None
        assert format_sync_status_line(None, False) is None
        line = format_sync_status_line(
            {'homed': True, 'hub_cn': 'hub_svc', 'local_next_seq': 12,
             'outbox_pending': 3},
            connected=True,
        )
        assert line == 'SYNC: hub hub_svc — live · head 12 · 3 pending', line
        line = format_sync_status_line(
            {'homed': True, 'hub_cn': 'hub_svc', 'local_next_seq': 5,
             'outbox_pending': 0},
            connected=False,
        )
        assert line == 'SYNC: hub hub_svc — offline · head 5 · 0 pending', line
        line = format_sync_status_line(
            {'homed': True, 'hub_cn': 'hub_svc', 'local_next_seq': 1,
             'outbox_pending': 0},
            connected=False,
            has_hub_url=False,
        )
        assert line == 'SYNC: hub hub_svc — no url configured', line
        print('  [OK] format_sync_status_line combinations')

        # Subscriber start/stop against local hub; own connection.
        msync.pull_and_apply(
            spoke_a, hub_url, container_id,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        doc_conn_id = id(spoke_a.conn)
        stop_ev = threading.Event()
        state = threading.Thread(target=lambda: None)  # dummy for attrs
        state.connected = False
        state.last_applied_at = None
        state.storage_conn_id = None

        sub_thr = threading.Thread(
            target=_sync_subscriber_main,
            args=(
                spoke_a_path, hub_url, container_id, stop_ev, hub_cn,
                ca_cert_path, None, state, 1.0,  # short poll for the test
            ),
            daemon=True,
        )
        sub_thr.start()
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and not state.connected:
            time.sleep(0.1)
        assert state.connected, 'subscriber never reported connected'
        assert state.storage_conn_id is not None
        assert state.storage_conn_id != doc_conn_id, (
            'subscriber must open its own MSFStorage connection, not the '
            f'document connection (doc={doc_conn_id} sub={state.storage_conn_id})'
        )
        # Document connection still usable.
        n = spoke_a.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        assert n >= 1
        stop_ev.set()
        sub_thr.join(timeout=8)
        assert not sub_thr.is_alive(), 'subscriber did not stop'
        print(f'  [OK] subscriber connected with own conn '
              f'(doc={doc_conn_id} sub={state.storage_conn_id}); stopped cleanly')

        # ==================================================================
        # 18. dev_tracker CLI hub mode
        # ==================================================================
        print('\n=== 18. dev_tracker hub mode ===')
        import dev_tracker as tracker_mod

        # Author a minimal tracker container on a fresh hub.
        tr_hub_dir = tempfile.mkdtemp(prefix='mschf_tr_hub_')
        tmp_dirs.append(tr_hub_dir)
        tr_id = 'dev_tracker'
        tr_hub_msf = os.path.join(tr_hub_dir, f'{tr_id}.msf')

        # Provision agent identity files in a temp "project" dir for the CLI.
        tr_proj = tempfile.mkdtemp(prefix='mschf_tr_proj_')
        tmp_dirs.append(tr_proj)
        agent_cert, agent_key = generate_user_cert(
            'tr_agent', ca_cert_pem, ca_key_pem
        )
        admin_c, admin_k = generate_user_cert(
            'tr_admin', ca_cert_pem, ca_key_pem
        )
        # Write identities as plaintext keys (load_identity accepts plaintext).
        for cn, cert, key in (
            ('tr_admin', admin_c, admin_k),
            ('tr_agent', agent_cert, agent_key),
            ('admin', admin_c, admin_k),  # init always uses admin
        ):
            with open(os.path.join(tr_proj, f'{cn}.crt'), 'wb') as f:
                f.write(cert)
            with open(os.path.join(tr_proj, f'{cn}.key'), 'wb') as f:
                f.write(key)

        tr_db = MSFStorage(tr_hub_msf, ca_cert_path=ca_cert_path)
        tr_db.conn.execute(
            "CREATE TABLE IF NOT EXISTS dev_tasks ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, detail TEXT, "
            "status TEXT NOT NULL DEFAULT 'backlog' "
            "CHECK(status IN ('backlog','in_progress','done')), "
            "created_at TEXT DEFAULT (datetime('now')), created_by TEXT, "
            "updated_at TEXT DEFAULT (datetime('now')), updated_by TEXT, "
            "horizon TEXT)"
        )
        tr_db.conn.execute(tracker_mod.TASK_LINKS_DDL)
        tr_db.conn.commit()
        admin_priv = _load_key(admin_k)
        _signed_exec(
            tr_db, admin_c, admin_k,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['entry_point', 'main_app'],
            bootstrap=True,
        )
        for ddl in tracker_mod.AUDIT_TRIGGERS + tracker_mod.LINK_TRIGGERS + tracker_mod.VALIDATION_TRIGGERS:
            _signed_exec(tr_db, admin_c, admin_k, ddl, [])
        for level, target, role, perm in [
            ('database', '*', 'agent', 'read'),
            ('database', '*', 'agent', 'write'),
            ('object', 'dev_tasks', 'agent', 'read'),
            ('object', 'dev_tasks', 'agent', 'write'),
            ('object', 'task_links', 'agent', 'read'),
            ('object', 'task_links', 'agent', 'write'),
        ]:
            _signed_exec(
                tr_db, admin_c, admin_k,
                "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
                [level, target, role, perm],
            )
        _signed_exec(
            tr_db, admin_c, admin_k,
            "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
            ['cert:CN=tr_agent', 'agent'],
        )
        _signed_exec(
            tr_db, admin_c, admin_k,
            "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, ?)",
            ['seed hub task', 'from fixture', 'backlog'],
        )
        _signed_exec(
            tr_db, admin_c, admin_k,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_cn', 'hub_svc'],
        )
        tr_db.close()

        # Stop the notes hub; start tracker hub (reuse hub_svc cert).
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
        hub = None
        hub_thread = None

        tr_hub = MSFHub(
            tr_hub_dir, hub_cert_path, hub_key_path,
            host='127.0.0.1', port=0, ca_cert_path=ca_cert_path,
        )
        hub = tr_hub  # for finally cleanup
        hub_thread = threading.Thread(target=tr_hub.serve_forever, daemon=True)
        hub_thread.start()
        for _ in range(50):
            if tr_hub.httpd.server_port:
                break
            time.sleep(0.02)
        tr_hub_url = tr_hub.url
        msync.sign_and_submit(
            tr_hub_url, tr_id, admin_priv, admin_c,
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ['sync_hub_url', tr_hub_url],
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )

        # Bootstrap spoke replica into tr_proj as dev_tracker.msf
        tr_spoke_path = os.path.join(tr_proj, 'dev_tracker.msf')
        tr_spoke = msync.bootstrap(
            tr_hub_url, tr_id, tr_spoke_path,
            expected_hub_cn=hub_cn, ca_cert_path=ca_cert_path,
        )
        tr_spoke.close()
        tr_spoke = None

        # Point the CLI at this fixture.
        old_db = tracker_mod.DB_PATH
        old_proj = tracker_mod.PROJ_DIR
        old_cli = tracker_mod._CLI_IDENTITY
        tracker_mod.DB_PATH = tr_spoke_path
        tracker_mod.PROJ_DIR = tr_proj
        tracker_mod._CLI_IDENTITY = 'tr_agent'
        # Plaintext keys: load_identity tries passphrase then falls back to plaintext.

        import io
        from contextlib import redirect_stdout

        try:
            # add → committed + visible in list
            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_add('hub-mode task', 'via hub_write')
            out = buf.getvalue()
            assert 'committed' in out.lower() or 'Added backlog task' in out, out
            assert 'hub-mode task' in out or 'Added' in out
            print(f'  [OK] add → {out.strip()}')

            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_list()
            list_out = buf.getvalue()
            assert 'hub-mode task' in list_out, list_out
            print('  [OK] list shows hub-mode task')

            # Stop hub → add → queued
            try:
                tr_hub.shutdown()
            except Exception:
                pass
            try:
                tr_hub.server_close()
            except Exception:
                pass
            if hub_thread is not None:
                hub_thread.join(timeout=2)
            hub = None
            hub_thread = None
            time.sleep(0.15)

            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_add('offline task', 'queued while hub down')
            qout = buf.getvalue()
            assert 'queued' in qout.lower(), qout
            print(f'  [OK] hub down add → {qout.strip()}')

            # list offline works with [offline] note
            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_list()
            loff = buf.getvalue()
            assert '[offline]' in loff or 'hub-mode task' in loff, loff
            assert 'seed hub task' in loff or 'hub-mode task' in loff
            print('  [OK] list offline shows local data')

            # Restart hub + flush
            tr_hub = MSFHub(
                tr_hub_dir, hub_cert_path, hub_key_path,
                host='127.0.0.1', port=0, ca_cert_path=ca_cert_path,
            )
            hub = tr_hub
            hub_thread = threading.Thread(target=tr_hub.serve_forever, daemon=True)
            hub_thread.start()
            for _ in range(50):
                if tr_hub.httpd.server_port:
                    break
                time.sleep(0.02)
            tr_hub_url = tr_hub.url
            # Manifest still has old URL — patch spoke manifest via raw write of
            # sync_hub_url is blocked by homed guard; flush takes explicit URL
            # but cmd_flush reads from manifest. Update hub_url in spoke via
            # temporary escape hatch so flush / list pull work.
            prev_env = os.environ.get('MSCHF_ALLOW_LOCAL_WRITES')
            os.environ['MSCHF_ALLOW_LOCAL_WRITES'] = '1'
            try:
                fix = MSFStorage(tr_spoke_path, ca_cert_path=ca_cert_path)
                # Direct unsigned manifest update for test plumbing only.
                fix.conn.execute(
                    "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
                    ['sync_hub_url', tr_hub_url],
                )
                fix.conn.commit()
                fix.close()
            finally:
                if prev_env is None:
                    os.environ.pop('MSCHF_ALLOW_LOCAL_WRITES', None)
                else:
                    os.environ['MSCHF_ALLOW_LOCAL_WRITES'] = prev_env

            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_flush()
            fout = buf.getvalue()
            assert 'flushed=' in fout, fout
            print(f'  [OK] flush after restart → {fout.strip()}')

            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_list()
            assert 'offline task' in buf.getvalue()
            print('  [OK] offline task visible after flush')

            # init / update-app refuse on homed replica
            try:
                tracker_mod.cmd_update_app()
                raise AssertionError('update-app should refuse on homed replica')
            except SystemExit as e:
                assert 'homed' in str(e).lower() or 'hub' in str(e).lower(), e
                print(f'  [OK] update-app refuses on homed: {e}')

            # Unhomed fixture: classic list/add still works (byte-compatible path).
            unhomed_path = os.path.join(tr_proj, 'unhomed_tracker.msf')
            udb = MSFStorage(unhomed_path, ca_cert_path=ca_cert_path)
            udb.conn.execute(
                "CREATE TABLE IF NOT EXISTS dev_tasks ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, detail TEXT, "
                "status TEXT NOT NULL DEFAULT 'backlog' "
                "CHECK(status IN ('backlog','in_progress','done')), "
                "created_at TEXT DEFAULT (datetime('now')), created_by TEXT, "
                "updated_at TEXT DEFAULT (datetime('now')), updated_by TEXT, "
                "horizon TEXT)"
            )
            udb.conn.execute(tracker_mod.TASK_LINKS_DDL)
            udb.conn.commit()
            _signed_exec(
                udb, admin_c, admin_k,
                "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
                ['entry_point', 'main_app'],
                bootstrap=True,
            )
            for ddl in (
                tracker_mod.AUDIT_TRIGGERS
                + tracker_mod.LINK_TRIGGERS
                + tracker_mod.VALIDATION_TRIGGERS
            ):
                _signed_exec(udb, admin_c, admin_k, ddl, [])
            for level, target, role, perm in [
                ('database', '*', 'agent', 'read'),
                ('database', '*', 'agent', 'write'),
                ('object', 'dev_tasks', 'agent', 'read'),
                ('object', 'dev_tasks', 'agent', 'write'),
                ('object', 'task_links', 'agent', 'read'),
                ('object', 'task_links', 'agent', 'write'),
            ]:
                _signed_exec(
                    udb, admin_c, admin_k,
                    "INSERT INTO rbac_rules (level, target, role, permission) "
                    "VALUES (?, ?, ?, ?)",
                    [level, target, role, perm],
                )
            _signed_exec(
                udb, admin_c, admin_k,
                "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
                ['cert:CN=tr_agent', 'agent'],
            )
            _signed_exec(
                udb, admin_c, admin_k,
                "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, ?)",
                ['local only', 'unhomed', 'backlog'],
            )
            udb.close()

            tracker_mod.DB_PATH = unhomed_path
            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_add('unhomed add', 'still local signed')
            uout = buf.getvalue()
            # Unhomed: no committed/queued tag — classic message only.
            assert 'Added backlog task: unhomed add' in uout, uout
            assert 'committed' not in uout.lower()
            assert 'queued' not in uout.lower()
            buf = io.StringIO()
            with redirect_stdout(buf):
                tracker_mod.cmd_list()
            assert 'unhomed add' in buf.getvalue()
            assert 'local only' in buf.getvalue()
            print('  [OK] unhomed tracker: classic add/list unchanged')

        finally:
            tracker_mod.DB_PATH = old_db
            tracker_mod.PROJ_DIR = old_proj
            tracker_mod._CLI_IDENTITY = old_cli

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
