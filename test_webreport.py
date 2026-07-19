"""Signed web-report authoring test (headless, CI-safe — no toga at runtime).

Verifies the container authors/signs/audits cleanly AND that the security
properties of the WebView renderer are actually present in the signed source:
a strict CSP with connect-src 'none', no remote script/style sources (no CDN),
and navigation denial. The live CSP-blocks-fetch behavior is verified visually
by rendering the container through the sandbox on Windows.
"""
import sys
import os
sys.path.insert(0, os.path.abspath('src'))

from mschf.storage import MSFStorage
from mschf.identity import Identity
from mschf.webreport import create_webreport_container, WEBREPORT_SOURCE, SEED_METRICS
from mschf.audit import replay_audit, format_report
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert


def run():
    dest = 'test_webreport.msf'
    for f in (dest, 'webreport_admin.crt', 'webreport_admin.key'):
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

    cert_pem, key_pem = generate_user_cert('webreport_admin', ca_cert_pem, ca_key_pem)
    with open('webreport_admin.crt', 'wb') as f:
        f.write(cert_pem)
    with open('webreport_admin.key', 'wb') as f:
        f.write(key_pem)

    identity = Identity.load('webreport_admin.crt', ca_cert_path)
    assert identity.is_valid

    print("--- Authoring web-report container ---")
    create_webreport_container(dest, identity, ca_cert_path)

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)
    assert db.get_manifest_item('entry_point') == 'main_app'
    assert db.get_manifest_item('name') == 'Signed Web Report'
    print("  [OK] manifest wired")

    status = db.get_code_signature_status('main_app')
    assert status['verified'], f"code signature not verified: {status['error']}"
    assert status['signer'] == 'webreport_admin'
    print(f"  [OK] code blob signed and verified (signer={status['signer']})")

    rows = db.conn.execute("SELECT label, value FROM metrics ORDER BY id").fetchall()
    assert [(r[0], r[1]) for r in rows] == SEED_METRICS
    print(f"  [OK] {len(rows)} metric rows seeded (chart reads them via signed query)")

    print("--- Security properties present in the signed renderer ---")
    src = WEBREPORT_SOURCE
    assert "Content-Security-Policy" in src, "missing CSP"
    assert "connect-src 'none'" in src, "CSP must block fetch/XHR (connect-src 'none')"
    assert "default-src 'none'" in src, "CSP must default-deny"
    assert "on_navigation_starting" in src, "navigation must be denied"
    # No remote code/resources: only inline scripts, no CDN/http(s) src=
    assert "https://unpkg" not in src and "cdn." not in src, "renderer must bundle inline, no CDN"
    assert 'src="http' not in src and "src='http" not in src, "no remote <script>/<img> src"
    assert "fetch(" in src, "self-test should attempt a fetch to prove CSP blocks it"
    print("  [OK] strict CSP (default-src/connect-src 'none'), no remote code, nav denied, fetch self-test present")

    print("--- Replay audit ---")
    report = replay_audit(db)
    print(format_report(report))
    assert report['ok'], "web-report container must be fully explained by its ledger"

    db.close()
    for f in (dest, 'webreport_admin.crt', 'webreport_admin.key'):
        os.remove(f)
    print("\n==========================================")
    print("ALL WEB-REPORT TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
