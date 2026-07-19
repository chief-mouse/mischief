"""Widget-gallery authoring test (headless, CI-safe — no toga at runtime).

create_gallery_container() is what make_gallery.py / the GUI would call. Verify
the authored container is a valid, signed, self-explaining micro-app. The
actual widget rendering is verified separately via the sandbox on Windows
(scripts render check), since toga's backend is required for that.
"""
import sys
import os
sys.path.insert(0, os.path.abspath('src'))

from mschf.storage import MSFStorage
from mschf.identity import Identity
from mschf.gallery import create_gallery_container, GALLERY_SOURCE
from mschf.audit import replay_audit, format_report
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert


def run():
    dest = 'test_gallery.msf'
    for f in (dest, 'gallery_admin.crt', 'gallery_admin.key'):
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

    cert_pem, key_pem = generate_user_cert('gallery_admin', ca_cert_pem, ca_key_pem)
    with open('gallery_admin.crt', 'wb') as f:
        f.write(cert_pem)
    with open('gallery_admin.key', 'wb') as f:
        f.write(key_pem)

    identity = Identity.load('gallery_admin.crt', ca_cert_path)
    assert identity.is_valid

    print("--- Authoring gallery container ---")
    create_gallery_container(dest, identity, ca_cert_path)

    db = MSFStorage(dest, ca_cert_path=ca_cert_path)

    assert db.get_manifest_item('entry_point') == 'main_app'
    assert db.get_manifest_item('name') == 'Widget Gallery'
    print("  [OK] manifest wired")

    status = db.get_code_signature_status('main_app')
    assert status['verified'], f"code signature not verified: {status['error']}"
    assert status['signer'] == 'gallery_admin'
    print(f"  [OK] code blob signed and verified (signer={status['signer']})")

    code_func = db.get_code('main_app')
    assert callable(code_func)
    print("  [OK] code blob unpickles to a callable")

    # Every widget the gallery claims to demo should be referenced in the source.
    widgets = [
        "Label", "TextInput", "MultilineTextInput", "PasswordInput", "NumberInput",
        "Slider", "Switch", "Selection", "DateInput", "TimeInput", "Button",
        "ProgressBar", "ActivityIndicator", "Divider", "Table", "DetailedList",
        "Tree", "ImageView", "Canvas", "WebView", "MapView", "SplitContainer",
        "ScrollContainer", "OptionContainer", "Box",
    ]
    missing = [w for w in widgets if f"toga.{w}(" not in GALLERY_SOURCE]
    assert not missing, f"gallery source is missing widgets: {missing}"
    print(f"  [OK] all {len(widgets)} widgets referenced in the gallery source")

    print("--- Replay audit ---")
    report = replay_audit(db)
    print(format_report(report))
    assert report['ok'], "gallery container must be fully explained by its ledger"

    db.close()
    for f in (dest, 'gallery_admin.crt', 'gallery_admin.key'):
        os.remove(f)
    print("\n==========================================")
    print("ALL WIDGET-GALLERY TESTS PASSED")
    print("==========================================")


if __name__ == '__main__':
    run()
