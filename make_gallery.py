"""Author widget_gallery.msf into the workspace, signed by the host admin identity.

Run once, then open widget_gallery.msf in the Workspace Manager (sign in as
admin) to browse every Toga widget available on this platform.

Usage: python make_gallery.py
"""
import os
import sys

PROJ_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(PROJ_DIR, 'src'))

from mschf.identity import Identity
from mschf.gallery import create_gallery_container

CA_CERT = os.path.join(PROJ_DIR, 'ca.crt')
ADMIN_CERT = os.path.join(PROJ_DIR, 'admin.crt')
DEST = os.path.join(PROJ_DIR, 'widget_gallery.msf')
PASSPHRASE = os.environ.get('MSCHF_ADMIN_PASSPHRASE', 'changeit')


def main():
    if not (os.path.isfile(ADMIN_CERT) and os.path.isfile(CA_CERT)):
        sys.exit("admin.crt/ca.crt not found — run the app once ('briefcase dev') to generate them.")
    identity = Identity.load(ADMIN_CERT, CA_CERT)
    if not identity.is_valid:
        sys.exit("admin identity is not valid / not signed by the Root CA.")
    identity.key_passphrase = PASSPHRASE

    if os.path.exists(DEST):
        os.remove(DEST)
    create_gallery_container(DEST, identity, CA_CERT)
    print(f"Created {DEST}. Open it in the Workspace Manager (sign in as admin).")


if __name__ == '__main__':
    main()
