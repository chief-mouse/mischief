"""Authoring for the "Getting Started" starter micro-app.

``create_starter_container(dest, identity, ca_cert_path)`` builds a small but
fully real ``.msf`` signed by the active identity: bootstrap claims container
admin for that identity, audit triggers are installed via signed DDL (so the
ledger fully explains the container and ``replay_audit`` passes), a few
welcome notes are seeded, and the UI code is deployed as a signed blob.

The UI source lives in ``STARTER_SOURCE`` and is compiled with ``exec`` into
an anonymous namespace before pickling: dill serializes importable-module
functions by reference, but a function born outside any importable module is
pickled BY VALUE — so the container carries its own code, like any micro-app
authored elsewhere.
"""
import os

import dill

from mschf.storage import MSFStorage, canonical_payload

STARTER_SOURCE = '''
def starter_app(toga, host_api):
    from toga.style import Pack as P

    cn = "Unknown"
    cert_pem = ""
    try:
        user = host_api.get_current_user()
        cn = user.get("common_name", "Unknown")
        cert_pem = user.get("certificate_pem", "")
    except Exception:
        pass

    board = toga.Box(id='starter_board', style=P(direction='column', margin=16))
    board.add(toga.Label("Welcome to Mischief", style=P(font_size=20, font_weight='bold', margin_bottom=2)))
    board.add(toga.Label(f"Signed in as {cn}", style=P(font_style='italic', font_size=10, color='#666666', margin_bottom=10)))

    intro = toga.MultilineTextInput(readonly=True, style=P(height=104, font_size=10, margin_bottom=10))
    intro.value = (
        "This window is a micro-app running from a .msf container - a single SQLite "
        "file holding this app's code, its data, its access rules, and a ledger of "
        "cryptographically signed transactions.\\n\\n"
        "Everything you do here is signed with your identity's private key and "
        "recorded in the ledger. The note you add below becomes a signed transaction, "
        "and the signer shown beneath each note is stamped by the database engine "
        "from your verified certificate - the app cannot forge it."
    )
    board.add(intro)

    notes_view = toga.MultilineTextInput(readonly=True, style=P(flex=1, font_size=10, margin_bottom=8))
    status_label = toga.Label("", style=P(font_size=10, font_style='italic', margin_top=6))

    def refresh(widget=None):
        try:
            cursor = host_api.execute_signed_query(
                "SELECT id, body, created_at, created_by FROM notes ORDER BY id DESC")
            rows = cursor.fetchall()
            notes_view.value = "\\n".join(
                f"#{r[0]}  {r[1]}\\n      - {(r[3] or '?').replace('cert:CN=', '')} at {r[2]}"
                for r in rows) or "No notes yet."
            status_label.text = f"{len(rows)} signed note(s) in the ledger."
        except Exception as e:
            notes_view.value = f"Query blocked: {e}"

    entry = toga.Box(style=P(direction='row'))
    note_input = toga.TextInput(placeholder="Write a note - it will be signed with your key...", style=P(flex=1, margin_right=8))

    def add_note(widget):
        body = (note_input.value or "").strip()
        if not body:
            status_label.text = "Type a note first."
            return
        try:
            host_api.execute_signed_query("INSERT INTO notes (body) VALUES (?)", [body])
            note_input.value = ""
            refresh()
        except Exception as e:
            status_label.text = f"Blocked by RBAC: {e}"

    note_input.on_confirm = add_note
    entry.add(note_input)
    entry.add(toga.Button("+ Add Signed Note", on_press=add_note))
    board.add(entry)
    board.add(status_label)
    board.add(notes_view)

    try:
        refresh()
    except Exception:
        pass

    return board
'''

# Engine-enforced attribution, same pattern as dev_tracker.py's AUDIT_TRIGGERS
# (see that file for the full canonical set including the immutability guard).
NOTES_TRIGGERS = [
    """CREATE TRIGGER trg_notes_insert_audit AFTER INSERT ON notes
       BEGIN
         UPDATE notes SET
           created_at = COALESCE(NEW.created_at, datetime('now')),
           created_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
]

SEED_NOTES = [
    "Notes added here are signed transactions - check the container's ledger.",
    "Open the Admin Guide to learn about roles, RBAC rules, and signed deployments.",
    "This container was created and signed on this machine, by the identity shown above.",
]


def _starter_callable():
    """Compile starter_app from source in a non-importable namespace so dill
    pickles it by value (the container must carry its own code)."""
    ns = {}
    exec(STARTER_SOURCE, ns)
    return ns['starter_app']


def create_starter_container(dest_path, identity, ca_cert_path):
    """Author the starter .msf at dest_path, signed by ``identity``.

    ``identity`` is a valid, unlocked mschf Identity (cert_pem, key_path, and
    key_passphrase for an encrypted key). The identity becomes the container's
    admin via the deliberate bootstrap path.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(identity.key_path, 'rb') as f:
        key_pem = f.read()
    password = identity.key_passphrase.encode('utf-8') if identity.key_passphrase else None
    private_key = load_pem_private_key(key_pem, password=password)
    cert_pem = identity.cert_pem

    if os.path.exists(dest_path):
        raise FileExistsError(f"{dest_path} already exists — not overwriting.")

    db = MSFStorage(dest_path, ca_cert_path=ca_cert_path)

    def sign(query, params):
        # Each signature commits to the ledger's current chain head + container.
        next_seq, prev_hash = db.get_chain_head()
        payload = canonical_payload(
            query, params, next_seq, prev_hash, db.container_uid)
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    try:
        # Table schema is unsigned authoring (pre-seeded by replay audits).
        db.conn.execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL, "
            "created_at TEXT DEFAULT (datetime('now')), created_by TEXT)")
        db.conn.commit()

        # First signed write claims admin for the creating identity (opt-in
        # bootstrap); everything after is a plain ledgered transaction.
        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        db.bootstrap_admin(q, ['entry_point', 'main_app'], sign(q, ['entry_point', 'main_app']), cert_pem)

        for ddl in NOTES_TRIGGERS:
            db.execute_signed(ddl, [], sign(ddl, []), cert_pem)

        q = "INSERT INTO notes (body) VALUES (?)"
        for body in SEED_NOTES:
            db.execute_signed(q, [body], sign(q, [body]), cert_pem)

        code_func = _starter_callable()
        pickled = dill.dumps(code_func)
        q = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
        db.store_code('main_app', code_func, sign(q, ['main_app', pickled]), cert_pem)

        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        for key, value in (('name', 'Getting Started'),
                           ('version', '1.0'),
                           ('description', 'Starter micro-app: signed notes on the Mischief platform.')):
            db.set_manifest_item(key, value, sign(q, [key, value]), cert_pem)
    finally:
        db.close()
    return dest_path
