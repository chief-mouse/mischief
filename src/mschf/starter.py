"""Authoring for the "Getting Started" starter micro-app.

``create_starter_container(dest, identity, ca_cert_path)`` builds a small but
fully real ``.msf`` signed by the active identity: bootstrap claims container
admin for that identity, audit triggers are installed via signed DDL (so the
ledger fully explains the container and ``replay_audit`` passes), a few
welcome notes are seeded, and the UI is a signed declarative ``ui_spec``
(JSON widget tree — no dill / pickled bytecode).
"""
import json
import os

from mschf.storage import MSFStorage, canonical_payload

# Pure-data UI for the starter (box/label/table/text_input/button/status).
# No multiline widget in the declarative vocabulary: orientation copy is
# short labels; notes are a bound table rather than a text dump.
STARTER_UI_SPEC = {
    "type": "box",
    "direction": "column",
    "margin": 16,
    "children": [
        {
            "type": "label",
            "text": "Welcome to Mischief",
            "font_size": 20,
            "bold": True,
            "margin": 2,
        },
        {
            "type": "box",
            "direction": "row",
            "margin": 10,
            "children": [
                {
                    "type": "label",
                    "text": "Signed in as ",
                    "font_size": 10,
                    "color": "#666666",
                },
                {
                    "type": "label",
                    "text_from": {"user": "common_name"},
                    "font_size": 10,
                    "color": "#666666",
                },
            ],
        },
        {
            "type": "label",
            "text": (
                "This window is a micro-app running from a .msf container — a "
                "single SQLite file holding this app's data, its access rules, "
                "and a ledger of cryptographically signed transactions."
            ),
            "font_size": 10,
            "margin": 4,
        },
        {
            "type": "label",
            "text": (
                "Everything you do here is signed with your identity's private "
                "key and recorded in the ledger. Notes added below become signed "
                "transactions; the signer column is stamped by the database "
                "engine from your verified certificate — the app cannot forge it."
            ),
            "font_size": 10,
            "margin": 10,
        },
        {
            "type": "table",
            "id": "notes_table",
            "headings": ["Id", "Body", "Created", "By"],
            "query": {
                "sql": (
                    "SELECT id, body, created_at, created_by "
                    "FROM notes ORDER BY id DESC"
                ),
                "params": [],
            },
            "columns": [0, 1, 2, 3],
            "flex": 1,
            "margin": 4,
        },
        {
            "type": "box",
            "direction": "row",
            "children": [
                {
                    "type": "text_input",
                    "id": "note_body",
                    "placeholder": (
                        "Write a note - it will be signed with your key..."
                    ),
                    "flex": 1,
                    "margin": 4,
                },
                {
                    "type": "button",
                    "text": "+ Add Signed Note",
                    "margin": 4,
                    "action": {
                        "kind": "exec",
                        "sql": "INSERT INTO notes (body) VALUES (?)",
                        "args": [{"input": "note_body"}],
                        "then_refresh": ["notes_table"],
                        "status": "status_line",
                    },
                },
            ],
        },
        {
            "type": "status",
            "id": "status_line",
            "margin": 6,
            "font_size": 10,
        },
    ],
}

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


def _validate_starter_spec(spec):
    """Structural validation of the widget tree without importing toga.

    Uses declarative's action/id cross-ref checks (``collect_ids``) with a
    stub toga stand-in so authoring stays headless-safe.
    """
    from types import SimpleNamespace

    from mschf.declarative import _RenderContext

    fake_toga = SimpleNamespace(style=SimpleNamespace(Pack=object))
    ctx = _RenderContext(fake_toga, host_api=None)
    ctx.collect_ids(spec)
    return spec


def create_starter_container(dest_path, identity, ca_cert_path):
    """Author the starter .msf at dest_path, signed by ``identity``.

    ``identity`` is a valid, unlocked mschf Identity (cert_pem, key_path, and
    key_passphrase for an encrypted key). The identity becomes the container's
    admin via the deliberate bootstrap path. UI is a signed ``ui_spec`` only —
    no ``source_code`` / dill blob.
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

    # Fail closed at authoring time if the baked-in spec is ever malformed.
    _validate_starter_spec(STARTER_UI_SPEC)

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
        db.bootstrap_admin(
            q, ['name', 'Getting Started'],
            sign(q, ['name', 'Getting Started']), cert_pem)

        for ddl in NOTES_TRIGGERS:
            db.execute_signed(ddl, [], sign(ddl, []), cert_pem)

        q = "INSERT INTO notes (body) VALUES (?)"
        for body in SEED_NOTES:
            db.execute_signed(q, [body], sign(q, [body]), cert_pem)

        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        ui_json = json.dumps(STARTER_UI_SPEC, sort_keys=True)
        db.set_manifest_item('ui_spec', ui_json, sign(q, ['ui_spec', ui_json]), cert_pem)

        for key, value in (
            ('version', '1.0'),
            ('description', 'Starter micro-app: signed notes on the Mischief platform.'),
        ):
            db.set_manifest_item(key, value, sign(q, [key, value]), cert_pem)
    finally:
        db.close()
    return dest_path
