"""Identity Directory — a signed ``.msf`` phonebook of org identities.

``create_directory_container`` authors a container that distributes public
certificates and metadata so admins can grant roles to identities from other
machines without manual CN/cert exchange. Helpers ``register_identity``,
``set_identity_status``, and ``lookup`` manage the phonebook after authoring.

HARD RULE: the directory is NEVER a trust anchor. Verification everywhere stays
rooted in the host trust store (``mschf.trust``); this container only carries
public certificates and metadata. Nothing in the platform may consult it to
decide whether a signature is trusted.
"""
import hashlib
import os

import dill
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from mschf.storage import MSFStorage, canonical_payload
from mschf.trust import resolve_trust_anchors, is_cert_trusted

# ---------------------------------------------------------------------------
# UI source — compiled into a non-importable namespace so dill pickles BY VALUE
# ---------------------------------------------------------------------------
DIRECTORY_SOURCE = '''
def main_app(toga, host_api):
    from toga.style import Pack as P

    cn = "Unknown"
    cert_pem = ""
    try:
        user = host_api.get_current_user()
        cn = user.get("common_name", "Unknown")
        cert_pem = user.get("certificate_pem", "")
    except Exception:
        pass

    can_read = False
    if cert_pem:
        try:
            can_read = host_api.has_database_permission("read", cert_pem)
        except Exception:
            can_read = False

    if not can_read:
        denied = toga.Box(style=P(direction="column", margin=20))
        denied.add(toga.Label(
            "ACCESS DENIED",
            style=P(font_size=20, font_weight="bold", color="red", margin_bottom=10),
        ))
        denied.add(toga.Label(
            f"Identity cert:CN={cn} has no database-level read permission "
            "on the Identity Directory.",
            style=P(),
        ))
        return denied

    board = toga.Box(id="directory_board", style=P(direction="column", margin=16, flex=1))
    board.add(toga.Label(
        "Identity Directory",
        style=P(font_size=20, font_weight="bold", margin_bottom=2),
    ))
    board.add(toga.Label(
        f"Signed in as {cn} — public certificates for org role grants.",
        style=P(font_style="italic", font_size=10, color="#666666", margin_bottom=10),
    ))

    table = toga.Table(
        headings=["CN", "Org", "Status", "Added by"],
        accessors=("cn", "org", "status", "added_by"),
        data=[],
        style=P(flex=1, margin_bottom=8),
    )
    board.add(table)
    status_label = toga.Label("Ready.", style=P(font_size=10, font_style="italic", margin_top=4))
    board.add(status_label)

    def refresh(widget=None):
        try:
            cursor = host_api.execute_signed_query(
                "SELECT cn, org, status, added_by FROM identities "
                "ORDER BY cn COLLATE NOCASE"
            )
            rows = cursor.fetchall()
            who = lambda w: (w or "?").replace("cert:CN=", "")
            table.data = [
                (r[0] or "", r[1] or "", r[2] or "", who(r[3]))
                for r in rows
            ]
            status_label.text = f"{len(rows)} identit{'y' if len(rows) == 1 else 'ies'}."
        except Exception as e:
            status_label.text = f"Query blocked: {e}"

    board.add(toga.Button("Refresh", on_press=refresh))
    try:
        refresh()
    except Exception:
        pass
    return board
'''

# Engine-enforced attribution (dev_tracker AUDIT_TRIGGERS pattern).
# recursive_triggers is off, so the insert trigger's own UPDATE does not re-fire
# other triggers — stamp both added_* and updated_* on insert.
IDENTITIES_TRIGGERS = [
    """CREATE TRIGGER trg_identities_insert_audit AFTER INSERT ON identities
       BEGIN
         UPDATE identities SET
           added_at = COALESCE(NEW.added_at, datetime('now')),
           updated_at = COALESCE(NEW.updated_at, datetime('now')),
           added_by = COALESCE(current_signer(), 'unsigned'),
           updated_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_identities_update_audit AFTER UPDATE ON identities
       BEGIN
         UPDATE identities SET
           updated_at = datetime('now'),
           updated_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_identities_added_immutable BEFORE UPDATE ON identities
       WHEN OLD.added_by IS NOT NULL
        AND (NEW.added_at IS NOT OLD.added_at OR NEW.added_by IS NOT OLD.added_by)
       BEGIN
         SELECT RAISE(ABORT, 'added_at/added_by are immutable audit fields');
       END""",
]

IDENTITIES_SCHEMA = (
    "CREATE TABLE identities ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "cn TEXT NOT NULL, "
    "fingerprint TEXT NOT NULL UNIQUE, "
    "cert_pem TEXT NOT NULL, "
    "display_name TEXT, "
    "org TEXT, "
    "status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')), "
    "added_at TEXT DEFAULT (datetime('now')), "
    "added_by TEXT, "
    "updated_at TEXT DEFAULT (datetime('now')), "
    "updated_by TEXT)"
)

# Seeded RBAC role definitions (signed at authoring by the container admin).
DIRECTORY_RBAC_RULES = [
    # directory_admin: full database + object write on identities
    ("database", "*", "directory_admin", "read"),
    ("database", "*", "directory_admin", "write"),
    ("object", "identities", "directory_admin", "read"),
    ("object", "identities", "directory_admin", "write"),
    # member: read-only phonebook
    ("database", "*", "member", "read"),
    ("object", "identities", "member", "read"),
]


def _as_bytes(pem):
    if isinstance(pem, str):
        return pem.encode("utf-8")
    return pem


def _as_str(pem):
    if isinstance(pem, bytes):
        return pem.decode("utf-8")
    return pem


def cert_fingerprint(cert_pem):
    """SHA-256 hex of the certificate's DER encoding."""
    cert = x509.load_pem_x509_certificate(_as_bytes(cert_pem), default_backend())
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def cert_cn(cert_pem):
    """Common Name from a PEM certificate."""
    cert = x509.load_pem_x509_certificate(_as_bytes(cert_pem), default_backend())
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _directory_callable():
    """Compile main_app from source in a non-importable namespace so dill
    pickles it by value (the container must carry its own code)."""
    ns = {}
    exec(DIRECTORY_SOURCE, ns)
    return ns["main_app"]


def _sign(db, private_key, query, params):
    """Sign against the container's current chain head (call immediately before execute)."""
    next_seq, prev_hash = db.get_chain_head()
    payload = canonical_payload(query, params, next_seq, prev_hash)
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def _load_identity_key(identity):
    with open(identity.key_path, "rb") as f:
        key_pem = f.read()
    password = identity.key_passphrase.encode("utf-8") if identity.key_passphrase else None
    return serialization.load_pem_private_key(key_pem, password=password)


def create_directory_container(dest_path, identity, ca_cert_path=None, trust_dir=None):
    """Author an Identity Directory ``.msf`` at *dest_path*, signed by *identity*.

    *identity* is a valid, unlocked mschf ``Identity`` (cert_pem, key_path, and
    key_passphrase when the key is encrypted). That identity becomes the
    container's admin via the deliberate bootstrap path.

    Layout (mirrors ``starter.py``): unsigned table schema → signed bootstrap
    + trigger DDL + RBAC seed + manifest + signed code blob. The result must
    pass ``replay_audit`` end-to-end.
    """
    private_key = _load_identity_key(identity)
    cert_pem = identity.cert_pem

    if os.path.exists(dest_path):
        raise FileExistsError(f"{dest_path} already exists — not overwriting.")

    db = MSFStorage(dest_path, ca_cert_path=ca_cert_path, trust_dir=trust_dir)

    def sign(query, params):
        return _sign(db, private_key, query, params)

    try:
        # Table schema is unsigned authoring (pre-seeded by replay audits).
        db.conn.execute(IDENTITIES_SCHEMA)
        db.conn.commit()

        # First signed write claims admin for the creating identity.
        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        db.bootstrap_admin(
            q, ["entry_point", "main_app"],
            sign(q, ["entry_point", "main_app"]),
            cert_pem,
        )

        for ddl in IDENTITIES_TRIGGERS:
            db.execute_signed(ddl, [], sign(ddl, []), cert_pem)

        for level, target, role, perm in DIRECTORY_RBAC_RULES:
            q = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
            params = [level, target, role, perm]
            db.add_rbac_rule(level, target, role, perm, sign(q, params), cert_pem)

        code_func = _directory_callable()
        pickled = dill.dumps(code_func)
        q = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
        db.store_code("main_app", code_func, sign(q, ["main_app", pickled]), cert_pem)

        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        for key, value in (
            ("name", "Identity Directory"),
            ("version", "1.0"),
            (
                "description",
                "Org phonebook of public identity certificates for cross-machine role grants. "
                "Not a trust anchor — verification stays in the host trust store.",
            ),
        ):
            db.set_manifest_item(key, value, sign(q, [key, value]), cert_pem)
    finally:
        db.close()
    return dest_path


def register_identity(
    storage,
    signer_cert_pem,
    signer_private_key,
    cert_pem,
    display_name=None,
    org=None,
):
    """Signed-INSERT a certificate into the directory after local trust checks.

    Parses *cert_pem* (rejects non-certs), computes its DER fingerprint, and
    verifies the certificate chains to a host trust anchor using the storage's
    trust config (``ca_cert_path`` / ``trust_dir``). Untrusted certs are refused
    so the phonebook does not accumulate unverifiable junk.

    Duplicate fingerprints surface as a clean ``ValueError`` (UNIQUE constraint);
    failed attempts leave the ledger unchanged (transaction rollback).
    """
    try:
        cert = x509.load_pem_x509_certificate(_as_bytes(cert_pem), default_backend())
    except Exception as e:
        raise ValueError(f"Not a valid PEM certificate: {e}") from e

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    fp = hashlib.sha256(
        cert.public_bytes(encoding=serialization.Encoding.DER)
    ).hexdigest()
    cert_text = _as_str(cert_pem)

    anchors = resolve_trust_anchors(storage._ca_cert_path_arg, storage.trust_dir)
    if not is_cert_trusted(cert_pem, anchors):
        raise PermissionError(
            "Certificate is not trusted by the local trust store "
            "(directory is not a trust anchor; register only host/org-CA certs)."
        )

    query = (
        "INSERT INTO identities (cn, fingerprint, cert_pem, display_name, org) "
        "VALUES (?, ?, ?, ?, ?)"
    )
    params = [cn, fp, cert_text, display_name, org]
    signature = _sign(storage, signer_private_key, query, params)
    try:
        storage.execute_signed(query, params, signature, signer_cert_pem)
    except Exception as e:
        # UNIQUE on fingerprint — surface a clean error; execute_signed already
        # rolled back so the ledger is unchanged.
        msg = str(e).lower()
        if "unique" in msg or "fingerprint" in msg:
            raise ValueError(
                f"Identity with fingerprint {fp} is already registered"
            ) from e
        raise
    return fp


def set_identity_status(storage, signer_cert_pem, signer_private_key, fingerprint, status):
    """Signed-UPDATE an identity's status to ``active`` or ``revoked`` only."""
    if status not in ("active", "revoked"):
        raise ValueError(f"Invalid status {status!r}; must be 'active' or 'revoked'")

    query = "UPDATE identities SET status = ? WHERE fingerprint = ?"
    params = [status, fingerprint]
    signature = _sign(storage, signer_private_key, query, params)
    storage.execute_signed(query, params, signature, signer_cert_pem)


def lookup(storage, cn=None, org=None, status="active"):
    """Plain (unsigned) read of directory rows matching optional filters.

    Returns a list of dicts with keys matching the ``identities`` columns.

    Unsigned reads are fine here: the phonebook is public metadata (CNs, public
    certs, org labels). Signed reads still exist for audit trails via
    ``execute_signed`` / HostAPI when a caller wants ledgered access; they are
    not required for correct directory consumption. Trust decisions never
    consult this table — only the host trust store does.
    """
    clauses = []
    params = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if cn is not None:
        clauses.append("cn = ?")
        params.append(cn)
    if org is not None:
        clauses.append("org = ?")
        params.append(org)

    sql = (
        "SELECT id, cn, fingerprint, cert_pem, display_name, org, status, "
        "added_at, added_by, updated_at, updated_by FROM identities"
    )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY cn COLLATE NOCASE"

    cursor = storage.conn.execute(sql, params)
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]
