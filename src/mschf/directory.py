"""Identity Directory — a signed ``.msf`` phonebook of org identities.

``create_directory_container`` authors a container that distributes public
certificates and metadata so admins can grant roles to identities from other
machines without manual CN/cert exchange. Helpers ``register_identity``,
``set_identity_status``, and ``lookup`` manage the phonebook after authoring.
Owner→agent attestations (``attest_agent`` / ``verify_attestation``) are
authorization evidence only — they never change authorship and never
participate in platform signature verification.

HARD RULE: the directory is NEVER a trust anchor. Verification everywhere stays
rooted in the host trust store (``mschf.trust``); this container only carries
public certificates and metadata. Attestations are distributed metadata:
nothing in ``storage.py`` signature verification, ``trust.py`` anchor
resolution, or RBAC enforcement may consult them. An attestation's validity
is checked only by the explicit ``verify_attestation`` API against the host
trust store.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone

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

# Owner→agent attestation rows. No UNIQUE on (agent_fp, owner_fp): a re-attest
# after revoke INSERTs a fresh row; consumers treat the newest active row as
# authoritative ("newest active row wins").
AGENT_ATTESTATIONS_SCHEMA = (
    "CREATE TABLE agent_attestations ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "agent_cn TEXT NOT NULL, "
    "agent_fingerprint TEXT NOT NULL, "
    "owner_cn TEXT NOT NULL, "
    "owner_fingerprint TEXT NOT NULL, "
    "conditions TEXT NOT NULL DEFAULT '', "
    "expires_at TEXT, "
    "signature TEXT NOT NULL, "
    "status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')), "
    "added_at TEXT DEFAULT (datetime('now')), "
    "added_by TEXT, "
    "updated_at TEXT DEFAULT (datetime('now')), "
    "updated_by TEXT)"
)

# Mirror of admin / directory_admin identities for engine-level status gating.
# Why not subselect user_roles directly in the status trigger? The host
# authorizer denies non-admin SQLITE_READ on system tables (including
# user_roles) at statement-prepare time — even when the subselect is behind a
# WHEN / short-circuit that would not run for an owner. That would refuse
# legitimate owner-signed status changes. attestation_authz is a non-system
# table members can read; mirror triggers keep it in sync with user_roles.
ATTESTATION_AUTHZ_SCHEMA = (
    "CREATE TABLE attestation_authz ("
    "identity TEXT PRIMARY KEY NOT NULL)"
)

# Trigger bodies deliberately avoid a whitespace-separated ``FROM table``
# token: storage._parse_sql_query classifies any statement containing
# ``FROM <ident>`` as a read (via a body-wide search), and replay_audit
# skips reads — which would drop these CREATE TRIGGER rows from the
# shadow and leave attestation_authz out of sync. ``FROM"table"`` is
# valid SQLite and does not match that regex; VALUES-only inserts need
# no FROM at all.
ATTESTATION_AUTHZ_TRIGGERS = [
    """CREATE TRIGGER trg_attestation_authz_ins AFTER INSERT ON user_roles
       WHEN NEW.role IN ('admin', 'directory_admin')
       BEGIN
         INSERT OR IGNORE INTO attestation_authz (identity) VALUES (NEW.identity);
       END""",
    """CREATE TRIGGER trg_attestation_authz_del AFTER DELETE ON user_roles
       BEGIN
         DELETE FROM"attestation_authz" WHERE identity = OLD.identity;
       END""",
    # Single UPDATE trigger: sibling AFTER UPDATE triggers have undefined
    # firing order in SQLite, so a separate unconditional DELETE + conditional
    # INSERT could leave the mirror empty after a role promotion (or even a
    # no-op admin→admin UPDATE). Statements inside one trigger body run in
    # order. Two DELETEs cover an UPDATE that renames identity itself.
    # INSERT ... SELECT ... WHERE (no FROM) keeps the replay-regex dodge
    # intact (see comment above ATTESTATION_AUTHZ_TRIGGERS).
    """CREATE TRIGGER trg_attestation_authz_upd AFTER UPDATE ON user_roles
       BEGIN
         DELETE FROM"attestation_authz" WHERE identity = OLD.identity;
         DELETE FROM"attestation_authz" WHERE identity = NEW.identity;
         INSERT OR IGNORE INTO attestation_authz (identity)
           SELECT NEW.identity WHERE NEW.role IN ('admin', 'directory_admin');
       END""",
]

AGENT_ATTESTATIONS_TRIGGERS = [
    """CREATE TRIGGER trg_agent_attestations_insert_audit AFTER INSERT ON agent_attestations
       BEGIN
         UPDATE agent_attestations SET
           added_at = COALESCE(NEW.added_at, datetime('now')),
           updated_at = COALESCE(NEW.updated_at, datetime('now')),
           added_by = COALESCE(current_signer(), 'unsigned'),
           updated_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_agent_attestations_update_audit AFTER UPDATE ON agent_attestations
       BEGIN
         UPDATE agent_attestations SET
           updated_at = datetime('now'),
           updated_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_agent_attestations_added_immutable BEFORE UPDATE ON agent_attestations
       WHEN OLD.added_by IS NOT NULL
        AND (NEW.added_at IS NOT OLD.added_at OR NEW.added_by IS NOT OLD.added_by)
       BEGIN
         SELECT RAISE(ABORT, 'added_at/added_by are immutable audit fields');
       END""",
    # Engine-level status gate (defense in depth beyond the revoke API).
    # Allowed: owner (cert:CN=owner_cn) OR admin/directory_admin (via
    # attestation_authz mirror of user_roles — see ATTESTATION_AUTHZ_SCHEMA).
    # NULL current_signer() is refused (IS NOT, never =).
    # update_audit only stamps updated_at/updated_by so it does not trip this.
    """CREATE TRIGGER trg_agent_attestations_status_guard BEFORE UPDATE ON agent_attestations
       WHEN NEW.status IS NOT OLD.status
       BEGIN
         SELECT RAISE(
           ABORT,
           'agent_attestations.status may only be changed by the owner, admin, or directory_admin'
         )
         WHERE current_signer() IS NULL
            OR (
              current_signer() IS NOT ('cert:CN=' || OLD.owner_cn)
              AND NOT EXISTS (
                SELECT 1 FROM"attestation_authz"
                WHERE identity = current_signer()
              )
            );
       END""",
    # Signed-core columns are immutable for everyone (including admin).
    # Corrections = revoke + re-attest. update_audit does not touch these.
    """CREATE TRIGGER trg_agent_attestations_core_immutable BEFORE UPDATE ON agent_attestations
       WHEN NEW.agent_cn IS NOT OLD.agent_cn
         OR NEW.agent_fingerprint IS NOT OLD.agent_fingerprint
         OR NEW.owner_cn IS NOT OLD.owner_cn
         OR NEW.owner_fingerprint IS NOT OLD.owner_fingerprint
         OR NEW.conditions IS NOT OLD.conditions
         OR NEW.expires_at IS NOT OLD.expires_at
         OR NEW.signature IS NOT OLD.signature
       BEGIN
         SELECT RAISE(
           ABORT,
           'agent_attestations signed-core columns are immutable (revoke + re-attest)'
         );
       END""",
]

# Seeded RBAC role definitions (signed at authoring by the container admin).
DIRECTORY_RBAC_RULES = [
    # directory_admin: full database + object write on identities + attestations
    ("database", "*", "directory_admin", "read"),
    ("database", "*", "directory_admin", "write"),
    ("object", "identities", "directory_admin", "read"),
    ("object", "identities", "directory_admin", "write"),
    ("object", "agent_attestations", "directory_admin", "read"),
    ("object", "agent_attestations", "directory_admin", "write"),
    # attestation_authz: readable so the status-guard trigger's EXISTS can
    # compile under the authorizer for non-admin signers (see schema comment).
    ("object", "attestation_authz", "directory_admin", "read"),
    # member: read-only phonebook; may INSERT/UPDATE agent_attestations
    # (object write covers both; status flips are engine-gated by
    # trg_agent_attestations_status_guard to owner / admin / directory_admin)
    ("database", "*", "member", "read"),
    ("database", "*", "member", "write"),
    ("object", "identities", "member", "read"),
    ("object", "agent_attestations", "member", "read"),
    ("object", "agent_attestations", "member", "write"),
    ("object", "attestation_authz", "member", "read"),
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


def attestation_payload(agent_fingerprint, owner_fingerprint, conditions, expires_at):
    """Canonical bytes for an owner→agent attestation signature.

    Single source of truth for what the owner signs (mirrors
    ``canonical_payload``). Fingerprints are SHA-256 DER hex strings as used
    by the directory ``fingerprint`` column. *conditions* is free-text stored
    and signed verbatim (empty string imposes nothing). *expires_at* is an
    ISO-8601 UTC string or ``None`` (no expiry).
    """
    return json.dumps(
        {
            "v": 1,
            "agent_fp": agent_fingerprint,
            "owner_fp": owner_fingerprint,
            "conditions": conditions if conditions is not None else "",
            "expires_at": expires_at,
        },
        sort_keys=True,
    ).encode()


def _directory_callable():
    """Compile main_app from source in a non-importable namespace so dill
    pickles it by value (the container must carry its own code)."""
    ns = {}
    exec(DIRECTORY_SOURCE, ns)
    return ns["main_app"]


def _sign(db, private_key, query, params):
    """Sign against the container's current chain head (call immediately before execute)."""
    next_seq, prev_hash = db.get_chain_head()
    payload = canonical_payload(query, params, next_seq, prev_hash, db.container_uid)
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
        db.conn.execute(AGENT_ATTESTATIONS_SCHEMA)
        db.conn.execute(ATTESTATION_AUTHZ_SCHEMA)
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

        for ddl in AGENT_ATTESTATIONS_TRIGGERS:
            db.execute_signed(ddl, [], sign(ddl, []), cert_pem)

        # Mirror triggers after bootstrap so later role grants stay in sync;
        # then backfill the bootstrap admin (INSERT into user_roles already
        # happened without the mirror triggers present).
        for ddl in ATTESTATION_AUTHZ_TRIGGERS:
            db.execute_signed(ddl, [], sign(ddl, []), cert_pem)
        seed_authz = (
            "INSERT INTO attestation_authz (identity) "
            "SELECT identity FROM user_roles "
            "WHERE role IN ('admin', 'directory_admin')"
        )
        db.execute_signed(seed_authz, [], sign(seed_authz, []), cert_pem)

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


def _table_exists(storage, name):
    row = storage.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _require_attestations_table(storage):
    if not _table_exists(storage, "agent_attestations"):
        raise RuntimeError(
            "directory predates attestations: agent_attestations table is missing "
            "(re-author with create_directory_container; no silent migration)"
        )


def _active_identity_row(storage, *, cn=None, fingerprint=None):
    """Return the active identities row for cn or fingerprint, or None."""
    if fingerprint is not None:
        rows = lookup(storage, status="active")
        for r in rows:
            if r["fingerprint"] == fingerprint:
                return r
        return None
    if cn is not None:
        rows = lookup(storage, cn=cn, status="active")
        return rows[0] if rows else None
    return None


def _signer_role(storage, signer_cert_pem):
    identity = storage._get_identity(signer_cert_pem)
    row = storage.conn.execute(
        "SELECT role FROM user_roles WHERE identity = ?", (identity,)
    ).fetchone()
    return row[0] if row else None


def attest_agent(
    storage,
    signer_cert_pem,
    signer_private_key,
    owner_key,
    owner_cert_pem,
    agent_cn,
    conditions="",
    expires_at=None,
):
    """Record a signed owner→agent attestation in the directory.

    Both owner and agent must already be registered and ``active`` in the
    directory. Both certs must currently chain to the host trust store
    (directory membership alone is not enough). Self-attestation is refused.

    The *owner_key* produces the attestation signature (cryptographic authority).
    The ledger row is signed by *signer_private_key* (submitter may be the owner
    or a directory_admin acting on their behalf).

    *conditions* is free-text stored/signed verbatim (``''`` imposes nothing).
    *expires_at* is an ISO-8601 UTC string or ``None`` (no expiry).

    Returns the new attestation row id. Raises a clear error when the container
    predates the attestations feature (no silent auto-migration).
    """
    _require_attestations_table(storage)

    if conditions is None:
        conditions = ""

    try:
        owner_cert = x509.load_pem_x509_certificate(
            _as_bytes(owner_cert_pem), default_backend()
        )
    except Exception as e:
        raise ValueError(f"Owner is not a valid PEM certificate: {e}") from e

    owner_fp = cert_fingerprint(owner_cert_pem)
    owner_cn = owner_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    owner_row = _active_identity_row(storage, fingerprint=owner_fp)
    if owner_row is None:
        # Distinguish revoked/missing registration
        any_owner = storage.conn.execute(
            "SELECT status FROM identities WHERE fingerprint = ?", (owner_fp,)
        ).fetchone()
        if any_owner is None:
            raise ValueError(
                f"Owner fingerprint {owner_fp} is not registered in the directory"
            )
        raise ValueError(
            f"Owner identity is not active (status={any_owner[0]!r}); "
            "revoked or inactive owners cannot attest"
        )

    agent_rows = lookup(storage, cn=agent_cn, status="active")
    if not agent_rows:
        any_agent = storage.conn.execute(
            "SELECT status FROM identities WHERE cn = ?", (agent_cn,)
        ).fetchone()
        if any_agent is None:
            raise ValueError(
                f"Agent cn={agent_cn!r} is not registered in the directory"
            )
        raise ValueError(
            f"Agent cn={agent_cn!r} is not active (status={any_agent[0]!r})"
        )
    agent_row = agent_rows[0]
    agent_fp = agent_row["fingerprint"]

    if owner_fp == agent_fp:
        raise ValueError("Self-attestation refused: owner and agent fingerprints match")

    anchors = resolve_trust_anchors(storage._ca_cert_path_arg, storage.trust_dir)
    if not is_cert_trusted(owner_cert_pem, anchors):
        raise PermissionError(
            "Owner certificate is not trusted by the local trust store "
            "(attestations are not a trust anchor)."
        )
    if not is_cert_trusted(agent_row["cert_pem"], anchors):
        raise PermissionError(
            "Agent certificate is not trusted by the local trust store "
            "(attestations are not a trust anchor)."
        )

    payload = attestation_payload(agent_fp, owner_fp, conditions, expires_at)
    signature_bytes = owner_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(signature_bytes).decode("ascii")

    query = (
        "INSERT INTO agent_attestations "
        "(agent_cn, agent_fingerprint, owner_cn, owner_fingerprint, "
        "conditions, expires_at, signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    params = [
        agent_cn,
        agent_fp,
        owner_cn,
        owner_fp,
        conditions,
        expires_at,
        sig_b64,
    ]
    sig = _sign(storage, signer_private_key, query, params)
    storage.execute_signed(query, params, sig, signer_cert_pem)

    row = storage.conn.execute(
        "SELECT id FROM agent_attestations WHERE agent_fingerprint = ? "
        "AND owner_fingerprint = ? ORDER BY id DESC LIMIT 1",
        (agent_fp, owner_fp),
    ).fetchone()
    return row[0] if row else None


def revoke_attestation(storage, signer_cert_pem, signer_private_key, attestation_id):
    """Signed-UPDATE an attestation's status to ``revoked``.

    Permitted to ``directory_admin`` / container ``admin`` via role, and to the
    attestation's owner (signer CN matches ``owner_cn``). Other members are
    refused at the API layer before submit. The same rule is enforced in-engine
    by ``trg_agent_attestations_status_guard`` so a crafted ``execute_signed``
    UPDATE cannot bypass it.
    """
    _require_attestations_table(storage)

    row = storage.conn.execute(
        "SELECT id, owner_cn, status FROM agent_attestations WHERE id = ?",
        (attestation_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"No attestation with id={attestation_id}")

    owner_cn = row[1]
    signer_cn = cert_cn(signer_cert_pem)
    role = _signer_role(storage, signer_cert_pem)

    if role not in ("admin", "directory_admin") and signer_cn != owner_cn:
        raise PermissionError(
            f"Access denied: only directory_admin/admin or owner cn={owner_cn!r} "
            f"may revoke attestation id={attestation_id} "
            f"(signer cn={signer_cn!r}, role={role!r})"
        )

    query = "UPDATE agent_attestations SET status = ? WHERE id = ?"
    params = ["revoked", attestation_id]
    sig = _sign(storage, signer_private_key, query, params)
    storage.execute_signed(query, params, sig, signer_cert_pem)


def lookup_attestations(storage, agent_cn=None, include_revoked=False):
    """Plain (unsigned) read of attestation rows — public metadata, like ``lookup``.

    Returns ``[]`` when the container predates the attestations table (no error).
    By default only ``status='active'`` rows are returned; set *include_revoked*
    to include every status. When multiple rows share an (agent, owner) pair
    (re-attest after revoke), callers should treat the newest active row as
    authoritative.
    """
    if not _table_exists(storage, "agent_attestations"):
        return []

    clauses = []
    params = []
    if not include_revoked:
        clauses.append("status = ?")
        params.append("active")
    if agent_cn is not None:
        clauses.append("agent_cn = ?")
        params.append(agent_cn)

    sql = (
        "SELECT id, agent_cn, agent_fingerprint, owner_cn, owner_fingerprint, "
        "conditions, expires_at, signature, status, "
        "added_at, added_by, updated_at, updated_by "
        "FROM agent_attestations"
    )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id ASC"

    cursor = storage.conn.execute(sql, params)
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def verify_attestation(
    storage_or_row,
    row=None,
    *,
    ca_cert_path=None,
    trust_dir=None,
    at_time=None,
):
    """Verify an owner→agent attestation as authorization evidence only.

    Call as ``verify_attestation(storage, row)`` where *row* is a dict from
    ``lookup_attestations``. The owner certificate is fetched from the directory
    ``identities`` table by ``owner_fingerprint`` (not taken from the caller).
    Trust is decided solely by the host trust store (``ca_cert_path`` /
    ``trust_dir``, defaulting to the storage's configured anchors).

    Also accepts a bare row dict as the first argument when it already carries
    ``owner_cert_pem`` (then *row* is omitted and trust anchors come only from
    the keyword args).

    Returns ``{valid: bool, reason: str}`` — never raises for a merely-invalid
    attestation (raises only on programmer error, e.g. missing arguments).
    """
    if row is None:
        if not isinstance(storage_or_row, dict):
            raise TypeError(
                "verify_attestation(storage, row) requires a row dict; "
                "or pass a row dict with owner_cert_pem as the first argument"
            )
        row = storage_or_row
        storage = None
        owner_cert_pem = row.get("owner_cert_pem")
        if not owner_cert_pem:
            raise TypeError(
                "Bare-row verify_attestation requires owner_cert_pem on the row; "
                "prefer verify_attestation(storage, row)"
            )
        anchors = resolve_trust_anchors(ca_cert_path, trust_dir)
    else:
        storage = storage_or_row
        if ca_cert_path is None and hasattr(storage, "_ca_cert_path_arg"):
            ca_cert_path = storage._ca_cert_path_arg
        if trust_dir is None and hasattr(storage, "trust_dir"):
            trust_dir = storage.trust_dir
        anchors = resolve_trust_anchors(ca_cert_path, trust_dir)

        owner_fp = row.get("owner_fingerprint")
        if not owner_fp:
            return {"valid": False, "reason": "missing owner_fingerprint on row"}
        id_row = storage.conn.execute(
            "SELECT cert_pem, status FROM identities WHERE fingerprint = ?",
            (owner_fp,),
        ).fetchone()
        if id_row is None:
            return {
                "valid": False,
                "reason": "owner certificate not found in directory for fingerprint",
            }
        owner_cert_pem = id_row[0]

    if row.get("status") != "active":
        return {
            "valid": False,
            "reason": f"attestation status is {row.get('status')!r}, not 'active' (revoked or inactive)",
        }

    expires_at = row.get("expires_at")
    if expires_at:
        try:
            exp = _parse_iso8601_utc(expires_at)
        except ValueError as e:
            return {"valid": False, "reason": f"unparseable expires_at: {e}"}
        when = at_time if at_time is not None else datetime.now(timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when >= exp:
            return {
                "valid": False,
                "reason": f"attestation expired at {expires_at} (checked at {when.isoformat()})",
            }

    if not is_cert_trusted(owner_cert_pem, anchors):
        return {
            "valid": False,
            "reason": "owner certificate does not chain to the host trust store (fail closed)",
        }

    try:
        payload = attestation_payload(
            row["agent_fingerprint"],
            row["owner_fingerprint"],
            row.get("conditions") if row.get("conditions") is not None else "",
            row.get("expires_at"),
        )
        sig = base64.b64decode(row["signature"])
        cert = x509.load_pem_x509_certificate(
            _as_bytes(owner_cert_pem), default_backend()
        )
        cert.public_key().verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
    except KeyError as e:
        return {"valid": False, "reason": f"incomplete attestation row: missing {e}"}
    except Exception as e:
        return {
            "valid": False,
            "reason": f"signature mismatch or crypto failure: {e}",
        }

    return {"valid": True, "reason": "ok"}


def _parse_iso8601_utc(value):
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # SQLite datetime('now') style: "YYYY-MM-DD HH:MM:SS" (treat as UTC)
    if "T" not in text and " " in text and len(text) >= 19:
        text = text.replace(" ", "T", 1)
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
