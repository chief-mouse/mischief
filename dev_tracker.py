"""Dev Tracker — a dogfood micro-app that manages this project's own dev process.

Authors dev_tracker.msf (a signed micro-app container) seeded with the current
hardening backlog, and doubles as a signed CLI for updating it. Every read and
write — CLI or GUI — goes through MSFStorage.execute_signed, signed with a host
identity (default admin.crt / passphrase-encrypted admin.key), so the tracker
exercises the exact code paths we are hardening.

Usage:
  python dev_tracker.py [--identity <cn>] <command> ...

  Identity (who signs CLI transactions):
    --identity <cn>              use PROJ_DIR/<cn>.crt + <cn>.key (global flag)
    MSCHF_TRACKER_IDENTITY       same, when --identity is omitted (default: admin)
    MSCHF_TRACKER_PASSPHRASE     key passphrase (falls back to MSCHF_ADMIN_PASSPHRASE,
                                 then 'changeit')

  python dev_tracker.py init                     # (re)create dev_tracker.msf with seeded backlog
                                                 # (always signs as admin; override is ignored)
  python dev_tracker.py list                     # show tasks (signed SELECT)
  python dev_tracker.py add "title" "detail"     # add a backlog task (description required)
  python dev_tracker.py describe <id> "text"     # set/replace a task's description (required non-blank)
  python dev_tracker.py status <id> <backlog|in_progress|done>
  python dev_tracker.py horizon <id> <near|later>
  python dev_tracker.py link <from_id> <to_id> [kind]  # directional link (default kind: related)
  python dev_tracker.py links <id>               # show links to/from a task
  python dev_tracker.py update-app               # hot-deploy the current UI code (keeps task data)
  python dev_tracker.py flush                    # flush pending sync_outbox intents (homed only)
  python dev_tracker.py verify                   # load the .msf and run it through the sandbox
  python dev_tracker.py audit                    # replay the signed ledger; flag out-of-band writes

  Examples:
    python dev_tracker.py --identity grok list
    MSCHF_TRACKER_IDENTITY=grok python dev_tracker.py add "task title" "why it matters"
    python dev_tracker.py describe 4 "fill in missing detail"
    python dev_tracker.py horizon 4 later
    python dev_tracker.py link 19 4 follow-up-of
"""
import sys
import os
import sqlite3

PROJ_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(PROJ_DIR, 'src'))

from mschf.storage import MSFStorage, canonical_payload

DB_PATH = os.path.join(PROJ_DIR, 'dev_tracker.msf')
ADMIN_CERT_PATH = os.path.join(PROJ_DIR, 'admin.crt')
ADMIN_KEY_PATH = os.path.join(PROJ_DIR, 'admin.key')
# Legacy module-level default (admin path); load_identity() prefers
# MSCHF_TRACKER_PASSPHRASE then MSCHF_ADMIN_PASSPHRASE.
PASSPHRASE = os.environ.get('MSCHF_ADMIN_PASSPHRASE', 'changeit')

# Set by main() when --identity is parsed; load_identity() also reads
# MSCHF_TRACKER_IDENTITY when this is None.
_CLI_IDENTITY = None

VALID_STATUSES = ('backlog', 'in_progress', 'done')
VALID_HORIZONS = ('near', 'later')

SEED_TASKS = [
    ("Authorizer-hook RBAC enforcement",
     "Replace regex-derived (operation, table) RBAC in MSFStorage.execute_signed with "
     "sqlite3 set_authorizer enforcement so permissions bind to every table the engine "
     "actually touches (joins, CTEs, views, triggers), and deny PRAGMA/ATTACH.",
     "backlog"),
    ("Reactive redraw via update hooks",
     "Notify open MSF documents when a signed transaction commits so their views refresh "
     "(poor man's live materialized view; sqlite update_hook / data_version).",
     "backlog"),
    ("Ledger replay audit verification",
     "Rebuild a shadow database by replaying the signed transactions ledger and diff it "
     "against live tables to detect writes that bypassed execute_signed.",
     "backlog"),
    ("Declarative UI exploration",
     "Prototype a manifest-driven widget tree + signed-query data bindings as an "
     "alternative to dill-pickled Python micro-apps (shrink the pickle attack surface).",
     "backlog"),
    ("Track Turso engine maturity",
     "Watch turso-db (SQLite-compatible Rust engine, MVCC + incremental views + stable "
     "bytecode target) as a possible future .msf container engine.",
     "backlog"),
]


def _active_cn():
    """CN for CLI signing: --identity flag, else MSCHF_TRACKER_IDENTITY, else admin."""
    if _CLI_IDENTITY is not None:
        return _CLI_IDENTITY
    return os.environ.get('MSCHF_TRACKER_IDENTITY', 'admin')


def _identity_passphrase():
    """Key passphrase: MSCHF_TRACKER_PASSPHRASE → MSCHF_ADMIN_PASSPHRASE → changeit."""
    return (
        os.environ.get('MSCHF_TRACKER_PASSPHRASE')
        or os.environ.get('MSCHF_ADMIN_PASSPHRASE')
        or 'changeit'
    )


def load_identity(cn=None):
    """Load a host identity by CN and unlock its passphrase-encrypted private key.

    Cert/key paths are PROJ_DIR/<cn>.crt and PROJ_DIR/<cn>.key. When cn is
    omitted, uses --identity / MSCHF_TRACKER_IDENTITY / 'admin'.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    if cn is None:
        cn = _active_cn()
    cert_path = os.path.join(PROJ_DIR, f'{cn}.crt')
    key_path = os.path.join(PROJ_DIR, f'{cn}.key')
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        sys.exit(
            f"{cn}.crt/{cn}.key not found in project root — "
            "run the app once ('briefcase dev') to generate admin, "
            "or provision the requested identity."
        )
    passphrase = _identity_passphrase()
    with open(cert_path, 'rb') as f:
        cert_pem = f.read()
    with open(key_path, 'rb') as f:
        key_pem = f.read()
    try:
        private_key = load_pem_private_key(key_pem, password=passphrase.encode('utf-8'))
    except (TypeError, ValueError):
        # Legacy plaintext key (the app auto-upgrades these on startup)
        private_key = load_pem_private_key(key_pem, password=None)
    return cert_pem, private_key


def load_admin_identity():
    """Load the host admin cert (compat wrapper for other importers)."""
    return load_identity('admin')


def sign_payload(db, private_key, query, params):
    """Sign against db's current chain head + container_uid (must execute before the head moves)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(
        query, params, next_seq, prev_hash, db.container_uid)
    return private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())


def signed_exec(db, cert_pem, private_key, query, params, bootstrap=False):
    signature = sign_payload(db, private_key, query, params)
    if bootstrap:
        return db.bootstrap_admin(query, params, signature, cert_pem)
    return db.execute_signed(query, params, signature, cert_pem)


def local_read(db, cert_pem, query, params=None):
    """RBAC-checked local SELECT (no ledger row) — used on homed replicas.

    Signed reads advance the chain and are refused on containers whose
    manifest names a hub; product reads therefore run unsigned after the
    same coarse database- + object-level gates as execute_signed.
    """
    params = params if params is not None else []
    identity = db._get_identity(cert_pem)
    operation, table_name = db._parse_sql_query(query)
    if operation != 'read':
        raise PermissionError(
            f"local_read is SELECT-only; got operation={operation!r}"
        )
    if not db.check_permission(identity, 'database', '*', 'read'):
        raise PermissionError(
            f"Access denied: Identity '{identity}' does not have database-level "
            f"read permissions ('No Access' active)."
        )
    if table_name != '*':
        if table_name in db.SYSTEM_TABLES:
            row = db.conn.execute(
                "SELECT role FROM user_roles WHERE identity = ?", (identity,)
            ).fetchone()
            role = row[0] if row else 'guest'
            if role != 'admin':
                raise PermissionError(
                    f"Access denied: System table '{table_name}' can only be "
                    f"modified by admin."
                )
        else:
            if not db.check_permission(identity, 'object', table_name, 'read'):
                raise PermissionError(
                    f"Access denied: Identity '{identity}' does not have "
                    f"'read' permission on table '{table_name}'."
                )
    cursor = db.conn.cursor()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    return cursor


def _print_write_result(result, action_msg):
    """Print committed/queued feedback after a hub or local write."""
    if result is None:
        print(action_msg)
        return
    status = result.get('status') if isinstance(result, dict) else getattr(result, 'status', None)
    seq = result.get('seq') if isinstance(result, dict) else getattr(result, 'seq', None)
    if status == 'queued':
        print(f"{action_msg}  [queued (hub unreachable — will flush on reconnect)]")
    elif status == 'committed' and seq is not None:
        print(f"{action_msg}  [committed (seq {seq})]")
    else:
        print(action_msg)


def hub_or_local_write(db, cert_pem, private_key, query, params, hub_url, hub_cn):
    """Route a mutation: hub_write when homed, signed_exec when unhomed.

    Returns a result dict ``{'status': 'committed'|'queued', 'seq': ...}`` for
    homed paths, or ``None`` for unhomed (caller prints the classic message).
    """
    if hub_cn:
        from mschf import sync as msync
        container_id = os.path.splitext(os.path.basename(db.filename))[0]
        cert = cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem
        return msync.hub_write(
            db,
            hub_url or '',
            container_id,
            private_key,
            cert,
            _active_cn(),
            query,
            params if params is not None else [],
            expected_hub_cn=hub_cn,
            ca_cert_path=getattr(db, '_ca_cert_path_arg', None),
            trust_dir=getattr(db, 'trust_dir', None),
        )
    signed_exec(db, cert_pem, private_key, query, params)
    return None


def cli_read(db, cert_pem, private_key, query, params, hub_cn):
    """SELECT path: unsigned local read when homed, signed_exec when unhomed."""
    if hub_cn:
        return local_read(db, cert_pem, query, params)
    return signed_exec(db, cert_pem, private_key, query, params)


# Audit fields are stamped by triggers from current_signer() — the SQL function
# storage.py registers with the verified identity of the executing signed
# transaction — so apps cannot spoof or forget attribution. recursive_triggers
# is off (SQLite default), so the audit triggers' own UPDATEs don't re-fire
# triggers (including the immutability guard below).
AUDIT_TRIGGERS = [
    """CREATE TRIGGER trg_dev_tasks_insert_audit AFTER INSERT ON dev_tasks
       BEGIN
         UPDATE dev_tasks SET
           created_at = COALESCE(NEW.created_at, datetime('now')),
           updated_at = COALESCE(NEW.updated_at, datetime('now')),
           created_by = COALESCE(current_signer(), 'unsigned'),
           updated_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_dev_tasks_update_audit AFTER UPDATE ON dev_tasks
       BEGIN
         UPDATE dev_tasks SET
           updated_at = datetime('now'),
           updated_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_dev_tasks_created_immutable BEFORE UPDATE ON dev_tasks
       WHEN OLD.created_by IS NOT NULL
        AND (NEW.created_at IS NOT OLD.created_at OR NEW.created_by IS NOT OLD.created_by)
       BEGIN
         SELECT RAISE(ABORT, 'created_at/created_by are immutable audit fields');
       END""",
]

# task_links stamping + append-only guard. Separate from AUDIT_TRIGGERS so
# test_ledger_audit (which imports that list) stays unchanged. The immutability
# trigger allows the insert-audit UPDATE while created_by is still NULL, then
# rejects every subsequent UPDATE (links are append-only history).
LINK_TRIGGERS = [
    """CREATE TRIGGER trg_task_links_insert_audit AFTER INSERT ON task_links
       BEGIN
         UPDATE task_links SET
           created_at = COALESCE(NEW.created_at, datetime('now')),
           created_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END""",
    """CREATE TRIGGER trg_task_links_no_update BEFORE UPDATE ON task_links
       WHEN OLD.created_by IS NOT NULL
       BEGIN
         SELECT RAISE(ABORT, 'task_links are immutable (append-only)');
       END""",
]

# Engine-level: every dev_tasks row must carry a non-blank description (detail).
# Separate from AUDIT_TRIGGERS so test_ledger_audit imports stay unchanged.
# The AFTER INSERT/UPDATE audit triggers stamp only timestamps/identity and
# leave detail alone; with recursive_triggers off those stamping UPDATEs do not
# re-enter this guard. A user UPDATE (status/horizon/…) on a legacy row that
# already has empty detail DOES trip the UPDATE guard — deliberate strictness:
# the next touch must set a description first (CLI: describe <id> "text").
DETAIL_REQUIRED_MSG = 'dev_tasks require a description (detail)'
VALIDATION_TRIGGERS = [
    f"""CREATE TRIGGER trg_dev_tasks_require_detail_ins BEFORE INSERT ON dev_tasks
       WHEN NEW.detail IS NULL OR trim(NEW.detail) = ''
       BEGIN
         SELECT RAISE(ABORT, '{DETAIL_REQUIRED_MSG}');
       END""",
    f"""CREATE TRIGGER trg_dev_tasks_require_detail_upd BEFORE UPDATE ON dev_tasks
       WHEN NEW.detail IS NULL OR trim(NEW.detail) = ''
       BEGIN
         SELECT RAISE(ABORT, '{DETAIL_REQUIRED_MSG}');
       END""",
]


def _is_detail_required_error(exc):
    """True when SQLite aborted because detail was empty/blank."""
    return DETAIL_REQUIRED_MSG in str(exc)


def _detail_required_cli_hint(task_id=None):
    if task_id is not None:
        return (
            f"Task #{task_id} has no description — set one first:\n"
            f'  python dev_tracker.py describe {task_id} "text"'
        )
    return (
        'Tasks require a description (detail). '
        'Usage: python dev_tracker.py add "title" "detail"'
    )


TASK_LINKS_DDL = (
    "CREATE TABLE task_links ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "from_id INTEGER NOT NULL, "
    "to_id INTEGER NOT NULL, "
    "kind TEXT NOT NULL DEFAULT 'related', "
    "created_at TEXT DEFAULT (datetime('now')), "
    "created_by TEXT, "
    "UNIQUE(from_id, to_id, kind))"
)

# Object-level rules agents need for task_links (dev_tasks rules are provisioned
# out-of-band for claude/grok). Checked/added idempotently in _ensure_schema.
AGENT_TASK_LINKS_RBAC = (
    ('object', 'task_links', 'agent', 'read'),
    ('object', 'task_links', 'agent', 'write'),
)

# Sort key for board list: in_progress → backlog(near) → later → done.
LIST_ORDER_SQL = (
    "ORDER BY CASE "
    "WHEN status = 'in_progress' THEN 0 "
    "WHEN status = 'backlog' AND COALESCE(horizon, 'near') = 'near' THEN 1 "
    "WHEN status = 'backlog' AND COALESCE(horizon, 'near') = 'later' THEN 2 "
    "WHEN status = 'done' THEN 3 "
    "ELSE 4 END, id"
)


def _cert_cn(cert_pem):
    """CN of the signing identity — stamped on rows as created_by/updated_by."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        pem = cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode('utf-8')
        return x509.load_pem_x509_certificate(pem).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return 'unknown'


def _ensure_schema(db, cert_pem, private_key):
    """Idempotent, signed migration of dev_tasks / task_links schema.

    When the schema is already current this performs no signed writes. Pending
    migrations require admin (DDL / system-table-adjacent writes); non-admin
    identities get a clear exit message instead of a traceback.
    """
    try:
        identity = f"cert:CN={_cert_cn(cert_pem)}"
        cols = {r[1] for r in db.conn.execute("PRAGMA table_info(dev_tasks)")}
        added = [c for c in ('created_at', 'created_by', 'updated_by') if c not in cols]
        for col in added:
            signed_exec(db, cert_pem, private_key, f"ALTER TABLE dev_tasks ADD COLUMN {col} TEXT", [])
        if added:
            # Backfill: everything so far was created in the seeding pass, and every
            # prior write was signed by this same identity (the ledger proves it).
            signed_exec(db, cert_pem, private_key,
                        "UPDATE dev_tasks SET created_at = COALESCE(created_at, updated_at), "
                        "created_by = COALESCE(created_by, ?), updated_by = COALESCE(updated_by, ?)",
                        [identity, identity])
            print(f"Migrated dev_tasks schema (added: {', '.join(added)}).")

        if 'horizon' not in cols:
            signed_exec(db, cert_pem, private_key,
                        "ALTER TABLE dev_tasks ADD COLUMN horizon TEXT", [])
            print("Migrated dev_tasks schema (added: horizon).")

        existing = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        missing = [ddl for ddl in AUDIT_TRIGGERS if ddl.split()[2] not in existing]
        if missing:
            # Normalize legacy CN-only attribution to identity strings BEFORE the
            # immutability trigger locks created_by down.
            for col in ('created_by', 'updated_by'):
                signed_exec(db, cert_pem, private_key,
                            f"UPDATE dev_tasks SET {col} = 'cert:CN=' || {col} "
                            f"WHERE {col} IS NOT NULL AND {col} NOT LIKE 'cert:%' AND {col} NOT LIKE 'key:%'", [])
            for ddl in missing:
                signed_exec(db, cert_pem, private_key, ddl, [])
            print(f"Installed audit triggers ({len(missing)}); attribution is now engine-enforced.")

        tables = {r[0] for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if 'task_links' not in tables:
            signed_exec(db, cert_pem, private_key, TASK_LINKS_DDL, [])
            print("Created task_links table.")

        existing = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        missing_links = [ddl for ddl in LINK_TRIGGERS if ddl.split()[2] not in existing]
        if missing_links:
            for ddl in missing_links:
                signed_exec(db, cert_pem, private_key, ddl, [])
            print(f"Installed task_links triggers ({len(missing_links)}).")

        existing = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        missing_val = [ddl for ddl in VALIDATION_TRIGGERS if ddl.split()[2] not in existing]
        if missing_val:
            for ddl in missing_val:
                signed_exec(db, cert_pem, private_key, ddl, [])
            print(f"Installed validation triggers ({len(missing_val)}): detail required on dev_tasks.")

        for level, target, role, perm in AGENT_TASK_LINKS_RBAC:
            row = db.conn.execute(
                "SELECT 1 FROM rbac_rules WHERE level = ? AND target = ? AND role = ? AND permission = ?",
                [level, target, role, perm],
            ).fetchone()
            if not row:
                signed_exec(
                    db, cert_pem, private_key,
                    "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
                    [level, target, role, perm],
                )
                print(f"Added RBAC rule: {level}/{target} {role} {perm}.")
    except PermissionError as e:
        sys.exit(
            f"Schema migration requires admin identity — run once as admin "
            f"(e.g. python dev_tracker.py --identity admin <cmd>): {e}"
        )


# ---------------------------------------------------------------------------
# The micro-app itself. Must stay self-contained: it is dill-pickled into the
# container and later called as code_func(toga, host_api) by the sandbox.
# ---------------------------------------------------------------------------
def dev_tracker_app(toga, host_api):
    # `import toga` alone does not expose the toga.style submodule; import Pack
    # explicitly so this works no matter what the host has already imported.
    from toga.style import Pack as P

    cn = "Unknown"
    cert_pem = ""
    try:
        user_info = host_api.get_current_user()
        cn = user_info.get("common_name", "Unknown")
        cert_pem = user_info.get("certificate_pem", "")
    except Exception:
        pass

    can_read = False
    if cert_pem:
        try:
            can_read = host_api.has_database_permission('read', cert_pem)
        except Exception:
            can_read = False

    if not can_read:
        denied = toga.Box(style=P(direction='column', margin=20))
        denied.add(toga.Label("ACCESS DENIED", style=P(font_size=20, font_weight='bold', color='red', margin_bottom=10)))
        denied.add(toga.Label(f"Identity cert:CN={cn} has no database-level read permission on the Dev Tracker.", style=P()))
        return denied

    def status_label_text(status, horizon):
        if status == 'in_progress':
            return '● In Progress'
        if status == 'done':
            return '✓ Done'
        if status == 'backlog' and (horizon or 'near') == 'later':
            return '◷ Later'
        return '○ Backlog'

    details = {}   # task id -> detail text, filled by refresh()
    titles = {}    # task id -> title
    link_lines = {}  # task id -> list of link description lines

    board = toga.Box(id='dev_tracker_board', style=P(direction='column', margin=16, flex=1))

    # --- Header ---
    header = toga.Box(style=P(direction='row', align_items='end', margin_bottom=2))
    header.add(toga.Label("Mischief Dev Tracker", style=P(font_size=20, font_weight='bold', flex=1)))
    counts_label = toga.Label("", style=P(font_size=10, color='#666666'))
    header.add(counts_label)
    board.add(header)
    board.add(toga.Label(f"Signed in as {cn} — every change is a signed transaction.",
                         style=P(font_style='italic', font_size=10, color='#666666', margin_bottom=10)))

    # --- Task table (select a row to act on it) ---
    table = toga.Table(
        headings=["#", "Task", "Status", "Created", "By", "Updated", "By"],
        accessors=("num", "title", "status", "created", "created_by", "updated", "updated_by"),
        data=[],
        style=P(flex=1, margin_bottom=6),
    )
    board.add(table)

    # A read-only multiline input wraps long detail text; a Label would force
    # the whole window to grow to the text's single-line width.
    detail_view = toga.MultilineTextInput(readonly=True, placeholder="Select a task to see its detail.",
                                          style=P(height=80, font_size=10, margin_bottom=8))
    board.add(detail_view)

    status_label = toga.Label("Ready.", style=P(font_size=10, font_style='italic', margin_top=8))

    def tune_columns(*_args):
        # WinForms-only polish: Toga's API has no column sizing, and the
        # ListView runs in VirtualMode where Width=-1 (auto-size to content)
        # is a no-op — so measure the cell text ourselves and set explicit
        # pixel widths, capped per column. try/except keeps other platforms
        # rendering with their default widths.
        try:
            from System.Windows.Forms import TextRenderer
            native = table._impl.native  # System.Windows.Forms.ListView
            font = native.Font
            caps = (60, 700, 170, 160, 140, 160, 140)
            pad = 24
            texts = [[h] for h in ("#", "Task", "Status", "Created", "By", "Updated", "By")]
            for row in table.data:
                for i, v in enumerate((row.num, row.title, row.status, row.created,
                                       row.created_by, row.updated, row.updated_by)):
                    texts[i].append(str(v))
            native.BeginUpdate()
            for i in range(native.Columns.Count):
                w = max(TextRenderer.MeasureText(t, font).Width for t in texts[i]) + pad
                native.Columns[i].Width = max(40, min(w, caps[i]))
            native.EndUpdate()
        except Exception:
            pass

    # The winforms backend's first layout pass calls impl._resize_columns(),
    # which splits the width equally across columns — after this function has
    # already returned. Replacing it on the instance makes that pass (and any
    # later column changes) use content-based sizing instead.
    try:
        table._impl._resize_columns = tune_columns
    except Exception:
        pass

    def refresh(widget=None):
        try:
            cursor = host_api.execute_signed_query(
                "SELECT id, title, status, created_at, created_by, updated_at, updated_by, detail, "
                "COALESCE(horizon, 'near') "
                "FROM dev_tasks "
                "ORDER BY CASE "
                "WHEN status = 'in_progress' THEN 0 "
                "WHEN status = 'backlog' AND COALESCE(horizon, 'near') = 'near' THEN 1 "
                "WHEN status = 'backlog' AND COALESCE(horizon, 'near') = 'later' THEN 2 "
                "WHEN status = 'done' THEN 3 "
                "ELSE 4 END, id"
            )
            rows = cursor.fetchall()
            details.clear()
            details.update({r[0]: (r[7] or "").strip() for r in rows})
            titles.clear()
            titles.update({r[0]: r[1] for r in rows})
            link_lines.clear()
            try:
                lcur = host_api.execute_signed_query(
                    "SELECT from_id, to_id, kind FROM task_links"
                )
                for fr, to, kind in lcur.fetchall():
                    link_lines.setdefault(fr, []).append(
                        f"  -[{kind}]-> #{to} {titles.get(to, '')}".rstrip())
                    link_lines.setdefault(to, []).append(
                        f"  <-[{kind}]- #{fr} {titles.get(fr, '')}".rstrip())
            except Exception:
                # Pre-migration containers or missing object read — detail still works.
                pass
            # Trim timestamps to minute resolution and identities to bare CNs
            # to keep the columns compact.
            who = lambda w: (w or "?").replace('cert:CN=', '')
            table.data = [(r[0], r[1], status_label_text(r[2], r[8]),
                           (r[3] or "")[:16], who(r[4]), (r[5] or "")[:16], who(r[6]))
                          for r in rows]
            tune_columns()
            near = later = in_prog = done = 0
            for r in rows:
                st, hz = r[2], (r[8] or 'near')
                if st == 'done':
                    done += 1
                elif st == 'in_progress':
                    in_prog += 1
                elif hz == 'later':
                    later += 1
                else:
                    near += 1
            counts_label.text = (
                f"{near} near · {later} later · {in_prog} in progress · {done} done"
            )
            status_label.text = "Ready."
        except Exception as e:
            status_label.text = f"Query blocked: {e}"

    def on_select(widget):
        row = table.selection
        if row is None:
            detail_view.value = ""
            return
        body = details.get(row.num) or "(no detail)"
        links = link_lines.get(row.num) or []
        if links:
            body = body + "\n\nLinks:\n" + "\n".join(links)
        detail_view.value = body
    table.on_select = on_select

    def set_status(new_status):
        def handler(widget):
            row = table.selection
            if row is None:
                status_label.text = "Select a task in the table first."
                return
            try:
                host_api.execute_signed_query(
                    "UPDATE dev_tasks SET status = ? WHERE id = ?",
                    [new_status, row.num]
                )
                status_label.text = f"Task #{row.num} -> {new_status} (signed by {cn})."
                refresh()
            except Exception as e:
                err = str(e)
                if 'require a description' in err:
                    status_label.text = (
                        f"Task #{row.num} needs a description before status can change. "
                        f"Use: describe {row.num} \"text\" ({e})"
                    )
                else:
                    status_label.text = f"Blocked: {e}"
        return handler

    def set_horizon(new_horizon):
        def handler(widget):
            row = table.selection
            if row is None:
                status_label.text = "Select a task in the table first."
                return
            try:
                host_api.execute_signed_query(
                    "UPDATE dev_tasks SET horizon = ? WHERE id = ?",
                    [new_horizon, row.num]
                )
                status_label.text = f"Task #{row.num} horizon -> {new_horizon} (signed by {cn})."
                refresh()
            except Exception as e:
                err = str(e)
                if 'require a description' in err:
                    status_label.text = (
                        f"Task #{row.num} needs a description before horizon can change. "
                        f"Use: describe {row.num} \"text\" ({e})"
                    )
                else:
                    status_label.text = f"Blocked: {e}"
        return handler

    actions = toga.Box(style=P(direction='row', margin_bottom=12))
    actions.add(toga.Button("● Mark In Progress", on_press=set_status('in_progress'), style=P(margin_right=8)))
    actions.add(toga.Button("✓ Mark Done", on_press=set_status('done'), style=P(margin_right=8)))
    actions.add(toga.Button("○ Back to Backlog", on_press=set_status('backlog'), style=P(margin_right=8)))
    actions.add(toga.Button("Defer to Later", on_press=set_horizon('later'), style=P(margin_right=8)))
    actions.add(toga.Button("Move to Near", on_press=set_horizon('near'), style=P(margin_right=8)))
    actions.add(toga.Box(style=P(flex=1)))
    actions.add(toga.Button("Refresh", on_press=refresh))
    board.add(actions)

    # --- New task ---
    new_row = toga.Box(style=P(direction='row'))
    title_input = toga.TextInput(placeholder="New task title...", style=P(flex=1, margin_right=8))
    detail_input = toga.TextInput(
        placeholder="Description (required)...",
        style=P(flex=1, margin_right=8),
    )

    def add_task(widget):
        title = (title_input.value or "").strip()
        detail = (detail_input.value or "").strip()
        if not title:
            status_label.text = "Enter a task title first."
            return
        if not detail:
            status_label.text = "Description is required — fill in the description field."
            return
        try:
            host_api.execute_signed_query(
                "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, 'backlog')",
                [title, detail]
            )
            title_input.value = ""
            detail_input.value = ""
            status_label.text = f"Added '{title}' (signed by {cn})."
            refresh()
        except Exception as e:
            err = str(e)
            if 'require a description' in err:
                status_label.text = f"Description required: {e}"
            else:
                status_label.text = f"Blocked: {e}"

    new_row.add(title_input)
    new_row.add(detail_input)
    new_row.add(toga.Button("+ Add Task", on_press=add_task))
    board.add(new_row)
    board.add(status_label)

    try:
        refresh()
    except Exception:
        pass

    return board


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
def cmd_init():
    import dill
    # init always bootstraps as admin; a non-admin first-writer would become
    # container admin via bootstrap_admin.
    override = _active_cn()
    if override != 'admin':
        print(f"Note: identity override '{override}' ignored for init (always uses admin).")
    if os.path.exists(DB_PATH):
        # Refuse re-init of a homed replica — admin authors on the hub copy.
        try:
            probe = MSFStorage(DB_PATH)
            from mschf import sync as msync
            _url, hub_cn = msync.homing(probe)
            probe.close()
            if hub_cn:
                sys.exit(
                    f"Refuse init: {DB_PATH} is a homed replica (hub {hub_cn!r}). "
                    "Author/admin on the hub's copy, or set MSCHF_ALLOW_LOCAL_WRITES=1 "
                    "only for orphan recovery (may fork)."
                )
        except SystemExit:
            raise
        except Exception:
            pass
    cert_pem, private_key = load_admin_identity()

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = MSFStorage(DB_PATH)

    # Schema is an authoring step, like test_microapp.py's provisioning.
    # horizon + task_links are added by _ensure_schema (signed migration) so
    # existing containers pick them up the same way; first admin CLI command
    # after init (or after an upgrade) runs that path.
    db.conn.execute(
        "CREATE TABLE IF NOT EXISTS dev_tasks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, detail TEXT, "
        "status TEXT NOT NULL DEFAULT 'backlog' CHECK(status IN ('backlog','in_progress','done')), "
        "created_at TEXT DEFAULT (datetime('now')), created_by TEXT, "
        "updated_at TEXT DEFAULT (datetime('now')), updated_by TEXT)"
    )
    # First signed write deliberately claims admin for cert:CN=admin (opt-in
    # bootstrap). Everything after — including trigger DDL — is a signed,
    # ledgered transaction so a replay audit can reconstruct history exactly.
    sig = sign_payload(db, private_key, "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", ['entry_point', 'main_app'])
    db.bootstrap_admin("INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", ['entry_point', 'main_app'], sig, cert_pem)

    # Audit triggers via SIGNED DDL, before any task rows exist: replay sees
    # them at the same point in history, and every seed insert gets stamped.
    for ddl in AUDIT_TRIGGERS:
        signed_exec(db, cert_pem, private_key, ddl, [])

    q = "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, ?)"
    for task in SEED_TASKS:
        signed_exec(db, cert_pem, private_key, q, list(task))

    # Micro-app code, signed like any other transaction.
    pickled = dill.dumps(dev_tracker_app)
    sig = sign_payload(db, private_key, "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)", ['main_app', pickled])
    db.store_code('main_app', dev_tracker_app, sig, cert_pem)
    for key, value in (('name', 'Mischief Dev Tracker'), ('version', '1.0'),
                       ('description', 'Dogfood tracker for the mschf hardening backlog.')):
        sig = sign_payload(db, private_key, "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", [key, value])
        db.set_manifest_item(key, value, sig, cert_pem)

    db.close()
    print(f"Created {DB_PATH} with {len(SEED_TASKS)} seeded tasks (admin = cert:CN=admin).")


def _open_for_cli():
    """Open the tracker container; return (db, cert, key, hub_url, hub_cn).

    When the container is homed, schema migrations are skipped (schema arrives
    via hub pull) and callers must use local_read / hub_or_local_write.
    """
    cert_pem, private_key = load_identity()
    if not os.path.exists(DB_PATH):
        sys.exit("dev_tracker.msf not found — run: python dev_tracker.py init")
    db = MSFStorage(DB_PATH)
    from mschf import sync as msync
    hub_url, hub_cn = msync.homing(db)
    return db, cert_pem, private_key, hub_url, hub_cn


def _maybe_pull(db, hub_url, hub_cn):
    """Best-effort pull_and_apply for list/links. Prints one [offline] note on failure."""
    if not hub_cn or not hub_url:
        return
    from mschf import sync as msync
    container_id = os.path.splitext(os.path.basename(db.filename))[0]
    try:
        msync.pull_and_apply(
            db, hub_url, container_id,
            expected_hub_cn=hub_cn,
            ca_cert_path=getattr(db, '_ca_cert_path_arg', None),
            trust_dir=getattr(db, 'trust_dir', None),
        )
    except Exception as e:
        if msync._is_connection_error(e) or isinstance(e, (TimeoutError, OSError)):
            print(f"[offline] hub unreachable — showing local data ({e})")
        else:
            # Non-network (attestation etc.): still continue with local data.
            print(f"[offline] pull failed — showing local data ({e})")


def _list_tag(status, horizon):
    """4-char status tag for CLI list lines."""
    if status == 'in_progress':
        return 'WIP '
    if status == 'done':
        return 'DONE'
    if status == 'backlog' and (horizon or 'near') == 'later':
        return 'LATR'
    if status == 'backlog':
        return 'TODO'
    return '??? '


def cmd_list():
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    else:
        _maybe_pull(db, hub_url, hub_cn)
    cursor = cli_read(
        db, cert_pem, private_key,
        "SELECT id, title, status, created_at, created_by, updated_at, updated_by, "
        "COALESCE(horizon, 'near') FROM dev_tasks " + LIST_ORDER_SQL,
        [],
        hub_cn,
    )
    rows = cursor.fetchall()
    # Compact outgoing/incoming link counts and first target for annotation.
    link_annot = {}
    try:
        lcur = cli_read(
            db, cert_pem, private_key,
            "SELECT from_id, to_id, kind FROM task_links", [],
            hub_cn,
        )
        for fr, to, kind in lcur.fetchall():
            link_annot.setdefault(fr, []).append(f"->{to}")
            link_annot.setdefault(to, []).append(f"<-{fr}")
    except Exception:
        pass
    strip = lambda who: (who or '?').replace('cert:CN=', '')
    for r in rows:
        tid, title, status = r[0], r[1], r[2]
        horizon = r[7]
        ann = link_annot.get(tid)
        ann_s = f"  [{','.join(ann)}]" if ann else ""
        print(f"  [{_list_tag(status, horizon)}] #{tid} {title}{ann_s}  "
              f"(created {r[3]} by {strip(r[4])}; updated {r[5]} by {strip(r[6])})")
    done = sum(1 for r in rows if r[2] == 'done')
    later = sum(1 for r in rows if r[2] == 'backlog' and (r[7] or 'near') == 'later')
    print(f"\n{len(rows)} tasks, {done} done, {later} later.")
    db.close()


def cmd_add(title, detail=""):
    # Client gate before any signing/open — engine triggers enforce the same rule.
    if not (detail or "").strip():
        sys.exit(_detail_required_cli_hint())
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    try:
        result = hub_or_local_write(
            db, cert_pem, private_key,
            "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, 'backlog')",
            [title, detail],
            hub_url, hub_cn,
        )
    except Exception as e:
        db.close()
        if _is_detail_required_error(e):
            sys.exit(_detail_required_cli_hint())
        raise
    _print_write_result(result, f"Added backlog task: {title}")
    db.close()


def cmd_describe(task_id, detail):
    """Set a task's description (detail). Refuses blank text before signing."""
    if not (detail or "").strip():
        sys.exit(
            'Description cannot be blank. '
            'Usage: python dev_tracker.py describe <id> "text"'
        )
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    tid = int(task_id)
    exists = cli_read(
        db, cert_pem, private_key,
        "SELECT title FROM dev_tasks WHERE id = ?", [tid],
        hub_cn,
    ).fetchone()
    if not exists:
        db.close()
        sys.exit(f"No task with id {tid}.")
    try:
        result = hub_or_local_write(
            db, cert_pem, private_key,
            "UPDATE dev_tasks SET detail = ? WHERE id = ?",
            [detail, tid],
            hub_url, hub_cn,
        )
    except Exception as e:
        db.close()
        if _is_detail_required_error(e):
            sys.exit(
                'Description cannot be blank. '
                'Usage: python dev_tracker.py describe <id> "text"'
            )
        raise
    _print_write_result(result, f"Task #{tid} ({exists[0]}) description updated.")
    db.close()


def cmd_status(task_id, new_status):
    if new_status not in VALID_STATUSES:
        sys.exit(f"Invalid status '{new_status}' — use one of {VALID_STATUSES}")
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    try:
        result = hub_or_local_write(
            db, cert_pem, private_key,
            "UPDATE dev_tasks SET status = ? WHERE id = ?",
            [new_status, int(task_id)],
            hub_url, hub_cn,
        )
    except Exception as e:
        db.close()
        if _is_detail_required_error(e):
            sys.exit(_detail_required_cli_hint(task_id))
        raise
    cursor = cli_read(
        db, cert_pem, private_key,
        "SELECT title FROM dev_tasks WHERE id = ?", [int(task_id)],
        hub_cn,
    )
    row = cursor.fetchone()
    _print_write_result(result, f"Task #{task_id} ({row[0] if row else '?'}) -> {new_status}")
    db.close()


def cmd_horizon(task_id, new_horizon):
    if new_horizon not in VALID_HORIZONS:
        sys.exit(f"Invalid horizon '{new_horizon}' — use one of {VALID_HORIZONS}")
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    try:
        result = hub_or_local_write(
            db, cert_pem, private_key,
            "UPDATE dev_tasks SET horizon = ? WHERE id = ?",
            [new_horizon, int(task_id)],
            hub_url, hub_cn,
        )
    except Exception as e:
        db.close()
        if _is_detail_required_error(e):
            sys.exit(_detail_required_cli_hint(task_id))
        raise
    cursor = cli_read(
        db, cert_pem, private_key,
        "SELECT title FROM dev_tasks WHERE id = ?", [int(task_id)],
        hub_cn,
    )
    row = cursor.fetchone()
    _print_write_result(
        result,
        f"Task #{task_id} ({row[0] if row else '?'}) horizon -> {new_horizon}",
    )
    db.close()


def cmd_link(from_id, to_id, kind='related'):
    from_id, to_id = int(from_id), int(to_id)
    kind = (kind or 'related').strip() or 'related'
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    for tid, label in ((from_id, 'from_id'), (to_id, 'to_id')):
        row = cli_read(
            db, cert_pem, private_key,
            "SELECT id FROM dev_tasks WHERE id = ?", [tid],
            hub_cn,
        ).fetchone()
        if not row:
            db.close()
            sys.exit(f"No task with id {tid} ({label}).")
    try:
        result = hub_or_local_write(
            db, cert_pem, private_key,
            "INSERT INTO task_links (from_id, to_id, kind) VALUES (?, ?, ?)",
            [from_id, to_id, kind],
            hub_url, hub_cn,
        )
    except sqlite3.IntegrityError:
        db.close()
        sys.exit(f"Link already exists: #{from_id} -[{kind}]-> #{to_id}")
    _print_write_result(result, f"Linked #{from_id} -[{kind}]-> #{to_id}")
    db.close()


def cmd_links(task_id):
    task_id = int(task_id)
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        _ensure_schema(db, cert_pem, private_key)
    else:
        _maybe_pull(db, hub_url, hub_cn)
    exists = cli_read(
        db, cert_pem, private_key,
        "SELECT title FROM dev_tasks WHERE id = ?", [task_id],
        hub_cn,
    ).fetchone()
    if not exists:
        db.close()
        sys.exit(f"No task with id {task_id}.")
    print(f"Links for #{task_id} ({exists[0]}):")
    out = cli_read(
        db, cert_pem, private_key,
        "SELECT to_id, kind FROM task_links WHERE from_id = ? ORDER BY id",
        [task_id],
        hub_cn,
    ).fetchall()
    inn = cli_read(
        db, cert_pem, private_key,
        "SELECT from_id, kind FROM task_links WHERE to_id = ? ORDER BY id",
        [task_id],
        hub_cn,
    ).fetchall()
    if not out and not inn:
        print("  (none)")
    for to_id, kind in out:
        print(f"  #{task_id} -[{kind}]-> #{to_id}")
    for from_id, kind in inn:
        print(f"  #{from_id} -[{kind}]-> #{task_id}")
    db.close()


def cmd_verify():
    """Load dev_tracker.msf and run it through the real sandbox, headless."""
    from mschf.sandbox import execute_micro_app
    import toga

    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    entry_point = db.get_manifest_item('entry_point')
    assert entry_point == 'main_app', f"Expected entry_point 'main_app', got {entry_point!r}"
    print(f"Manifest entry point: {entry_point}")

    sig_status = db.get_code_signature_status(entry_point)
    print(f"Code signature: verified={sig_status['verified']} signer={sig_status['signer']} ({sig_status['method']})")
    assert sig_status['verified'], f"Code signature not verified: {sig_status['error']}"

    code_func = db.get_code(entry_point)
    assert code_func is not None, "Failed to load code from container"

    cn = _active_cn()
    key_path = os.path.join(PROJ_DIR, f'{cn}.key')
    cert_str = cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem
    widget = execute_micro_app(
        code_func, PROJ_DIR, db,
        current_user_cn=cn,
        current_user_cert_pem=cert_str,
        key_path=key_path,
        key_passphrase=_identity_passphrase(),
    )
    assert widget is not None, "Micro-app returned no widget"
    print(f"Sandbox returned widget: {type(widget).__name__} (id={widget.id})")
    # The task board carries an explicit widget id; the lockout view and the
    # sandbox's error-fallback box do not — so reaching it proves the signed
    # SELECT inside refresh() succeeded under the active identity.
    assert widget.id == 'dev_tracker_board', "Expected the task board, got a lockout/error view"
    db.close()
    print("\nDev Tracker container verified end-to-end (signed reads/writes + sandbox execution).")


def cmd_update_app():
    """Hot-deploy the current dev_tracker_app code into the existing container.

    A signed code replacement: task data is untouched, the new blob is signed
    and appended to the audit log, and get_code_signature_status() verifies the
    newest deployment. Reopen the document in the GUI to load the new UI.
    Non-admin identities are denied by RBAC (source_code is a system table).
    Homed replicas refuse update-app — operate on the hub copy.
    """
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if hub_cn:
        db.close()
        sys.exit(
            f"Refuse update-app: container is a homed replica (hub {hub_cn!r}). "
            "Deploy on the hub's copy, or use MSCHF_ALLOW_LOCAL_WRITES=1 only "
            "for orphan recovery (may fork)."
        )
    _ensure_schema(db, cert_pem, private_key)
    pickled = __import__('dill').dumps(dev_tracker_app)
    try:
        sig = sign_payload(db, private_key, "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)", ['main_app', pickled])
        db.store_code('main_app', dev_tracker_app, sig, cert_pem)
    except PermissionError as e:
        db.close()
        sys.exit(f"Permission denied: update-app requires admin identity ({e})")
    status = db.get_code_signature_status('main_app')
    db.close()
    assert status['verified'], f"Deployed code failed signature verification: {status['error']}"
    print("Deployed updated micro-app code to dev_tracker.msf (signed, verified).")
    print("Reopen the document in the GUI to load the new UI.")


def cmd_flush():
    """Flush pending sync_outbox intents for the active identity (homed only)."""
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    if not hub_cn:
        db.close()
        sys.exit("flush requires a homed container (manifest sync_hub_cn).")
    if not hub_url:
        db.close()
        sys.exit("flush requires sync_hub_url in the container manifest.")
    from mschf import sync as msync
    container_id = os.path.splitext(os.path.basename(db.filename))[0]
    cert = cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem
    summary = msync.flush_outbox(
        db, hub_url, container_id,
        private_key, cert, _active_cn(),
        expected_hub_cn=hub_cn,
        ca_cert_path=getattr(db, '_ca_cert_path_arg', None),
        trust_dir=getattr(db, 'trust_dir', None),
    )
    db.close()
    print(
        f"flush: flushed={summary['flushed']} failed={summary['failed']} "
        f"remaining={summary['remaining']} stopped_on={summary['stopped_on']}"
    )
    if summary['failed'] or summary['remaining']:
        sys.exit(1)


def cmd_audit():
    """Replay the signed ledger into a shadow DB and diff against live tables."""
    from mschf.audit import replay_audit, format_report
    db, cert_pem, private_key, hub_url, hub_cn = _open_for_cli()
    report = replay_audit(db)
    print(format_report(report))
    db.close()
    sys.exit(0 if report['ok'] else 1)


def _parse_global_flags(argv):
    """Pull global flags (e.g. --identity) out of argv; set _CLI_IDENTITY; return rest."""
    global _CLI_IDENTITY
    rest = []
    identity_cn = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == '--identity' and i + 1 < len(argv):
            identity_cn = argv[i + 1]
            i += 2
        elif arg.startswith('--identity='):
            identity_cn = arg.split('=', 1)[1]
            i += 1
        else:
            rest.append(arg)
            i += 1
    _CLI_IDENTITY = identity_cn
    return rest


def main():
    args = _parse_global_flags(sys.argv[1:])
    if not args:
        print(__doc__)
        sys.exit(1)
    cmd = args[0]
    if cmd == 'init':
        cmd_init()
    elif cmd == 'list':
        cmd_list()
    elif cmd == 'add' and len(args) >= 2:
        # Missing detail arg is refused cleanly (same as blank detail).
        cmd_add(args[1], args[2] if len(args) > 2 else "")
    elif cmd == 'describe' and len(args) >= 2:
        cmd_describe(args[1], args[2] if len(args) > 2 else "")
    elif cmd == 'status' and len(args) == 3:
        cmd_status(args[1], args[2])
    elif cmd == 'horizon' and len(args) == 3:
        cmd_horizon(args[1], args[2])
    elif cmd == 'link' and len(args) >= 3:
        cmd_link(args[1], args[2], args[3] if len(args) > 3 else 'related')
    elif cmd == 'links' and len(args) == 2:
        cmd_links(args[1])
    elif cmd == 'update-app':
        cmd_update_app()
    elif cmd == 'flush':
        cmd_flush()
    elif cmd == 'audit':
        cmd_audit()
    elif cmd == 'verify':
        cmd_verify()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
