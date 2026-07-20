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
  python dev_tracker.py add "title" ["detail"]   # add a backlog task (signed INSERT)
  python dev_tracker.py status <id> <backlog|in_progress|done>
  python dev_tracker.py update-app               # hot-deploy the current UI code (keeps task data)
  python dev_tracker.py verify                   # load the .msf and run it through the sandbox
  python dev_tracker.py audit                    # replay the signed ledger; flag out-of-band writes

  Examples:
    python dev_tracker.py --identity grok list
    MSCHF_TRACKER_IDENTITY=grok python dev_tracker.py add "task title"
"""
import sys
import os

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
    """Idempotent, signed migration of dev_tasks to the attribution schema.

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

    LABELS = {'in_progress': '● In Progress', 'backlog': '○ Backlog', 'done': '✓ Done'}
    details = {}   # task id -> detail text, filled by refresh()

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
                                          style=P(height=56, font_size=10, margin_bottom=8))
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
                "SELECT id, title, status, created_at, created_by, updated_at, updated_by, detail "
                "FROM dev_tasks "
                "ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'backlog' THEN 1 ELSE 2 END, id"
            )
            rows = cursor.fetchall()
            details.clear()
            details.update({r[0]: (r[7] or "").strip() for r in rows})
            # Trim timestamps to minute resolution and identities to bare CNs
            # to keep the columns compact.
            who = lambda w: (w or "?").replace('cert:CN=', '')
            table.data = [(r[0], r[1], LABELS.get(r[2], r[2]),
                           (r[3] or "")[:16], who(r[4]), (r[5] or "")[:16], who(r[6]))
                          for r in rows]
            tune_columns()
            n = {'backlog': 0, 'in_progress': 0, 'done': 0}
            for r in rows:
                n[r[2]] = n.get(r[2], 0) + 1
            counts_label.text = f"{n['backlog']} backlog · {n['in_progress']} in progress · {n['done']} done"
            status_label.text = "Ready."
        except Exception as e:
            status_label.text = f"Query blocked: {e}"

    def on_select(widget):
        row = table.selection
        if row is None:
            detail_view.value = ""
        else:
            detail_view.value = details.get(row.num) or "(no detail)"
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
                status_label.text = f"Blocked by RBAC: {e}"
        return handler

    actions = toga.Box(style=P(direction='row', margin_bottom=12))
    actions.add(toga.Button("● Mark In Progress", on_press=set_status('in_progress'), style=P(margin_right=8)))
    actions.add(toga.Button("✓ Mark Done", on_press=set_status('done'), style=P(margin_right=8)))
    actions.add(toga.Button("○ Back to Backlog", on_press=set_status('backlog'), style=P(margin_right=8)))
    actions.add(toga.Box(style=P(flex=1)))
    actions.add(toga.Button("Refresh", on_press=refresh))
    board.add(actions)

    # --- New task ---
    new_row = toga.Box(style=P(direction='row'))
    title_input = toga.TextInput(placeholder="New task title...", style=P(flex=1, margin_right=8))

    def add_task(widget):
        title = (title_input.value or "").strip()
        if not title:
            status_label.text = "Enter a task title first."
            return
        try:
            host_api.execute_signed_query(
                "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, 'backlog')",
                [title, ""]
            )
            title_input.value = ""
            status_label.text = f"Added '{title}' (signed by {cn})."
            refresh()
        except Exception as e:
            status_label.text = f"Blocked by RBAC: {e}"

    new_row.add(title_input)
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
    cert_pem, private_key = load_admin_identity()

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = MSFStorage(DB_PATH)

    # Schema is an authoring step, like test_microapp.py's provisioning.
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
    cert_pem, private_key = load_identity()
    if not os.path.exists(DB_PATH):
        sys.exit("dev_tracker.msf not found — run: python dev_tracker.py init")
    return MSFStorage(DB_PATH), cert_pem, private_key


def cmd_list():
    db, cert_pem, private_key = _open_for_cli()
    _ensure_schema(db, cert_pem, private_key)
    cursor = signed_exec(db, cert_pem, private_key,
                         "SELECT id, title, status, created_at, created_by, updated_at, updated_by FROM dev_tasks "
                         "ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'backlog' THEN 1 ELSE 2 END, id", [])
    rows = cursor.fetchall()
    tags = {'in_progress': 'WIP ', 'backlog': 'TODO', 'done': 'DONE'}
    strip = lambda who: (who or '?').replace('cert:CN=', '')
    for r in rows:
        print(f"  [{tags.get(r[2], '??? ')}] #{r[0]} {r[1]}  "
              f"(created {r[3]} by {strip(r[4])}; updated {r[5]} by {strip(r[6])})")
    done = sum(1 for r in rows if r[2] == 'done')
    print(f"\n{len(rows)} tasks, {done} done.")
    db.close()


def cmd_add(title, detail=""):
    db, cert_pem, private_key = _open_for_cli()
    _ensure_schema(db, cert_pem, private_key)
    signed_exec(db, cert_pem, private_key,
                "INSERT INTO dev_tasks (title, detail, status) VALUES (?, ?, 'backlog')",
                [title, detail])
    print(f"Added backlog task: {title}")
    db.close()


def cmd_status(task_id, new_status):
    if new_status not in VALID_STATUSES:
        sys.exit(f"Invalid status '{new_status}' — use one of {VALID_STATUSES}")
    db, cert_pem, private_key = _open_for_cli()
    _ensure_schema(db, cert_pem, private_key)
    signed_exec(db, cert_pem, private_key,
                "UPDATE dev_tasks SET status = ? WHERE id = ?",
                [new_status, int(task_id)])
    cursor = signed_exec(db, cert_pem, private_key, "SELECT title FROM dev_tasks WHERE id = ?", [int(task_id)])
    row = cursor.fetchone()
    print(f"Task #{task_id} ({row[0] if row else '?'}) -> {new_status}")
    db.close()


def cmd_verify():
    """Load dev_tracker.msf and run it through the real sandbox, headless."""
    from mschf.sandbox import execute_micro_app
    import toga

    db, cert_pem, private_key = _open_for_cli()
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
    widget = execute_micro_app(
        code_func, PROJ_DIR, db,
        current_user_cn=cn,
        current_user_cert_pem=cert_pem.decode('utf-8'),
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
    """
    db, cert_pem, private_key = _open_for_cli()
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


def cmd_audit():
    """Replay the signed ledger into a shadow DB and diff against live tables."""
    from mschf.audit import replay_audit, format_report
    db, cert_pem, private_key = _open_for_cli()
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
        cmd_add(args[1], args[2] if len(args) > 2 else "")
    elif cmd == 'status' and len(args) == 3:
        cmd_status(args[1], args[2])
    elif cmd == 'update-app':
        cmd_update_app()
    elif cmd == 'audit':
        cmd_audit()
    elif cmd == 'verify':
        cmd_verify()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
