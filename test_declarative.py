"""Declarative UI prototype tests (headless — toga widgets, no main loop).

Authors a small notes container with a JSON ``ui_spec`` manifest entry, renders
it via ``render_declarative``, and proves:

  * admin can read the seeded table and INSERT via the button action
  * viewer role can read but RBAC-denies the INSERT (status line, no crash)
  * identity without db-read gets the lockout box
  * malformed specs raise DeclarativeSpecError
  * replay_audit passes on the authored container
  * declarative.py imports neither exec/eval/dill
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath("src"))

import toga
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from mschf.audit import format_report, replay_audit
from mschf.declarative import (
    DeclarativeSpecError,
    render_declarative,
    resolve_ui_mode,
    spec_from_manifest,
)
from mschf.gen_cert import generate_selfsigned_cert, generate_user_cert
from mschf.sandbox import HostAPI
from mschf.storage import MSFStorage, canonical_payload

DB_PATH = "test_declarative.msf"
ARTIFACTS = [
    DB_PATH,
    "decl_admin.crt",
    "decl_admin.key",
    "decl_viewer.crt",
    "decl_viewer.key",
    "decl_guest.crt",
    "decl_guest.key",
]

NOTES_TRIGGER = """CREATE TRIGGER trg_notes_insert_audit AFTER INSERT ON notes
       BEGIN
         UPDATE notes SET
           created_at = COALESCE(NEW.created_at, datetime('now')),
           created_by = COALESCE(current_signer(), 'unsigned')
         WHERE id = NEW.id;
       END"""

SEED_NOTES = [
    "First signed note from authoring.",
    "Second note — visible to viewers.",
]

# Pure-data UI: title, notes table, input + Add button, status line.
UI_SPEC = {
    "type": "box",
    "direction": "column",
    "margin": 16,
    "children": [
        {
            "type": "label",
            "text": "Declarative Notes",
            "font_size": 18,
            "bold": True,
        },
        {
            "type": "label",
            "text_from": {"user": "common_name"},
            "font_size": 10,
            "color": "#666666",
        },
        {
            "type": "table",
            "id": "notes_table",
            "headings": ["Id", "Body", "By"],
            "query": {
                "sql": "SELECT id, body, created_by FROM notes ORDER BY id",
                "params": [],
            },
            "columns": [0, 1, 2],
            "flex": 1,
        },
        {
            "type": "box",
            "direction": "row",
            "children": [
                {
                    "type": "text_input",
                    "id": "note_body",
                    "placeholder": "Write a note...",
                    "flex": 1,
                },
                {
                    "type": "button",
                    "text": "Add",
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
        {"type": "status", "id": "status_line"},
    ],
}


def _cleanup():
    for f in ARTIFACTS:
        if os.path.exists(f):
            os.remove(f)


def _ensure_ca():
    ca_cert_path, ca_key_path = "ca.crt", "ca.key"
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        ca_pem, ca_key_pem = generate_selfsigned_cert("Temporary Root CA")
        with open(ca_cert_path, "wb") as f:
            f.write(ca_pem)
        with open(ca_key_path, "wb") as f:
            f.write(ca_key_pem)
    with open(ca_cert_path, "rb") as f:
        ca_cert_pem = f.read()
    with open(ca_key_path, "rb") as f:
        ca_key_pem = f.read()
    return ca_cert_path, ca_cert_pem, ca_key_pem


def _write_identity(cn, ca_cert_pem, ca_key_pem):
    cert_pem, key_pem = generate_user_cert(cn, ca_cert_pem, ca_key_pem)
    with open(f"{cn}.crt", "wb") as f:
        f.write(cert_pem)
    with open(f"{cn}.key", "wb") as f:
        f.write(key_pem)
    return cert_pem, key_pem


def _signer(db, key_pem):
    private_key = load_pem_private_key(key_pem, password=None)

    def sign(query, params):
        next_seq, prev_hash = db.get_chain_head()
        payload = canonical_payload(query, params, next_seq, prev_hash, db.container_uid)
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return sign


def _host_api(db, cn, cert_pem, key_path):
    return HostAPI(
        workspace_path=os.path.abspath("."),
        db=db,
        current_user_cn=cn,
        current_user_cert_pem=cert_pem,
        key_path=key_path,
        key_passphrase=None,
    )


def _walk(widget):
    """Yield widget and all descendants (Box children)."""
    yield widget
    children = getattr(widget, "children", None) or []
    for child in children:
        yield from _walk(child)


def _find_by_type(root, cls):
    return [w for w in _walk(root) if isinstance(w, cls)]


def _find_button(root, text):
    for w in _find_by_type(root, toga.Button):
        if getattr(w, "text", None) == text:
            return w
    raise AssertionError(f"no button with text {text!r}")


def _find_text_input(root):
    inputs = _find_by_type(root, toga.TextInput)
    assert inputs, "expected a TextInput"
    return inputs[0]


def _find_table(root):
    tables = _find_by_type(root, toga.Table)
    assert tables, "expected a Table"
    return tables[0]


def _find_status_label(root, exclude_texts=None):
    """Return the status Label (empty or italic outcome line), not title labels."""
    exclude_texts = set(exclude_texts or [])
    labels = _find_by_type(root, toga.Label)
    # Prefer a label that was empty at construction or starts with known prefixes.
    for lbl in labels:
        t = lbl.text or ""
        if t in exclude_texts:
            continue
        if t == "" or t.startswith("Success") or t.startswith("Blocked") or t.startswith("Query"):
            return lbl
    # Fallback: last label in tree (status is last in our spec)
    return labels[-1]


def author_container(ca_cert_path, admin_cert, admin_key, viewer_cert):
    """Bootstrap admin, notes schema+trigger, RBAC, seed rows, ui_spec manifest."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    db = MSFStorage(DB_PATH, ca_cert_path=ca_cert_path)
    sign = _signer(db, admin_key)

    # Schema is unsigned authoring (same pattern as starter / ledger tests).
    db.conn.execute(
        "CREATE TABLE notes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "body TEXT NOT NULL, "
        "created_at TEXT DEFAULT (datetime('now')), "
        "created_by TEXT)"
    )
    db.conn.commit()

    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    db.bootstrap_admin(
        q, ["entry_point", "declarative"], sign(q, ["entry_point", "declarative"]), admin_cert
    )

    db.execute_signed(NOTES_TRIGGER, [], sign(NOTES_TRIGGER, []), admin_cert)

    q = "INSERT INTO notes (body) VALUES (?)"
    for body in SEED_NOTES:
        db.execute_signed(q, [body], sign(q, [body]), admin_cert)

    # RBAC: viewer role — database read + object read on notes (no write).
    viewer_id = db._get_identity(viewer_cert)
    q = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
    db.execute_signed(q, [viewer_id, "viewer"], sign(q, [viewer_id, "viewer"]), admin_cert)

    q = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
    for params in (
        ["database", "*", "viewer", "read"],
        ["object", "notes", "viewer", "read"],
    ):
        db.execute_signed(q, params, sign(q, params), admin_cert)

    # Authoring a declarative UI is a signed set_manifest_item — pure data.
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    ui_json = json.dumps(UI_SPEC)
    db.set_manifest_item("ui_spec", ui_json, sign(q, ["ui_spec", ui_json]), admin_cert)
    db.set_manifest_item(
        "name", "Declarative Notes", sign(q, ["name", "Declarative Notes"]), admin_cert
    )

    return db


def test_admin_render_and_insert(db, admin_cert, admin_cn="decl_admin"):
    print("--- 1. Render as admin: table shows seeds; Add inserts + refreshes ---")
    host = _host_api(db, admin_cn, admin_cert, f"{admin_cn}.key")
    spec = spec_from_manifest(db)
    assert spec is not None, "ui_spec must be present in manifest"
    assert spec["type"] == "box"

    root = render_declarative(spec, toga, host)
    assert isinstance(root, toga.Box)

    table = _find_table(root)
    rows = list(table.data)
    assert len(rows) == len(SEED_NOTES), f"expected {len(SEED_NOTES)} seed rows, got {len(rows)}"
    # Toga slugifies headings ["#", "Body", "By"] → accessors like body / by.
    body_vals = [getattr(r, "body", None) for r in rows]
    assert body_vals == SEED_NOTES, f"table bodies={body_vals}"
    by_vals = [getattr(r, "by", None) for r in rows]
    assert all(v == f"cert:CN={admin_cn}" for v in by_vals), f"created_by stamps: {by_vals}"

    labels = _find_by_type(root, toga.Label)
    title_texts = [lbl.text for lbl in labels]
    assert any("Declarative Notes" in (t or "") for t in title_texts)
    assert any(admin_cn in (t or "") for t in title_texts), f"text_from user missing: {title_texts}"

    note_input = _find_text_input(root)
    note_input.value = "Admin-added note via declarative button"
    btn = _find_button(root, "Add")
    btn.on_press()  # Toga wrapped handler: no-arg invoke

    rows_after = list(table.data)
    assert len(rows_after) == 3, f"expected 3 rows after insert, got {len(rows_after)}"
    new_bodies = [getattr(r, "body", None) for r in rows_after]
    assert "Admin-added note via declarative button" in new_bodies

    # created_by stamped from signing identity (trigger + current_signer).
    raw = db.conn.execute(
        "SELECT body, created_by FROM notes WHERE body = ?",
        ["Admin-added note via declarative button"],
    ).fetchone()
    assert raw is not None
    assert raw[1] == f"cert:CN={admin_cn}", f"expected stamp, got {raw[1]}"

    status = _find_status_label(
        root, exclude_texts={"Declarative Notes", admin_cn}
    )
    assert "Success" in (status.text or ""), f"status should show success, got {status.text!r}"
    print("  [OK] admin render, insert, stamp, refresh, status")


def test_viewer_rbac_denial(db, viewer_cert, viewer_cn="decl_viewer"):
    print("--- 2. Render as viewer: table ok; Add denied in status, no insert ---")
    host = _host_api(db, viewer_cn, viewer_cert, f"{viewer_cn}.key")
    spec = spec_from_manifest(db)
    root = render_declarative(spec, toga, host)

    table = _find_table(root)
    n_before = len(list(table.data))
    assert n_before >= 2, "viewer must see seeded notes"

    count_before = db.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]

    note_input = _find_text_input(root)
    note_input.value = "viewer should not insert this"
    btn = _find_button(root, "Add")
    btn.on_press()  # must not raise

    count_after = db.conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    assert count_after == count_before, "viewer INSERT must not land"

    status = _find_status_label(
        root, exclude_texts={"Declarative Notes", viewer_cn}
    )
    st = status.text or ""
    assert "Blocked" in st or "denied" in st.lower() or "Access" in st, (
        f"status should show RBAC denial, got {st!r}"
    )
    print(f"  [OK] viewer read ok; Add blocked: {st}")


def test_lockout(db, guest_cert, guest_cn="decl_guest"):
    print("--- 3. Identity without db-read → lockout box ---")
    host = _host_api(db, guest_cn, guest_cert, f"{guest_cn}.key")
    spec = spec_from_manifest(db)
    root = render_declarative(spec, toga, host)

    assert isinstance(root, toga.Box)
    texts = [getattr(w, "text", None) for w in _walk(root)]
    assert any(t and "ACCESS DENIED" in t for t in texts), texts
    # Must not expose the notes table.
    assert not _find_by_type(root, toga.Table), "lockout must not include data tables"
    print("  [OK] lockout box for no-read identity")


def test_malformed_specs(db, admin_cert, admin_cn="decl_admin"):
    print("--- 4. Malformed specs raise DeclarativeSpecError ---")
    host = _host_api(db, admin_cn, admin_cert, f"{admin_cn}.key")

    cases = [
        (
            "unknown widget type",
            {"type": "webview", "url": "https://evil.example"},
        ),
        (
            "non-SELECT table query",
            {
                "type": "table",
                "id": "t",
                "headings": ["x"],
                "query": {"sql": "DELETE FROM notes", "params": []},
                "columns": [0],
            },
        ),
        (
            "args without ? placeholders",
            {
                "type": "box",
                "children": [
                    {"type": "text_input", "id": "x"},
                    {
                        "type": "button",
                        "text": "Go",
                        "action": {
                            "kind": "exec",
                            "sql": "INSERT INTO notes (body) VALUES ('hardcoded')",
                            "args": [{"input": "x"}],
                        },
                    },
                    {"type": "status", "id": "s"},
                ],
            },
        ),
        (
            "action refs missing input id",
            {
                "type": "box",
                "children": [
                    {
                        "type": "button",
                        "text": "Go",
                        "action": {
                            "kind": "exec",
                            "sql": "INSERT INTO notes (body) VALUES (?)",
                            "args": [{"input": "no_such_input"}],
                        },
                    },
                ],
            },
        ),
    ]

    for label, bad_spec in cases:
        try:
            render_declarative(bad_spec, toga, host)
            raise AssertionError(f"{label}: expected DeclarativeSpecError")
        except DeclarativeSpecError as e:
            print(f"  [OK] {label}: {e}")


def test_loader_mode_resolution(db):
    print("--- 7. Loader mode: declarative preferred; pickle/about fallbacks ---")
    # Authored container carries both entry_point and ui_spec → declarative wins.
    mode, payload = resolve_ui_mode(db)
    assert mode == "declarative", f"expected declarative, got {mode}"
    assert isinstance(payload, dict) and payload["type"] == "box"

    scratch = "test_declarative_modes.msf"
    if os.path.exists(scratch):
        os.remove(scratch)
    sdb = MSFStorage(scratch)
    try:
        assert resolve_ui_mode(sdb) == ("about", None)

        sdb.conn.execute(
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ("entry_point", "main"),
        )
        sdb.conn.commit()
        assert resolve_ui_mode(sdb) == ("pickle", "main")

        # Present-but-malformed ui_spec must hard-error, never fall through
        # to the pickle path.
        sdb.conn.execute(
            "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)",
            ("ui_spec", "{not valid json"),
        )
        sdb.conn.commit()
        try:
            resolve_ui_mode(sdb)
            raise AssertionError("malformed ui_spec must raise DeclarativeSpecError")
        except DeclarativeSpecError as e:
            print(f"  [OK] malformed ui_spec blocks the loader: {e}")
    finally:
        sdb.close()
        os.remove(scratch)
    print("  [OK] declarative > pickle > about resolution")


def test_manifest_signature_status(db):
    print("--- 8. ui_spec banner: verified clean; raw tamper detected ---")
    status = db.get_manifest_signature_status("ui_spec")
    assert status["verified"], f"clean ui_spec must verify: {status}"
    assert status["signer"] == "decl_admin", status
    print(f"  [OK] verified, signer={status['signer']}, method={status['method']}")

    # Out-of-band edit of the manifest value (skips execute_signed).
    original = db.get_manifest_item("ui_spec")
    tampered = json.dumps({"type": "box", "children": []})
    db.conn.execute(
        "UPDATE manifest SET value = ? WHERE key = ?", (tampered, "ui_spec"))
    db.conn.commit()
    status = db.get_manifest_signature_status("ui_spec")
    assert not status["verified"], "tampered ui_spec must not verify"
    assert "tampered" in (status["error"] or "").lower(), status
    print(f"  [OK] raw tamper flagged: {status['error']}")

    # Restore for the later replay-audit test.
    db.conn.execute(
        "UPDATE manifest SET value = ? WHERE key = ?", (original, "ui_spec"))
    db.conn.commit()
    assert db.get_manifest_signature_status("ui_spec")["verified"]

    # A key never written through a signed transaction has no proof.
    status = db.get_manifest_signature_status("no_such_key")
    assert not status["verified"]
    assert "No signed transaction" in (status["error"] or ""), status
    print("  [OK] unsigned key reports no signing transaction")


def test_headless_import():
    print("--- 9. mschf.declarative imports without toga (loader helpers headless) ---")
    import subprocess

    code = (
        "import sys; sys.path.insert(0, 'src'); sys.modules['toga'] = None; "
        "from mschf.declarative import resolve_ui_mode, DeclarativeSpecError; "
        "print('headless-ok')"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=os.getcwd()
    )
    assert out.returncode == 0 and "headless-ok" in out.stdout, (
        f"headless import failed: {out.stderr}"
    )
    print("  [OK] no module-level toga dependency")


def test_replay_audit(db):
    print("--- 5. replay_audit on authored container ---")
    report = replay_audit(db)
    print(format_report(report))
    assert report["ok"], f"replay_audit failed: {report}"
    print("  [OK] ledger fully explains the container")


def test_no_dangerous_imports():
    print("--- 6. declarative.py has no exec/eval/dill usage ---")
    path = os.path.join("src", "mschf", "declarative.py")
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    # Strip comments / docstrings roughly by checking import and call patterns.
    # Require: no import of dill; no bare exec( or eval( call sites.
    for bad in ("import dill", "from dill", "import eval", "from eval"):
        assert bad not in src, f"forbidden pattern in declarative.py: {bad}"
    # exec/eval as function calls (not the word in comments like "no exec")
    # Allow mentions in comments/docstrings; forbid actual call/import forms.
    assert "dill." not in src
    assert "dill(" not in src
    # Actual call forms
    assert not re_search_call(src, "exec")
    assert not re_search_call(src, "eval")
    print("  [OK] no exec/eval/dill in declarative.py")


def re_search_call(src, name):
    """True if ``name(`` appears outside of comments and string/doc contexts.

    Conservative: strip # line comments and triple-quoted strings, then look
    for the call form. Mentions inside remaining single-line strings are rare
    enough that we only check the call pattern ``name(``.
    """
    import re

    # Remove triple-quoted blocks
    cleaned = re.sub(r'""".*?"""', '""', src, flags=re.DOTALL)
    cleaned = re.sub(r"'''.*?'''", "''", cleaned, flags=re.DOTALL)
    # Remove # comments
    lines = []
    for line in cleaned.splitlines():
        if "#" in line:
            line = line[: line.index("#")]
        lines.append(line)
    cleaned = "\n".join(lines)
    return re.search(rf"\b{name}\s*\(", cleaned) is not None


def run():
    _cleanup()
    ca_cert_path, ca_cert_pem, ca_key_pem = _ensure_ca()

    admin_cert, admin_key = _write_identity("decl_admin", ca_cert_pem, ca_key_pem)
    viewer_cert, viewer_key = _write_identity("decl_viewer", ca_cert_pem, ca_key_pem)
    guest_cert, guest_key = _write_identity("decl_guest", ca_cert_pem, ca_key_pem)
    del viewer_key, guest_key  # keys on disk for HostAPI

    print("--- Authoring declarative notes container ---")
    db = author_container(ca_cert_path, admin_cert, admin_key, viewer_cert)
    raw = db.get_manifest_item("ui_spec")
    assert raw and json.loads(raw)["type"] == "box"
    print("  [OK] ui_spec stored via signed set_manifest_item")

    try:
        test_admin_render_and_insert(db, admin_cert)
        test_viewer_rbac_denial(db, viewer_cert)
        test_lockout(db, guest_cert)
        test_malformed_specs(db, admin_cert)
        test_loader_mode_resolution(db)
        test_manifest_signature_status(db)
        test_headless_import()
        test_replay_audit(db)
        test_no_dangerous_imports()
    finally:
        db.close()
        _cleanup()

    print("\n==========================================")
    print("ALL DECLARATIVE UI TESTS PASSED")
    print("==========================================")
    # Toga/WinForms can AV on process teardown after headless widget
    # construction; force a clean 0 exit so CI does not treat that as failure.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    run()
