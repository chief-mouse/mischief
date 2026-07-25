import os
import threading
import json

import toga
from toga.style import Pack

from mschf.storage import MSFStorage
from mschf.sandbox import HostAPI, execute_micro_app
from mschf.declarative import (
    DeclarativeSpecError,
    render_declarative,
    resolve_ui_mode,
)
from mschf.syncstate import (
    format_sync_status_line,
    record_sync_render_facts,
    is_sync_render_stale,
    _sync_subscriber_main,
)
from mschf import editor as mschf_editor
from mschf.widgets import label as ui_label, message_widget, set_message


class MSF(toga.Document):
    description = "Mischief Storage Facility"
    extensions = ["msf"]
    
    def create(self) -> None:
        """Create the window for the document."""
        self.main_window = toga.Window(
            title=self.title,
            position=(200, 200),
            size=(984, 576),
            closable=True,
            on_close=self.on_window_close
        )
        
        self.main_box = toga.Box(style=Pack(direction='column', margin=10))
        self.main_window.content = self.main_box
        self.db = None
        self._change_baseline = None
        self._sync_stop = None
        self._sync_thread = None
        # Snapshot of connected/outbox_pending last painted into the status line
        # (see record_sync_render_facts). Compared by sync_render_stale().
        self._rendered_sync = None
        # No-code editor (admin-only): when True, redraw paints the editor view.
        self._editor_open = False
        self._editor_ui_input = None
        self._editor_schema_input = None
        self._editor_status = None
        self._helper_dialog = None

    def read(self) -> None:
        """Load representation of the document from self.path and populate the window."""
        if self.path and self.path.exists():
            ca_cert_path = getattr(self.app, "ca_cert_path", None)
            self.db = MSFStorage(str(self.path), ca_cert_path=ca_cert_path)
            # In-process reactive redraw: a mutating signed transaction on this
            # document's connection (e.g. from its sandboxed micro-app) tells
            # the app to refresh other open documents on the same file.
            self.db.on_commit = self._on_db_commit
            self._change_baseline = None
            self._start_sync_subscriber()
            self.redraw()

    def _start_sync_subscriber(self) -> None:
        """If homed with a hub URL, start a daemon long-poll subscriber thread."""
        self._stop_sync_subscriber()
        if not self.db or not self.path:
            return
        try:
            from mschf import sync as msync
            hub_url, hub_cn = msync.homing(self.db)
        except Exception:
            return
        if not hub_cn:
            return
        # No URL → status line shows "no url configured"; skip the thread.
        if not hub_url:
            return

        stop_event = threading.Event()
        path = str(self.path)
        container_id = os.path.splitext(os.path.basename(path))[0]
        ca_cert_path = getattr(self.app, "ca_cert_path", None) if self.app else None
        ca_cert_path = ca_cert_path or getattr(self.db, '_ca_cert_path_arg', None)
        trust_dir = getattr(self.db, 'trust_dir', None)

        # Thread records connected / last_applied_at / storage_conn_id on itself.
        thread = threading.Thread(
            target=lambda: _sync_subscriber_main(
                path, hub_url, container_id, stop_event, hub_cn,
                ca_cert_path, trust_dir, thread,
            ),
            daemon=True,
            name=f'mschf-sync-{container_id}',
        )
        thread.connected = False
        thread.last_applied_at = None
        thread.storage_conn_id = None
        self._sync_stop = stop_event
        self._sync_thread = thread
        thread.start()

    def _stop_sync_subscriber(self) -> None:
        """Signal the subscriber to stop and join briefly (best-effort)."""
        stop = getattr(self, '_sync_stop', None)
        thr = getattr(self, '_sync_thread', None)
        if stop is not None:
            try:
                stop.set()
            except Exception:
                pass
        if thr is not None and thr.is_alive():
            try:
                thr.join(timeout=2.0)
            except Exception:
                pass
        self._sync_stop = None
        self._sync_thread = None

    def _sync_status_text(self):
        """Recompute the sync status line from local facts only (no network).

        Also records the facts that were painted (``_rendered_sync``) so the
        ~2s poll can detect live↔offline / outbox deltas that change no data.
        """
        if not self.db:
            self._rendered_sync = None
            return None
        try:
            from mschf import sync as msync
            hub_url, hub_cn = msync.homing(self.db)
            if not hub_cn:
                self._rendered_sync = None
                return None
            status = msync.sync_status(self.db)  # no probe
            connected = False
            thr = getattr(self, '_sync_thread', None)
            if thr is not None:
                connected = bool(getattr(thr, 'connected', False))
            # One status dict drives both the label and the staleness snapshot.
            self._rendered_sync = record_sync_render_facts(status, connected)
            return format_sync_status_line(
                status, connected, has_hub_url=bool(hub_url),
            )
        except Exception:
            return None

    def sync_render_stale(self) -> bool:
        """True if the painted sync status line is stale vs local facts.

        Cheap: ``sync_status(self.db)`` without a network probe, plus the
        subscriber thread's ``connected`` flag. Main-thread only; never raises.
        """
        try:
            if not self.db:
                return False
            from mschf import sync as msync
            status = msync.sync_status(self.db)  # no probe
            thr = getattr(self, '_sync_thread', None)
            connected = bool(getattr(thr, 'connected', False)) if thr is not None else False
            return is_sync_render_stale(
                getattr(self, '_rendered_sync', None),
                status,
                connected,
            )
        except Exception:
            return False

    def _on_db_commit(self, storage) -> None:
        notify = getattr(self.app, "notify_msf_commit", None)
        if notify:
            notify(self)

    def _current_change_marker(self):
        """(data_version, last mutating ledger id) for external-change detection.

        PRAGMA data_version only moves when *another* connection changed the
        file — but signed reads append audit rows, so data_version alone would
        make co-open documents refresh each other forever. The ledger high-water
        mark of non-SELECT transactions pins redraws to actual mutations.
        """
        try:
            dv = self.db.conn.execute("PRAGMA data_version").fetchone()[0]
            wid = self.db.conn.execute(
                "SELECT IFNULL(MAX(id), 0) FROM transactions WHERE query NOT LIKE 'SELECT%'"
            ).fetchone()[0]
            return (dv, wid)
        except Exception:
            return None

    def check_external_change(self) -> bool:
        """Return True if another connection mutated the file (caller should redraw).

        Does not redraw itself — the app poll combines this with
        ``sync_render_stale()`` into a single redraw.
        """
        if not self.db:
            return False
        marker = self._current_change_marker()
        if marker is None or self._change_baseline is None:
            self._change_baseline = marker
            return False
        if marker[0] == self._change_baseline[0]:
            return False  # nothing changed on other connections
        if marker[1] == self._change_baseline[1]:
            # Other-connection activity was only audit rows from signed reads;
            # advance the baseline without a redraw.
            self._change_baseline = marker
            return False
        return True

    def redraw(self) -> None:
        if not self.db:
            return
        try:
            self._draw_content()
        finally:
            self._change_baseline = self._current_change_marker()

    def _security_banner(self, status, source_text=None):
        """Build the signature-status header row shared by both UI modes."""
        status_text = (
            "🛡️ CRYPTO ACTIVE: VERIFIED" if status['verified']
            else "🚨 CRYPTO WARNING: UNVERIFIED OR TAMPERED"
        )
        header_box = toga.Box(style=Pack(direction='row', margin=10))
        header_box.add(ui_label(toga, status_text, style=Pack(font_weight='bold', margin_right=15)))
        header_box.add(ui_label(toga, f"Signer CN: {status['signer']}", style=Pack(margin_right=15)))
        header_box.add(ui_label(toga, f"Method: {status['method']}", style=Pack(font_size=9)))
        if source_text:
            header_box.add(ui_label(toga, source_text, style=Pack(font_size=9, margin_left=15)))
        return header_box

    def _can_show_edit_app(self) -> bool:
        """Admin of this container and not a homed replica."""
        if not self.db:
            return False
        active_id = getattr(self.app, "active_identity", None)
        if not active_id or not getattr(active_id, "cert_pem", None):
            return False
        try:
            return mschf_editor.can_edit_app(self.db, active_id.cert_pem)
        except Exception:
            return False

    def _with_edit_affordance(self, content):
        """Wrap document content with admin-only Edit App button when eligible."""
        if not self._can_show_edit_app():
            return content
        outer = toga.Box(style=Pack(direction='column', flex=1))
        bar = toga.Box(style=Pack(direction='row', margin=4))
        bar.add(toga.Button(
            "Edit App",
            on_press=self._open_editor,
            style=Pack(margin=4),
        ))
        outer.add(bar)
        try:
            content.style.flex = 1
        except Exception:
            pass
        outer.add(content)
        return outer

    def _set_document_content(self, widget) -> None:
        self.main_window.content = self._with_edit_affordance(widget)

    def _wrap_app_widget(self, app_widget, status, source_text=None):
        """Banner + optional sync-status line + the micro-app widget."""
        wrapper_box = toga.Box(style=Pack(direction='column', margin=5))
        wrapper_box.add(self._security_banner(status, source_text))

        # Homed containers: second, smaller sync-status line (local facts only).
        sync_text = self._sync_status_text()
        if sync_text:
            wrapper_box.add(ui_label(
                toga,
                sync_text,
                style=Pack(font_size=9, color='#555555', margin_left=10, margin_bottom=4),
            ))

        app_widget.style.flex = 1
        wrapper_box.add(app_widget)
        return wrapper_box

    def _show_spec_error(self, error) -> None:
        """A present-but-broken ui_spec is a hard error view — never a silent
        fallback to executing pickled code."""
        box = toga.Box(style=Pack(direction='column', margin=20))
        box.add(ui_label(
            toga,
            "🚨 DECLARATIVE UI ERROR",
            style=Pack(font_size=20, font_weight='bold', margin_bottom=10, color='red')))
        box.add(ui_label(
            toga,
            "This container's ui_spec manifest entry could not be rendered:",
            style=Pack(margin_bottom=8)))
        box.add(message_widget(toga, str(error), kind="error", min_height=120))
        self._set_document_content(box)

    def _draw_declarative(self, spec) -> None:
        """Render manifest ui_spec via the declarative renderer (no exec/dill).

        The db-read gate lives inside render_declarative (fixed lockout box).
        The banner verifies the ui_spec manifest value against its signing
        ledger row — pure data, so the signed transaction IS the integrity
        proof (no code blob to hash).
        """
        workspace_path = os.path.dirname(os.path.abspath(str(self.path)))
        active_id = getattr(self.app, "active_identity", None)
        host_api = HostAPI(
            workspace_path,
            self.db,
            current_user_cn=active_id.cn if active_id else "Unknown",
            current_user_cert_pem=active_id.cert_pem if active_id else "",
            key_path=active_id.key_path if active_id else None,
            key_passphrase=active_id.key_passphrase if active_id else None,
        )
        try:
            app_widget = render_declarative(spec, toga, host_api)
        except DeclarativeSpecError as e:
            self._show_spec_error(e)
            return

        status = self.db.get_manifest_signature_status('ui_spec')
        self._set_document_content(self._wrap_app_widget(
            app_widget, status, "UI: signed manifest (declarative)"
        ))

    def _load_active_private_key(self):
        """Load the active identity's private key for signed editor saves."""
        active_id = getattr(self.app, "active_identity", None)
        if not active_id or not getattr(active_id, "key_path", None):
            raise mschf_editor.EditorError(
                "No active identity with a private key — sign in as container admin."
            )
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        with open(active_id.key_path, "rb") as f:
            key_pem = f.read()
        password = (
            active_id.key_passphrase.encode("utf-8")
            if getattr(active_id, "key_passphrase", None)
            else None
        )
        return load_pem_private_key(key_pem, password=password), active_id.cert_pem

    def _open_editor(self, widget=None) -> None:
        self._editor_open = True
        self.redraw()

    def _close_editor(self, widget=None) -> None:
        self._editor_open = False
        self._editor_ui_input = None
        self._editor_schema_input = None
        self._editor_status = None
        self.redraw()

    def _editor_set_status(self, msg) -> None:
        if self._editor_status is not None:
            set_message(self._editor_status, str(msg) if msg else "")

    def _draw_editor(self) -> None:
        """Thin wiring: two JSON text areas + validate/save/cancel + helpers."""
        texts = mschf_editor.load_spec_texts(self.db)

        root = toga.Box(style=Pack(direction='column', margin=8, flex=1))
        root.add(ui_label(
            toga,
            "Edit App — ui_spec / schema_spec (signed on Save)",
            style=Pack(font_size=14, font_weight='bold', margin_bottom=6),
        ))

        # --- ui_spec ---
        root.add(ui_label(toga, "ui_spec", style=Pack(font_weight='bold', margin_top=4)))
        ui_input = toga.MultilineTextInput(style=Pack(flex=1, margin=4))
        ui_input.value = texts.get("ui_spec") or ""
        self._editor_ui_input = ui_input
        root.add(ui_input)

        # --- schema_spec ---
        root.add(ui_label(toga, "schema_spec", style=Pack(font_weight='bold', margin_top=4)))
        schema_input = toga.MultilineTextInput(style=Pack(flex=1, margin=4))
        schema_input.value = texts.get("schema_spec") or ""
        self._editor_schema_input = schema_input
        root.add(schema_input)

        # Validation / save errors can be many lines — wrap, don't blow layout.
        status = message_widget(toga, "", kind="info", min_height=96)
        self._editor_status = status
        root.add(status)

        btn_row = toga.Box(style=Pack(direction='row', margin=4))
        btn_row.add(toga.Button("Validate", on_press=self._editor_validate, style=Pack(margin=4)))
        btn_row.add(toga.Button("Save", on_press=self._editor_save, style=Pack(margin=4)))
        btn_row.add(toga.Button("Cancel", on_press=self._close_editor, style=Pack(margin=4)))
        btn_row.add(toga.Button(
            "Add object…", on_press=self._helper_prompt_add_object, style=Pack(margin=4)))
        btn_row.add(toga.Button(
            "Add list view…", on_press=self._helper_prompt_add_list_view, style=Pack(margin=4)))
        btn_row.add(toga.Button(
            "Add rule…", on_press=self._helper_prompt_add_rule, style=Pack(margin=4)))
        root.add(btn_row)

        self.main_window.content = root

    def _editor_validate(self, widget=None) -> None:
        ui_text = self._editor_ui_input.value if self._editor_ui_input else ""
        sch_text = self._editor_schema_input.value if self._editor_schema_input else ""
        errs = []
        if ui_text.strip():
            errs.extend(
                f"ui_spec: {e}" for e in mschf_editor.validate_ui_spec_text(ui_text)
            )
        else:
            errs.append("ui_spec: (empty)")
        if sch_text.strip():
            errs.extend(
                f"schema_spec: {e}"
                for e in mschf_editor.validate_schema_spec_text(sch_text)
            )
        if errs:
            self._editor_set_status("Validation errors:\n" + "\n".join(errs))
        else:
            self._editor_set_status("Valid.")

    def _editor_save(self, widget=None) -> None:
        """Validate both → save schema then ui (no partial on validation failure)."""
        ui_text = self._editor_ui_input.value if self._editor_ui_input else ""
        sch_text = self._editor_schema_input.value if self._editor_schema_input else ""

        ui_errs = mschf_editor.validate_ui_spec_text(ui_text) if ui_text.strip() else [
            "ui_spec is empty"
        ]
        sch_errs = []
        if sch_text.strip():
            sch_errs = mschf_editor.validate_schema_spec_text(sch_text)
        if ui_errs or sch_errs:
            msgs = [f"ui_spec: {e}" for e in ui_errs] + [
                f"schema_spec: {e}" for e in sch_errs
            ]
            self._editor_set_status("Save refused — validation failed:\n" + "\n".join(msgs))
            return

        try:
            private_key, cert_pem = self._load_active_private_key()
            # Schema first: evolution may refuse without signing; ui not touched yet.
            if sch_text.strip():
                mschf_editor.save_schema_spec(
                    self.db, private_key, cert_pem, sch_text
                )
            mschf_editor.save_ui_spec(self.db, private_key, cert_pem, ui_text)
        except Exception as e:
            self._editor_set_status(f"Save failed: {e}")
            return

        self._editor_open = False
        self._editor_ui_input = None
        self._editor_schema_input = None
        self._editor_status = None
        self.redraw()

    def _close_helper_dialog(self) -> None:
        dlg = getattr(self, "_helper_dialog", None)
        if dlg is not None:
            try:
                dlg.close()
            except Exception:
                pass
        self._helper_dialog = None

    def _helper_prompt_add_object(self, widget=None) -> None:
        """Minimal prompt → helper_add_object → land in schema text area."""
        self._close_helper_dialog()
        name_in = toga.TextInput(placeholder="object name (e.g. items)", style=Pack(margin=4, flex=1))
        fields_in = toga.TextInput(
            placeholder="fields: name:type:rule,...  e.g. title:text:required,amount:real",
            style=Pack(margin=4, flex=1),
        )
        err_lbl = message_widget(toga, "", kind="error", min_height=48)

        def apply_helper(w=None):
            name = (name_in.value or "").strip()
            raw = (fields_in.value or "").strip()
            if not name or not raw:
                set_message(err_lbl, "Name and fields are required.")
                return
            fields = []
            try:
                for part in raw.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    bits = [b.strip() for b in part.split(":")]
                    if len(bits) < 2:
                        raise ValueError(f"bad field entry {part!r}")
                    fname, ftype = bits[0], bits[1]
                    rules = [r for r in bits[2:] if r] if len(bits) > 2 else []
                    fields.append((fname, ftype, rules))
                schema = json.loads(self._editor_schema_input.value or "{}")
                if "v" not in schema:
                    schema["v"] = 1
                if "objects" not in schema:
                    schema["objects"] = []
                new_spec = mschf_editor.helper_add_object(schema, name, fields)
                self._editor_schema_input.value = json.dumps(
                    new_spec, indent=2, sort_keys=True
                )
                self._editor_set_status(
                    f"Helper add_object({name!r}) applied — review and Save."
                )
                self._close_helper_dialog()
            except Exception as e:
                set_message(err_lbl, str(e))

        box = toga.Box(style=Pack(direction='column', margin=10))
        box.add(ui_label(toga, "Add object", style=Pack(font_weight='bold', margin_bottom=6)))
        box.add(name_in)
        box.add(fields_in)
        box.add(err_lbl)
        row = toga.Box(style=Pack(direction='row'))
        row.add(toga.Button("Apply", on_press=apply_helper, style=Pack(margin=4)))
        row.add(toga.Button(
            "Cancel", on_press=lambda w: self._close_helper_dialog(), style=Pack(margin=4)))
        box.add(row)
        win = toga.Window(title="Add object…", size=(480, 240))
        win.content = box
        self._helper_dialog = win
        win.show()

    def _helper_prompt_add_list_view(self, widget=None) -> None:
        self._close_helper_dialog()
        obj_in = toga.TextInput(placeholder="object name", style=Pack(margin=4, flex=1))
        cols_in = toga.TextInput(
            placeholder="columns: title,body", style=Pack(margin=4, flex=1))
        err_lbl = message_widget(toga, "", kind="error", min_height=48)

        def apply_helper(w=None):
            object_name = (obj_in.value or "").strip()
            cols_raw = (cols_in.value or "").strip()
            if not object_name or not cols_raw:
                set_message(err_lbl, "Object name and columns are required.")
                return
            try:
                columns = [c.strip() for c in cols_raw.split(",") if c.strip()]
                ui = json.loads(self._editor_ui_input.value or "{}")
                new_spec = mschf_editor.helper_add_list_view(ui, object_name, columns)
                self._editor_ui_input.value = json.dumps(
                    new_spec, indent=2, sort_keys=True
                )
                self._editor_set_status(
                    f"Helper add_list_view({object_name!r}) applied — review and Save."
                )
                self._close_helper_dialog()
            except Exception as e:
                set_message(err_lbl, str(e))

        box = toga.Box(style=Pack(direction='column', margin=10))
        box.add(ui_label(toga, "Add list view", style=Pack(font_weight='bold', margin_bottom=6)))
        box.add(obj_in)
        box.add(cols_in)
        box.add(err_lbl)
        row = toga.Box(style=Pack(direction='row'))
        row.add(toga.Button("Apply", on_press=apply_helper, style=Pack(margin=4)))
        row.add(toga.Button(
            "Cancel", on_press=lambda w: self._close_helper_dialog(), style=Pack(margin=4)))
        box.add(row)
        win = toga.Window(title="Add list view…", size=(420, 220))
        win.content = box
        self._helper_dialog = win
        win.show()

    def _helper_prompt_add_rule(self, widget=None) -> None:
        self._close_helper_dialog()
        obj_in = toga.TextInput(placeholder="object name", style=Pack(margin=4, flex=1))
        field_in = toga.TextInput(
            placeholder="field name (empty = object-level rule)",
            style=Pack(margin=4, flex=1),
        )
        rule_in = toga.TextInput(
            placeholder="rule (e.g. required or owner_only_update)",
            style=Pack(margin=4, flex=1),
        )
        err_lbl = message_widget(toga, "", kind="error", min_height=48)

        def apply_helper(w=None):
            object_name = (obj_in.value or "").strip()
            field = (field_in.value or "").strip() or None
            rule = (rule_in.value or "").strip()
            if not object_name or not rule:
                set_message(err_lbl, "Object name and rule are required.")
                return
            try:
                # Allow simple JSON object rules like {"enum":["a","b"]}
                if rule.startswith("{"):
                    rule_val = json.loads(rule)
                else:
                    rule_val = rule
                schema = json.loads(self._editor_schema_input.value or "{}")
                new_spec = mschf_editor.helper_add_rule(
                    schema, object_name, field, rule_val
                )
                self._editor_schema_input.value = json.dumps(
                    new_spec, indent=2, sort_keys=True
                )
                self._editor_set_status(
                    f"Helper add_rule({object_name!r}, {field!r}) applied — review and Save."
                )
                self._close_helper_dialog()
            except Exception as e:
                set_message(err_lbl, str(e))

        box = toga.Box(style=Pack(direction='column', margin=10))
        box.add(ui_label(toga, "Add rule", style=Pack(font_weight='bold', margin_bottom=6)))
        box.add(obj_in)
        box.add(field_in)
        box.add(rule_in)
        box.add(err_lbl)
        row = toga.Box(style=Pack(direction='row'))
        row.add(toga.Button("Apply", on_press=apply_helper, style=Pack(margin=4)))
        row.add(toga.Button(
            "Cancel", on_press=lambda w: self._close_helper_dialog(), style=Pack(margin=4)))
        box.add(row)
        win = toga.Window(title="Add rule…", size=(420, 260))
        win.content = box
        self._helper_dialog = win
        win.show()

    def _draw_content(self) -> None:
        if getattr(self, "_editor_open", False):
            self._draw_editor()
            return

        try:
            ui_mode, ui_payload = resolve_ui_mode(self.db)
        except DeclarativeSpecError as e:
            self._show_spec_error(e)
            return

        if ui_mode == 'declarative':
            self._draw_declarative(ui_payload)
            return

        entry_point_id = ui_payload if ui_mode == 'pickle' else None

        if entry_point_id:
            code_func = self.db.get_code(entry_point_id)
            if code_func:
                workspace_path = os.path.dirname(os.path.abspath(str(self.path)))
                active_id = getattr(self.app, "active_identity", None)
                user_cn = active_id.cn if active_id else "Unknown"
                user_cert_pem = active_id.cert_pem if active_id else ""
                user_key_path = active_id.key_path if active_id else None
                user_key_passphrase = active_id.key_passphrase if active_id else None

                # Check for database-level No Access
                identity = self.db._get_identity(user_cert_pem)
                if not self.db.check_permission(identity, 'database', '*', 'read'):
                    box = toga.Box(style=Pack(direction='column', margin=20))
                    box.add(ui_label(
                        toga, "🚨 ACCESS DENIED",
                        style=Pack(font_size=28, font_weight='bold', margin_bottom=15, color='red')))
                    box.add(ui_label(
                        toga, f"Active Identity: {user_cn} ({identity})",
                        style=Pack(font_size=14, margin_bottom=10)))
                    box.add(ui_label(
                        toga,
                        "This identity does not have database-level permissions "
                        "('No Access' active).",
                        style=Pack(font_size=12, margin_bottom=20)))
                    box.add(ui_label(
                        toga,
                        "The micro-app interface has been completely blocked for security.",
                        style=Pack(font_style='italic', color='gray')))
                    self._set_document_content(box)
                    return

                app_widget = execute_micro_app(
                    code_func,
                    workspace_path,
                    self.db,
                    current_user_cn=user_cn,
                    current_user_cert_pem=user_cert_pem,
                    key_path=user_key_path,
                    key_passphrase=user_key_passphrase
                )
                
                # Fetch cryptographic verification status
                status = self.db.get_code_signature_status(entry_point_id)

                self._set_document_content(self._wrap_app_widget(app_widget, status))
                return
                
        # Default fallback "About" view if no custom entry point is defined
        about_data = self.db.get_manifest_item('about')
        
        box = toga.Box(style=Pack(direction='column', margin=20))
        title_lbl = ui_label(toga, "MSF Micro-App", style=Pack(font_size=24, margin_bottom=10))
        box.add(title_lbl)

        # Sync status for about view too (homed containers with no entry point).
        sync_text = self._sync_status_text()
        if sync_text:
            box.add(ui_label(
                toga, sync_text,
                style=Pack(font_size=9, color='#555555', margin_bottom=8),
            ))
        
        if about_data:
            try:
                about = json.loads(about_data)
                box.add(ui_label(toga, f"Title: {about.get('title', 'Unknown')}"))
                box.add(ui_label(toga, f"UUID: {about.get('uuid', 'Unknown')}"))
                box.add(ui_label(toga, f"Created At: {about.get('created_at', 'Unknown')}"))
                
                body = toga.MultilineTextInput(readonly=True, style=Pack(flex=1, margin_top=10))
                body.value = about.get('body', '')
                box.add(body)
            except Exception as e:
                box.add(message_widget(
                    toga, f"Error parsing about info: {e}", kind="error", min_height=48,
                ))
        else:
            box.add(ui_label(
                toga, "This MSF file has no manifest data or entry point.",
            ))
            
        self._set_document_content(box)

    def on_window_close(self, window):
        try:
            self._close_helper_dialog()
        except Exception:
            pass
        try:
            self._stop_sync_subscriber()
        except Exception:
            pass
        if self.db:
            try:
                self.db.close()
            except Exception:
                pass
            self.db = None
        try:
            self.app.documents._remove(self)
        except Exception as e:
            print(f"Error removing document from app document set: {e}")
        return True
