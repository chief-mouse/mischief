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
        header_box.add(toga.Label(status_text, style=Pack(font_weight='bold', margin_right=15)))
        header_box.add(toga.Label(f"Signer CN: {status['signer']}", style=Pack(margin_right=15)))
        header_box.add(toga.Label(f"Method: {status['method']}", style=Pack(font_size=9)))
        if source_text:
            header_box.add(toga.Label(source_text, style=Pack(font_size=9, margin_left=15)))
        return header_box

    def _wrap_app_widget(self, app_widget, status, source_text=None):
        """Banner + optional sync-status line + the micro-app widget."""
        wrapper_box = toga.Box(style=Pack(direction='column', margin=5))
        wrapper_box.add(self._security_banner(status, source_text))

        # Homed containers: second, smaller sync-status line (local facts only).
        sync_text = self._sync_status_text()
        if sync_text:
            wrapper_box.add(toga.Label(
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
        box.add(toga.Label(
            "🚨 DECLARATIVE UI ERROR",
            style=Pack(font_size=20, font_weight='bold', margin_bottom=10, color='red')))
        box.add(toga.Label(
            "This container's ui_spec manifest entry could not be rendered:",
            style=Pack(margin_bottom=8)))
        detail = toga.MultilineTextInput(readonly=True, style=Pack(flex=1))
        detail.value = str(error)
        box.add(detail)
        self.main_window.content = box

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
        self.main_window.content = self._wrap_app_widget(
            app_widget, status, "UI: signed manifest (declarative)"
        )

    def _draw_content(self) -> None:

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
                    box.add(toga.Label("🚨 ACCESS DENIED", style=Pack(font_size=28, font_weight='bold', margin_bottom=15, color='red')))
                    box.add(toga.Label(f"Active Identity: {user_cn} ({identity})", style=Pack(font_size=14, margin_bottom=10)))
                    box.add(toga.Label("This identity does not have database-level permissions ('No Access' active).", style=Pack(font_size=12, margin_bottom=20)))
                    box.add(toga.Label("The micro-app interface has been completely blocked for security.", style=Pack(font_style='italic', color='gray')))
                    self.main_window.content = box
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

                self.main_window.content = self._wrap_app_widget(app_widget, status)
                return
                
        # Default fallback "About" view if no custom entry point is defined
        about_data = self.db.get_manifest_item('about')
        
        box = toga.Box(style=Pack(direction='column', margin=20))
        title_lbl = toga.Label("MSF Micro-App", style=Pack(font_size=24, margin_bottom=10))
        box.add(title_lbl)

        # Sync status for about view too (homed containers with no entry point).
        sync_text = self._sync_status_text()
        if sync_text:
            box.add(toga.Label(sync_text, style=Pack(font_size=9, color='#555555', margin_bottom=8)))
        
        if about_data:
            try:
                about = json.loads(about_data)
                box.add(toga.Label(f"Title: {about.get('title', 'Unknown')}"))
                box.add(toga.Label(f"UUID: {about.get('uuid', 'Unknown')}"))
                box.add(toga.Label(f"Created At: {about.get('created_at', 'Unknown')}"))
                
                body = toga.MultilineTextInput(readonly=True, style=Pack(flex=1, margin_top=10))
                body.value = about.get('body', '')
                box.add(body)
            except Exception as e:
                box.add(toga.Label(f"Error parsing about info: {e}"))
        else:
            box.add(toga.Label("This MSF file has no manifest data or entry point."))
            
        self.main_window.content = box

    def on_window_close(self, window):
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
