import os
import threading
import time
import json

import toga
from toga.style import Pack

from mschf.storage import MSFStorage
from mschf.sandbox import execute_micro_app


def format_sync_status_line(status, connected, has_hub_url=True):
    """Build the GUI sync-status line from cheap local facts only.

    Headless-testable. ``status`` is the dict from ``sync.sync_status`` (no
    network probe). ``connected`` is the subscriber thread's live/offline flag
    (True after any successful poll cycle, including empty timeouts).

    Returns ``None`` when the container is not homed (caller shows nothing).
    """
    if not status or not status.get('homed'):
        return None
    cn = status.get('hub_cn') or '?'
    if not has_hub_url:
        return f"SYNC: hub {cn} — no url configured"
    live = 'live' if connected else 'offline'
    head = status.get('local_next_seq', 0)
    pending = status.get('outbox_pending', 0) or 0
    return f"SYNC: hub {cn} — {live} · head {head} · {pending} pending"


def _sync_subscriber_main(
    path,
    hub_url,
    container_id,
    stop_event,
    hub_cn,
    ca_cert_path,
    trust_dir,
    thread_state,
    poll_timeout=None,
):
    """Long-poll loop for a document subscriber (runs in a daemon thread).

    Opens its **own** ``MSFStorage`` on ``path`` — never touch the document's
    connection or any Toga object. Applied rows bump ``PRAGMA data_version``;
    the existing ``check_external_change`` poll redraws the document.

    ``thread_state`` is a simple namespace (or the Thread itself) with:
    - ``connected``: True after any successful poll cycle (incl. empty timeout)
    - ``last_applied_at``: monotonic time of last non-empty apply
    - ``storage_conn_id``: ``id(conn)`` of this thread's connection (tests)

    ``poll_timeout`` overrides the long-poll wait (seconds); default matches
    ``sync.subscribe``. The first cycle uses a short timeout so the live/offline
    indicator flips without waiting a full long-poll window.
    """
    from mschf import sync as msync

    # Defaults mirror sync.subscribe so behaviour stays aligned.
    full_timeout = (
        float(poll_timeout)
        if poll_timeout is not None
        else float(getattr(msync, '_DEFAULT_EVENTS_TIMEOUT', 25))
    )
    events_slop = getattr(msync, '_EVENTS_HTTP_SLOP', 10)
    backoff_start = getattr(msync, '_BACKOFF_START', 1.0)
    backoff_cap = getattr(msync, '_BACKOFF_CAP', 30.0)
    # First cycle: short park so "live" appears quickly when already in sync.
    first_timeout = min(full_timeout, 2.0)

    thread_state.connected = False
    thread_state.last_applied_at = None
    thread_state.storage_conn_id = None

    sub = MSFStorage(path, ca_cert_path=ca_cert_path, trust_dir=trust_dir)
    thread_state.storage_conn_id = id(sub.conn)
    backoff = backoff_start
    first_cycle = True
    try:
        while not stop_event.is_set():
            since_seq = msync._local_max_seq(sub)
            this_timeout = first_timeout if first_cycle else full_timeout
            try:
                code, data = msync._http_json(
                    'GET',
                    msync._url(
                        hub_url,
                        'containers',
                        container_id,
                        'events',
                        query={
                            'since_seq': since_seq,
                            'timeout': this_timeout,
                        },
                    ),
                    timeout=this_timeout + events_slop,
                )
                if code != 200:
                    raise PermissionError(
                        f'subscribe: events failed ({code}): {data}'
                    )
                # Successful poll cycle (including empty timeout rows) → live.
                thread_state.connected = True
                first_cycle = False
                result = msync.pull_and_apply(
                    sub,
                    hub_url,
                    container_id,
                    expected_hub_cn=hub_cn,
                    ca_cert_path=ca_cert_path,
                    trust_dir=trust_dir,
                )
                backoff = backoff_start
                if result.get('applied', 0) > 0:
                    thread_state.last_applied_at = time.monotonic()
            except Exception as e:
                if stop_event.is_set():
                    break
                if msync._is_connection_error(e) or isinstance(e, TimeoutError):
                    thread_state.connected = False
                    stop_event.wait(timeout=backoff)
                    backoff = min(backoff * 2, backoff_cap)
                    continue
                # Application / crypto glitch — keep looping, stay "connected"
                # only if we had previously succeeded; do not flip offline for
                # a transient 403 (hub is reachable).
                stop_event.wait(timeout=min(backoff, 5.0))
                backoff = min(backoff * 2, backoff_cap)
                continue
    finally:
        try:
            sub.close()
        except Exception:
            pass


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
        """Recompute the sync status line from local facts only (no network)."""
        if not self.db:
            return None
        try:
            from mschf import sync as msync
            hub_url, hub_cn = msync.homing(self.db)
            if not hub_cn:
                return None
            status = msync.sync_status(self.db)  # no probe
            connected = False
            thr = getattr(self, '_sync_thread', None)
            if thr is not None:
                connected = bool(getattr(thr, 'connected', False))
            return format_sync_status_line(
                status, connected, has_hub_url=bool(hub_url),
            )
        except Exception:
            return None

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

    def check_external_change(self) -> None:
        """Redraw if another connection (CLI, second window) mutated the file."""
        if not self.db:
            return
        marker = self._current_change_marker()
        if marker is None or self._change_baseline is None:
            self._change_baseline = marker
            return
        if marker[0] == self._change_baseline[0]:
            return  # nothing changed on other connections
        if marker[1] == self._change_baseline[1]:
            # Other-connection activity was only audit rows from signed reads;
            # advance the baseline without a redraw.
            self._change_baseline = marker
            return
        self.redraw()

    def redraw(self) -> None:
        if not self.db:
            return
        try:
            self._draw_content()
        finally:
            self._change_baseline = self._current_change_marker()

    def _draw_content(self) -> None:

        entry_point_id = self.db.get_manifest_item('entry_point')
        
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
                
                # Create a security status banner
                status_text = "🛡️ CRYPTO ACTIVE: VERIFIED" if status['verified'] else "🚨 CRYPTO WARNING: UNVERIFIED OR TAMPERED"
                
                header_box = toga.Box(style=Pack(direction='row', margin=10))
                status_lbl = toga.Label(status_text, style=Pack(font_weight='bold', margin_right=15))
                signer_lbl = toga.Label(f"Signer CN: {status['signer']}", style=Pack(margin_right=15))
                method_lbl = toga.Label(f"Method: {status['method']}", style=Pack(font_size=9))
                
                header_box.add(status_lbl)
                header_box.add(signer_lbl)
                header_box.add(method_lbl)

                wrapper_box = toga.Box(style=Pack(direction='column', margin=5))
                wrapper_box.add(header_box)

                # Homed containers: second, smaller sync-status line (local facts only).
                sync_text = self._sync_status_text()
                if sync_text:
                    sync_lbl = toga.Label(
                        sync_text,
                        style=Pack(font_size=9, color='#555555', margin_left=10, margin_bottom=4),
                    )
                    wrapper_box.add(sync_lbl)
                
                app_widget.style.flex = 1
                wrapper_box.add(app_widget)
                
                self.main_window.content = wrapper_box
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
