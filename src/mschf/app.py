import asyncio
import time
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW
import logging
from logging.handlers import RotatingFileHandler
import sys
import os
import pytz
import toml

from mschf.gen_cert import generate_selfsigned_cert, x509, NameOID, default_backend, serialization
from mschf.msf import MSF
from mschf.identity import Identity

PROJ_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_TZ_NAME = 'America/New_York'
FILE_EXT = ".msf"
SETTINGS_FILE = os.path.join(PROJ_DIR, 'settings.toml')

settings = {
    'tz_name': DEFAULT_TZ_NAME,
    'user_id': 'ca.crt'
}

log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
log.addHandler(out_hdlr)
log.setLevel(logging.INFO)

import socket
host_name = socket.gethostname()

def load_settings():
    if not os.path.isfile(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'w') as f:
            toml.dump(settings, f)
    else:
        loaded = toml.load(SETTINGS_FILE)
        settings.update(loaded)

class Mschf(toga.App):
    # How often open documents are checked for changes made by OTHER
    # connections (CLI tools, other processes). In-process changes don't wait
    # for this — they broadcast immediately via MSFStorage.on_commit.
    WATCH_INTERVAL_SECONDS = 2
    # Emit a liveness heartbeat to the runtime log this often. If the app
    # freezes (e.g. the WinForms/pythonnet stack wedging across a screen lock),
    # the last heartbeat's timestamp pins WHEN, and whether the poll loop was
    # still ticking — plus a GDI/USER handle trend to spot resource exhaustion.
    HEARTBEAT_SECONDS = 30

    def notify_msf_commit(self, origin_doc):
        """A mutating signed transaction committed on origin_doc's connection:
        live-refresh every other open document showing the same file."""
        try:
            origin_path = os.path.abspath(str(origin_doc.path))
        except Exception:
            return
        for doc in list(self.documents):
            if doc is origin_doc or not isinstance(doc, MSF) or not doc.db:
                continue
            try:
                if os.path.abspath(str(doc.path)) == origin_path:
                    doc.redraw()
            except Exception as e:
                log.error(f"Reactive redraw failed for {doc.path}: {e}", exc_info=True)

    async def on_running(self):
        """Poll open documents for external changes (data_version moves only
        when another connection wrote the file; see MSF.check_external_change),
        and emit a periodic liveness heartbeat to the runtime log."""
        seq = 0
        last_heartbeat = 0.0
        max_lag = 0.0
        log.info("Runtime monitor started (heartbeat every %ss).", self.HEARTBEAT_SECONDS)
        while True:
            before = time.monotonic()
            await asyncio.sleep(self.WATCH_INTERVAL_SECONDS)
            # How much later than requested did this coroutine actually resume?
            # toga_winforms marshals every asyncio iteration onto the GUI thread
            # (proactor.py), so an oversleep is GUI-thread scheduling latency: it
            # stays ~0 while the thread services work on time, and spikes if the
            # thread is CPU-starved/blocked. A freeze with LOW lag means the pump
            # is fine and input is being routed away (window ghosting); a freeze
            # with HIGH lag means the GUI thread itself stalled.
            lag = (time.monotonic() - before) - self.WATCH_INTERVAL_SECONDS
            if lag > max_lag:
                max_lag = lag

            for doc in list(self.documents):
                if isinstance(doc, MSF):
                    try:
                        doc.check_external_change()
                    except Exception as e:
                        log.error(f"External-change check failed for {doc.path}: {e}", exc_info=True)

            now = time.monotonic()
            if now - last_heartbeat >= self.HEARTBEAT_SECONDS:
                last_heartbeat = now
                seq += 1
                gdi, user = self._gui_resource_counts()
                log.info(
                    "heartbeat #%d - docs=%d identity=%s gdi=%s user=%s loop_lag_max=%.3fs",
                    seq, len(list(self.documents)),
                    getattr(self.active_identity, 'cn', '?') if self.active_identity.is_valid else 'none',
                    gdi, user, max_lag,
                )
                max_lag = 0.0

    @staticmethod
    def _gui_resource_counts():
        """(GDI, USER) handle counts for this process on Windows; (None, None)
        elsewhere or on failure. A climbing trend before a freeze indicates
        handle exhaustion (widgets recreated without disposal).

        The handle args must be marshaled at pointer width: GetCurrentProcess()
        returns a pseudo-handle (-1) and GetGuiResources takes a HANDLE, so
        without explicit argtypes/restype ctypes passes a truncated 32-bit value
        on 64-bit Windows and the call silently returns 0 (the bug in 0.4.2)."""
        try:
            import ctypes
            from ctypes import wintypes
            GR_GDIOBJECTS, GR_USEROBJECTS = 0, 1
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.GetCurrentProcess.argtypes = []
            user32.GetGuiResources.restype = wintypes.DWORD
            user32.GetGuiResources.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            proc = kernel32.GetCurrentProcess()
            return (user32.GetGuiResources(proc, GR_GDIOBJECTS),
                    user32.GetGuiResources(proc, GR_USEROBJECTS))
        except Exception:
            return (None, None)

    def action_info_dialog(self, widget):
        self.main_window.info_dialog('Mschf', 'Workspace Manager for Micro-Apps')

    async def action_open_file_dialog(self, widget):
        if not self.active_identity.is_valid:
            self.main_window.error_dialog(
                "Access Denied",
                "Cannot open application: Your active user identity is invalid or not signed by the trusted Root CA."
            )
            return
        try:
            path = await self.main_window.open_file_dialog(
                title="Open Micro-App MSF",
                file_types=["msf"]
            )
            if path:
                # 1. Verify file is a valid SQLite database before opening
                with open(path, 'rb') as f:
                    header = f.read(16)
                if not header.startswith(b"SQLite format 3\x00"):
                    self.label.text = f"Error: {os.path.basename(str(path))} is not a valid SQLite database (legacy SHELF-1 container)"
                    return

                # 2. Open via Toga documents API
                self.documents.open(path)
                self.label.text = f"Opened: {os.path.basename(str(path))}"
        except Exception as e:
            self.label.text = f"Error: {e}"

    def open_selected_app(self, widget, row=None, **kwargs):
        if not self.active_identity.is_valid:
            self.main_window.error_dialog(
                "Access Denied",
                "Cannot open application: Your active user identity is invalid or not signed by the trusted Root CA."
            )
            return
        selection = self.workspace.selection
        if selection:
            path = selection.absolute_path
            try:
                # 1. Verify file exists
                if not os.path.isfile(path):
                    self.label.text = f"Error: File does not exist at {path}"
                    return

                # 2. Verify file is a valid SQLite database before opening
                with open(path, 'rb') as f:
                    header = f.read(16)
                if not header.startswith(b"SQLite format 3\x00"):
                    self.label.text = f"Error: {os.path.basename(path)} is not a valid SQLite database (legacy SHELF-1 container)"
                    return

                # 3. Open via Toga documents API
                self.documents.open(path)
                self.label.text = f"Opened: {os.path.basename(path)}"
            except Exception as e:
                self.label.text = f"Error opening {path}: {e}"
        else:
            self.label.text = "Please select an app from the workspace list below."

    def refresh_workspace(self, widget=None):
        import glob
        
        # 1. Scan current working directory
        cwd = os.getcwd()
        msf_patterns = [
            os.path.join(cwd, f"*{FILE_EXT}"),
        ]
        
        # 2. Scan project directory (parent of src)
        try:
            proj_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            if os.path.isdir(proj_dir) and proj_dir != cwd:
                msf_patterns.append(os.path.join(proj_dir, f"*{FILE_EXT}"))
        except Exception:
            pass

        # 3. Scan the per-user data dir — the workspace that makes sense for an
        # installed app, where cwd/install dir are not user-writable places.
        data_dir = getattr(self, 'data_dir', None)
        if data_dir and os.path.isdir(data_dir):
            msf_patterns.append(os.path.join(data_dir, f"*{FILE_EXT}"))

        # Collect and deduplicate absolute paths
        seen_paths = set()
        msf_files = []
        for pattern in msf_patterns:
            for path in glob.glob(pattern):
                abs_path = os.path.abspath(path)
                if abs_path not in seen_paths:
                    seen_paths.add(abs_path)
                    msf_files.append(abs_path)
                    
        data = []
        for path in msf_files:
            data.append({
                'application_name': (toga.Icon.APP_ICON, os.path.basename(path)),
                'absolute_path': path
            })
        self.workspace.data = data
        self.label.text = f"Found {len(msf_files)} local apps."
        self._update_onboarding(len(msf_files))

    def on_select_app(self, widget):
        selection = widget.selection
        if selection:
            name = selection.application_name
            if isinstance(name, tuple):
                name = name[1]
            self.label.text = f"Selected: {name}"

    def _ensure_key_encrypted(self, key_path, passphrase):
        """Re-encrypt a plaintext private key in place with the given passphrase.

        Preserves the keypair (so the matching cert stays valid); no-ops if the key
        is already encrypted or missing.
        """
        if not passphrase or not os.path.isfile(key_path):
            return
        try:
            with open(key_path, 'rb') as f:
                data = f.read()
            try:
                key = serialization.load_pem_private_key(data, password=None, backend=default_backend())
            except TypeError:
                return  # already encrypted — nothing to do
            enc = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8')),
            )
            with open(key_path, 'wb') as f:
                f.write(enc)
            log.info(f"Upgraded plaintext key to passphrase-protected: {os.path.basename(key_path)}")
        except Exception as e:
            log.warning(f"Could not upgrade key encryption for {key_path}: {e}")

    def set_active_identity(self, cert_filename, key_passphrase=None):
        path = os.path.join(self.proj_dir, cert_filename) if not os.path.isabs(cert_filename) else cert_filename
        if not os.path.isfile(path):
            log.error(f"Certificate file not found: {path}")
            return

        ca_cert_path = os.path.join(PROJ_DIR, 'ca.crt')
        self.active_identity = Identity.load(path, ca_cert_path)
        self.active_identity.key_passphrase = key_passphrase

        self.identity_label.text = self.active_identity.identity_label
        self.label.text = self.active_identity.status_text

        self._apply_identity_state()
        log.info(f"Switched active user identity to CN={self.active_identity.cn} via {cert_filename}")

    def log_out(self, widget=None):
        """Drop the active identity (and its in-memory passphrase), re-locking the app."""
        self.active_identity = Identity.logged_out()
        self.identity_label.text = self.active_identity.identity_label
        self.label.text = "Logged out. Authenticate via the Auth Gateway to open apps."
        self._apply_identity_state()
        log.info("Logged out; active identity cleared.")

    def _setup_runtime_log(self):
        """Attach a rotating file log in the user data dir. Survives across runs
        and captures the heartbeat trail, so a freeze leaves durable evidence
        (unlike the stdout log, which vanishes with the dev console)."""
        try:
            log_path = os.path.join(self.data_dir, 'mschf-runtime.log')
            handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            handler.setLevel(logging.INFO)
            log.addHandler(handler)
            log.info("Runtime log opened at %s", log_path)
        except Exception as e:
            log.warning(f"Could not open runtime log file: {e}")

    def register_auth_panel(self, panel):
        """Called by the auth plugin: the app owns WHERE (and whether) the
        panel appears — it is only composed into the window while logged out."""
        self.auth_panel = panel

    def _update_onboarding(self, app_count=None):
        """Contextual first-run guidance + progressive disclosure.

        The window shows only what matters for the current state:
        logged out            -> onboarding banner + Auth Gateway, nothing else;
        logged in, no apps    -> banner (with starter creation) + workspace;
        logged in, apps exist -> just the workspace.
        """
        if not hasattr(self, 'onboarding_label'):
            return
        if app_count is None:
            app_count = getattr(self, '_app_count', 0)
        self._app_count = app_count

        if not self.active_identity.is_valid:
            pw_hint = (
                "the default passphrase 'changeit' (set MSCHF_ADMIN_PASSPHRASE to change it)"
                if getattr(self, '_admin_passphrase_is_default', True)
                else "your MSCHF_ADMIN_PASSPHRASE passphrase"
            )
            self.onboarding_label.text = (
                "Welcome to Mischief. Sign in below to unlock the workspace —\n"
                f"this machine's built-in identity is 'admin', with {pw_hint}."
            )
        elif app_count == 0:
            self.onboarding_label.text = (
                "You're signed in, but no micro-apps (.msf) were found.\n"
                f"Workspace folder: {self.data_dir}\n"
                "Create the starter app to see the platform in action, or use Browse MSF "
                "to open an existing container."
            )
        self._recompose_layout()

    def _recompose_layout(self):
        """Rebuild the main window's children for the current state.

        Widgets are added/removed from the layout rather than css-hidden:
        Pack display toggling proved unreliable on WinForms, and removal also
        reclaims the space (no dead zones from invisible widgets).
        """
        if not hasattr(self, 'outer_box'):
            return
        logged_in = self.active_identity.is_valid
        app_count = getattr(self, '_app_count', 0)

        # The starter button lives in the banner only when it is actionable.
        want_starter = logged_in and app_count == 0
        have_starter = self.btn_create_starter in list(self.onboarding_box.children)
        if want_starter and not have_starter:
            self.onboarding_box.add(self.btn_create_starter)
        elif not want_starter and have_starter:
            self.onboarding_box.remove(self.btn_create_starter)

        if not logged_in:
            desired = [self.onboarding_box]
            if getattr(self, 'auth_panel', None) is not None:
                desired.append(self.auth_panel)
        elif app_count == 0:
            desired = [self.onboarding_box, self.identity_label, self.btn_box,
                       self.workspace, self.label]
        else:
            desired = [self.identity_label, self.btn_box, self.workspace, self.label]

        current = list(self.outer_box.children)
        if current != desired:
            for child in current:
                self.outer_box.remove(child)
            for child in desired:
                self.outer_box.add(child)

    def create_starter_app(self, widget=None):
        """Author the signed 'Getting Started' micro-app in the user's workspace."""
        if not self.active_identity.is_valid:
            return
        from mschf.starter import create_starter_container
        dest = os.path.join(self.data_dir, 'getting_started.msf')
        try:
            create_starter_container(dest, self.active_identity, self.ca_cert_path)
            self.label.text = "Starter app created — double-click it in the list to open it."
            log.info(f"Created starter container at {dest} signed by CN={self.active_identity.cn}")
        except FileExistsError:
            self.label.text = "Starter app already exists — double-click it in the list to open it."
        except Exception as e:
            log.error(f"Failed to create starter app: {e}", exc_info=True)
            self.label.text = f"Could not create starter app: {e}"
        self.refresh_workspace()

    def _apply_identity_state(self):
        """Sync button enablement to the active identity and re-lock/redraw open docs."""
        is_valid = self.active_identity.is_valid
        for attr in ('btn_open_selected', 'btn_open_dialog'):
            btn = getattr(self, attr, None)
            if btn is not None:
                btn.enabled = is_valid
        if getattr(self, 'btn_logout', None) is not None:
            self.btn_logout.enabled = is_valid
        if getattr(self, 'btn_create_starter', None) is not None:
            self.btn_create_starter.enabled = is_valid
        self._update_onboarding()

        # Redraw open documents so they lock (logged out / no access) or refresh live.
        for doc in list(self.documents):
            try:
                doc.redraw()
            except Exception as redraw_err:
                log.warning(f"Failed to redraw document {doc}: {redraw_err}")

    def action_exit(self, app, **kwargs):
        log.info("Workspace shutting down.")
        return True

    def startup(self):
        self.on_exit = self.action_exit
        log.info(f"We're running on {host_name}")
        log.info(f"Current working directory: {os.path.abspath(os.getcwd())}")
        load_settings()

        # Prune the stock document commands that don't fit the .msf model. A
        # container is never "saved" — every change is a signed transaction
        # committed immediately — so Save / Save As / Save All are no-ops, and
        # micro-apps are authored (starter button, dev_tracker.py), not created
        # as blank documents, so New opens a meaningless empty window. Keep Open
        # (browse for an .msf) and Exit. Toga installs these before startup()
        # precisely so we can remove them here.
        for cmd_id in (toga.Command.NEW, toga.Command.SAVE,
                       toga.Command.SAVE_AS, toga.Command.SAVE_ALL):
            try:
                del self.commands[cmd_id]
            except KeyError:
                pass

        tzinfo = pytz.timezone(settings['tz_name'])
        log.info(f"Time zone is {tzinfo}")
        
        # 1. Verify/Generate Root Certificate Authority (ca.crt / ca.key)
        ca_cert_path = os.path.join(PROJ_DIR, 'ca.crt')
        ca_key_path = os.path.join(PROJ_DIR, 'ca.key')
        self.proj_dir = PROJ_DIR
        self.ca_cert_path = ca_cert_path  # trust anchor handed to MSFStorage
        
        if not os.path.isfile(ca_cert_path) or not os.path.isfile(ca_key_path):
            pem_ca_cert, pem_ca_key = generate_selfsigned_cert("Bespoke Root CA")
            with open(ca_cert_path, 'wb') as f:
                f.write(pem_ca_cert)
            with open(ca_key_path, 'wb') as f:
                f.write(pem_ca_key)
            log.info("Generated new Root Certificate Authority (ca.crt/ca.key)")

        with open(ca_cert_path, 'rb') as f:
            self.ca_cert_pem = f.read()
        with open(ca_key_path, 'rb') as f:
            self.ca_key_pem = f.read()

        # 2. Verify/Generate default Admin User identity (admin.crt / admin.key) signed by Root CA.
        # The admin key is passphrase-protected so logging in as admin requires a secret.
        # The passphrase comes from MSCHF_ADMIN_PASSPHRASE (demo default "changeit").
        admin_cert_path = os.path.join(PROJ_DIR, 'admin.crt')
        admin_key_path = os.path.join(PROJ_DIR, 'admin.key')
        admin_passphrase = os.environ.get('MSCHF_ADMIN_PASSPHRASE', 'changeit')
        # Drives the first-run hint: we may tell the user the DEFAULT passphrase
        # in the UI, but never a custom one from the environment.
        self._admin_passphrase_is_default = 'MSCHF_ADMIN_PASSPHRASE' not in os.environ

        # Per-user workspace folder for .msf files — the sensible location for
        # an installed app (cwd / install dir are not user workspaces).
        try:
            self.data_dir = str(self.paths.data)
            os.makedirs(self.data_dir, exist_ok=True)
        except Exception as data_dir_err:
            log.warning(f"Could not prepare user data dir: {data_dir_err}")
            self.data_dir = PROJ_DIR

        self._setup_runtime_log()

        if not os.path.isfile(admin_cert_path) or not os.path.isfile(admin_key_path):
            with open(ca_cert_path, 'rb') as f:
                ca_cert_pem = f.read()
            with open(ca_key_path, 'rb') as f:
                ca_key_pem = f.read()
            from mschf.gen_cert import generate_user_cert
            pem_admin_cert, pem_admin_key = generate_user_cert("admin", ca_cert_pem, ca_key_pem, passphrase=admin_passphrase)
            with open(admin_cert_path, 'wb') as f:
                f.write(pem_admin_cert)
            with open(admin_key_path, 'wb') as f:
                f.write(pem_admin_key)
            log.info("Generated default Admin User identity (admin.crt/admin.key) signed by Root CA")

        # Upgrade a legacy plaintext admin.key in place (same keypair, now encrypted),
        # so an existing admin identity keeps working but now requires a passphrase.
        self._ensure_key_encrypted(admin_key_path, admin_passphrase)

        # 3. Start logged-out. The admin identity file (admin.crt/key) exists on disk
        # from step 2, but it is NOT auto-activated — opening micro-apps is gated on
        # the user authenticating via the Auth Gateway. This stops the host from
        # booting straight into a fully-authorized admin session.
        self.active_identity = Identity.logged_out()
        identity_text = self.active_identity.identity_label
        status_text = self.active_identity.status_text

        # Initialize Plugin System
        from mschf.plugins.manager import PluginManager
        self.plugin_manager = PluginManager(self)
        self.plugin_manager.load_all()

        self.main_window = toga.MainWindow(title=self.formal_name, size=(760, 640))
        self.label = toga.Label(status_text, style=Pack(margin=10))

        self.identity_label = toga.Label(identity_text, style=Pack(margin=10, font_weight="bold"))

        # Create Identity Management UI components
        is_valid = self.active_identity.is_valid

        self.workspace = toga.Table(
            columns=['Application Name', 'Absolute Path'],
            on_select=self.on_select_app,
            on_activate=self.open_selected_app,
            style=Pack(flex=1)
        )

        try:
            native_lv = self.workspace._impl.native
            if hasattr(native_lv, "SmallImageList") and native_lv.SmallImageList is not None:
                from System.Drawing import Size
                native_lv.SmallImageList.ImageSize = Size(24, 24)
        except Exception as e:
            log.warning(f"Could not adjust native image size: {e}")

        btn_style = Pack(flex=1, margin=5)
        self.btn_open_selected = toga.Button('Open Selected', on_press=self.open_selected_app, style=btn_style, enabled=is_valid)
        self.btn_open_dialog = toga.Button('Browse MSF', on_press=self.action_open_file_dialog, style=btn_style, enabled=is_valid)
        btn_refresh = toga.Button('Refresh', on_press=self.refresh_workspace, style=btn_style)
        # Log Out clears the active identity; disabled until someone is logged in.
        self.btn_logout = toga.Button('Log Out', on_press=self.log_out, style=btn_style, enabled=is_valid)

        self.btn_box = toga.Box(
            children=[self.btn_open_selected, self.btn_open_dialog, btn_refresh, self.btn_logout],
            style=Pack(direction=ROW, margin=5)
        )

        # First-run onboarding banner: contextual next-step guidance, populated
        # by _update_onboarding(). The starter button is composed in only when
        # actionable (signed in + empty workspace).
        self.onboarding_label = toga.Label("", style=Pack(margin=8, font_size=10))
        self.btn_create_starter = toga.Button(
            'Create Starter App', on_press=self.create_starter_app,
            style=Pack(margin=8, margin_top=0), enabled=is_valid,
        )
        self.onboarding_box = toga.Box(
            children=[self.onboarding_label],
            style=Pack(direction=COLUMN, background_color='#fff7ed', margin_bottom=5),
        )

        # Root container starts empty; _recompose_layout() fills it with only
        # the widgets relevant to the current auth/workspace state.
        self.auth_panel = None
        self.outer_box = toga.Box(children=[], style=Pack(direction=COLUMN, margin=10))

        # Let plugins extend the main UI (the auth plugin registers its panel
        # via register_auth_panel; the composition owns its placement).
        for p_name, plugin in self.plugin_manager.plugins.items():
            if hasattr(plugin, 'extend_ui'):
                try:
                    plugin.extend_ui(self, self.outer_box)
                except Exception as extend_err:
                    log.error(f"Plugin {p_name} failed to extend UI: {extend_err}", exc_info=True)

        self.main_window.content = self.outer_box
        self.refresh_workspace()
        self.main_window.show()

def main():
    # Pass metadata explicitly: `briefcase dev` can leave a stale .dist-info in
    # the venv, and the About dialog reads whatever the App carries. Version is
    # sourced from the canonical __version__ (kept in sync with pyproject.toml).
    from mschf import __version__
    return Mschf(
        'Mischief Workspace Manager',
        'com.mschf.mschf',
        author='Chief Mouse',
        version=__version__,
        description='Workspace Manager for cryptographically signed micro-apps (.msf)',
        home_page='https://github.com/chief-mouse/mischief',
        document_types=[MSF],
    )

if __name__ == '__main__':
    main().main_loop()
