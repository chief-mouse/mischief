import logging
import os
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from mschf.plugins.base import BasePlugin
from mschf.identity import Identity
from mschf.plugins.auth.providers.password import PasswordAuthenticator
from mschf.plugins.auth.providers.oauth import OAuth2Authenticator
from mschf.plugins.auth.providers.passkey import PasskeyAuthenticator

log = logging.getLogger(__name__)

class AuthPlugin(BasePlugin):
    def __init__(self):
        super().__init__("authentication_gateway")
        # Instantiate available authenticators
        self.providers = {
            "local_password": PasswordAuthenticator(),
            "google_oauth": OAuth2Authenticator("google_oauth", "Google OAuth 2.0 (OIDC)", "https://accounts.google.com"),
            "microsoft_oauth": OAuth2Authenticator("microsoft_oauth", "Microsoft OAuth 2.0 (OIDC)", "https://login.microsoftonline.com"),
            "fido2_passkey": PasskeyAuthenticator()
        }
        self.active_provider_key = "local_password"

    def on_load(self, app):
        log.info("AuthPlugin loaded successfully.")

    def extend_ui(self, app, outer_box):
        """Inject the interactive Authentication Gateway panel into the workspace manager GUI."""
        plugin_box = toga.Box(style=Pack(direction=COLUMN, margin_top=15, margin_bottom=10))
        
        # Section Title
        plugin_box.add(toga.Label(
            "🔌 Plugin: Cryptographic Identity & Auth Gateways",
            style=Pack(font_size=12, font_weight="bold", margin_bottom=5, color="#1e3a8a")
        ))
        
        # Selector for authentication methods
        provider_choices = [p.display_name for p in self.providers.values()]
        provider_select = toga.Selection(items=provider_choices, style=Pack(margin=5))
        
        # Form inputs
        input_box = toga.Box(style=Pack(direction=ROW, margin=5))
        username_input = toga.TextInput(placeholder="Username / Identity CN / Email", style=Pack(flex=1, margin_right=5))
        # Masked: this field carries the key passphrase / password / OAuth token.
        password_input = toga.PasswordInput(placeholder="Passphrase / Password / OAuth ID Token", style=Pack(flex=1))
        
        input_box.add(username_input)
        input_box.add(password_input)
        
        # Labels for status and metadata display
        status_label = toga.Label("Auth Status: Waiting for input.", style=Pack(margin=5, font_style="italic"))
        metadata_label = toga.Label("Decoded Token / Crypto Properties: (None)", style=Pack(margin=5, font_size=9))
        
        def on_authenticate(widget):
            # Capture the secret, then clear it from the widget immediately so it does
            # not linger on screen / in the field after the attempt (success or fail).
            secret = password_input.value or ""
            password_input.value = ""

            # Path 1: assume an existing, deliberately-issued identity by CN. Holding
            # its CA-signed cert+key on the host IS the credential — this is how you
            # log in as 'admin' (admin.crt) without the mock password minting admin.
            typed_cn = (username_input.value or "").strip()
            if typed_cn:
                existing_cert = os.path.join(app.proj_dir, f"{typed_cn}.crt")
                existing_key = os.path.join(app.proj_dir, f"{typed_cn}.key")
                if os.path.isfile(existing_cert):
                    probe = Identity.load(existing_cert, app.ca_cert_path)
                    if not probe.is_valid:
                        status_label.text = f"✖ Identity '{typed_cn}' is not signed by the trusted Root CA."
                        metadata_label.text = ""
                        return
                    if not os.path.isfile(existing_key):
                        status_label.text = f"✖ Identity '{typed_cn}' has no private key on this host; cannot sign as it."
                        metadata_label.text = ""
                        return
                    # The passphrase that unlocks the private key IS the login secret:
                    # possession of the file is not enough. Verify by decrypting it.
                    passphrase = secret
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key
                    with open(existing_key, 'rb') as f:
                        key_bytes = f.read()
                    try:
                        load_pem_private_key(key_bytes, password=passphrase.encode('utf-8') if passphrase else None)
                    except TypeError:
                        status_label.text = (f"✖ Identity '{typed_cn}' requires a passphrase."
                                             if not passphrase else
                                             f"✖ Identity '{typed_cn}' key is not passphrase-protected.")
                        metadata_label.text = ""
                        return
                    except ValueError:
                        status_label.text = f"✖ Incorrect passphrase for identity '{typed_cn}'."
                        metadata_label.text = ""
                        return
                    app.set_active_identity(existing_cert, key_passphrase=passphrase or None)
                    status_label.text = f"✔ Logged in as existing identity '{probe.cn}' ({os.path.basename(existing_cert)})."
                    metadata_label.text = ("Cryptographic Verification:\n"
                                           "  • source: on-host CA-signed identity file\n"
                                           "  • unlocked with: passphrase\n"
                                           f"  • common_name: {probe.cn}")
                    return

            # Path 2: authenticate via an external protocol (mock) and provision a NEW
            # per-user ephemeral identity. This path never yields the seeded identities.
            selected_display_name = provider_select.value
            provider = None
            for p in self.providers.values():
                if p.display_name == selected_display_name:
                    provider = p
                    break

            if not provider:
                status_label.text = "Error: Provider not found."
                return

            username = username_input.value
            password = secret

            # Run the dynamic authenticators
            res = provider.authenticate(username=username, password=password)
            
            if res['success']:
                # Authentication succeeded!
                status_label.text = f"✔ Authenticated successfully as '{res['identity']}'!"
                meta_str = "\n".join([f"  • {k}: {v}" for k, v in res['metadata'].items()])
                metadata_label.text = f"Cryptographic Verification:\n{meta_str}"
                
                # Dynamic Ephemeral Certificate Provisioning
                try:
                    clean_name = res['identity'].replace(':', '_').replace('@', '_').replace('.', '_')
                    cert_filename = f"{clean_name}.crt"
                    key_filename = f"{clean_name}.key"

                    cert_path = os.path.join(app.proj_dir, cert_filename)
                    key_path = os.path.join(app.proj_dir, key_filename)

                    # Generate the certificate signed by Root CA. The CN must match the
                    # sanitized filename stem so the cert, the .crt/.key files, and the
                    # derived RBAC identity (cert:CN=clean_name) all agree. The new key is
                    # encrypted with the login password, so future logins need that secret.
                    from mschf.gen_cert import generate_user_cert
                    pem_cert, pem_key = generate_user_cert(clean_name, app.ca_cert_pem, app.ca_key_pem, passphrase=(password or None))

                    with open(cert_path, 'wb') as f:
                        f.write(pem_cert)
                    with open(key_path, 'wb') as f:
                        f.write(pem_key)

                    log.info(f"Dynamically provisioned ephemeral X.509 Certificate for: {res['identity']}")

                    # Hot-swap and set active identity in the main App GUI
                    app.set_active_identity(cert_filename, key_passphrase=(password or None))
                    
                    status_label.text += f"\n✔ Dynamically provisioned & set active X.509 cert: {cert_filename}!"
                except Exception as cert_err:
                    log.error(f"Failed to dynamically provision certificate: {cert_err}", exc_info=True)
                    status_label.text += f"\n⚠ Could not provision X.509 certificate: {cert_err}"
            else:
                status_label.text = f"✖ Authentication Failed: {res['error']}"
                metadata_label.text = ""
                
        btn_auth = toga.Button("Authenticate & Verify Identity", on_press=on_authenticate, style=Pack(margin=5))

        # Pressing Enter in either field submits the login, same as the button.
        username_input.on_confirm = on_authenticate
        password_input.on_confirm = on_authenticate
        
        # Layout organization
        plugin_box.add(toga.Label("Select Authentication Protocol:", style=Pack(margin_left=5, font_size=10)))
        plugin_box.add(provider_select)
        plugin_box.add(input_box)
        plugin_box.add(btn_auth)
        plugin_box.add(status_label)
        plugin_box.add(metadata_label)
        
        # Insert plugin panel right under the main workspace actions but above the file table
        # We can append it to the outer layout container
        outer_box.add(plugin_box)
