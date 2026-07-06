import logging
import os
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from mschf.plugins.base import BasePlugin
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
        password_input = toga.TextInput(placeholder="Password / OAuth ID Token", style=Pack(flex=1)) # password_input can double as JWT input
        
        input_box.add(username_input)
        input_box.add(password_input)
        
        # Labels for status and metadata display
        status_label = toga.Label("Auth Status: Waiting for input.", style=Pack(margin=5, font_style="italic"))
        metadata_label = toga.Label("Decoded Token / Crypto Properties: (None)", style=Pack(margin=5, font_size=9))
        
        def on_authenticate(widget):
            # Resolve chosen provider
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
            password = password_input.value
            
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
                    # derived RBAC identity (cert:CN=clean_name) all agree.
                    from mschf.gen_cert import generate_user_cert
                    pem_cert, pem_key = generate_user_cert(clean_name, app.ca_cert_pem, app.ca_key_pem)
                    
                    with open(cert_path, 'wb') as f:
                        f.write(pem_cert)
                    with open(key_path, 'wb') as f:
                        f.write(pem_key)
                        
                    log.info(f"Dynamically provisioned ephemeral X.509 Certificate for: {res['identity']}")
                    
                    # Hot-swap and set active identity in the main App GUI
                    app.set_active_identity(cert_filename)
                    
                    status_label.text += f"\n✔ Dynamically provisioned & set active X.509 cert: {cert_filename}!"
                except Exception as cert_err:
                    log.error(f"Failed to dynamically provision certificate: {cert_err}", exc_info=True)
                    status_label.text += f"\n⚠ Could not provision X.509 certificate: {cert_err}"
            else:
                status_label.text = f"✖ Authentication Failed: {res['error']}"
                metadata_label.text = ""
                
        btn_auth = toga.Button("Authenticate & Verify Identity", on_press=on_authenticate, style=Pack(margin=5))
        
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
