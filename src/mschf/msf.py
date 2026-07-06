import toga
import os
from pathlib import Path
from toga.style import Pack
from mschf.storage import MSFStorage
from mschf.sandbox import execute_micro_app
import json

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

    def read(self) -> None:
        """Load representation of the document from self.path and populate the window."""
        if self.path and self.path.exists():
            ca_cert_path = getattr(self.app, "ca_cert_path", None)
            self.db = MSFStorage(str(self.path), ca_cert_path=ca_cert_path)
            self.redraw()

    def redraw(self) -> None:
        if not self.db:
            return
            
        entry_point_id = self.db.get_manifest_item('entry_point')
        
        if entry_point_id:
            code_func = self.db.get_code(entry_point_id)
            if code_func:
                workspace_path = os.path.dirname(os.path.abspath(str(self.path)))
                active_id = getattr(self.app, "active_identity", None)
                user_cn = active_id.cn if active_id else "Unknown"
                user_cert_pem = active_id.cert_pem if active_id else ""
                user_key_path = active_id.key_path if active_id else None

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
                    key_path=user_key_path
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
                
                # Wrap the header and the sandboxed app widget
                wrapper_box = toga.Box(style=Pack(direction='column', margin=5))
                wrapper_box.add(header_box)
                
                app_widget.style.flex = 1
                wrapper_box.add(app_widget)
                
                self.main_window.content = wrapper_box
                return
                
        # Default fallback "About" view if no custom entry point is defined
        about_data = self.db.get_manifest_item('about')
        
        box = toga.Box(style=Pack(direction='column', margin=20))
        title_lbl = toga.Label("MSF Micro-App", style=Pack(font_size=24, margin_bottom=10))
        box.add(title_lbl)
        
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
        if self.db:
            self.db.close()
        try:
            self.app.documents._remove(self)
        except Exception as e:
            print(f"Error removing document from app document set: {e}")
        return True
