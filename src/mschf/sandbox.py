import os
import toga

class HostAPI:
    """Bridge API exposed to the micro-app. Restricted to local MSF, config, and ID files."""
    def __init__(self, workspace_path, db=None, current_user_cn=None, current_user_cert_pem=None):
        self.workspace_path = os.path.abspath(workspace_path)
        self.db = db
        self.current_user_cn = current_user_cn or "Unknown"
        self.current_user_cert_pem = current_user_cert_pem or ""
        
    def _is_safe_path(self, filename):
        safe_path = os.path.abspath(os.path.join(self.workspace_path, filename))
        return safe_path.startswith(self.workspace_path) and os.path.isfile(safe_path)

    def list_local_msf(self):
        """Return a list of local .msf files in the workspace."""
        if not os.path.isdir(self.workspace_path):
            return []
        return [f for f in os.listdir(self.workspace_path) if f.endswith('.msf')]

    def read_config(self, filename):
        """Read a local config file (e.g. settings.toml)."""
        if not self._is_safe_path(filename):
            raise PermissionError(f"Access denied to {filename}")
        safe_path = os.path.abspath(os.path.join(self.workspace_path, filename))
        with open(safe_path, 'r', encoding='utf-8') as f:
            return f.read()

    def read_id(self, filename='ca.crt'):
        """Read the local identity file."""
        return self.read_config(filename)

    def has_view_permission(self, view_name, pub_key_pem):
        """Check if an identity has permission to view a specific screen."""
        if not self.db:
            return False
        return self.db.check_view_permission(view_name, pub_key_pem)

    def has_field_permission(self, table_name, field_name, permission, pub_key_pem):
        """Check if an identity has a field-level permission."""
        if not self.db:
            return False
        return self.db.check_field_permission(table_name, field_name, permission, pub_key_pem)

    def has_database_permission(self, permission, pub_key_pem):
        """Check if an identity has a database-level permission (read/write)."""
        if not self.db:
            return False
        identity = self.db._get_identity(pub_key_pem)
        return self.db.check_permission(identity, 'database', '*', permission)

    def get_current_user(self):
        """Get information about the current user logged in on the host."""
        return {
            "common_name": self.current_user_cn,
            "certificate_pem": self.current_user_cert_pem
        }

    def execute_signed_query(self, query, params=None):
        """Execute a signed database query on behalf of the sandboxed app using active user's key."""
        if not self.db:
            raise PermissionError("Database not connected to HostAPI.")
        if not self.current_user_cn or self.current_user_cn == "Unknown":
            raise PermissionError("No valid active user identity.")
            
        # Locate corresponding .key file on host
        key_filename = f"{self.current_user_cn}.key"
        if self.current_user_cn == "DESKTOP-GKSCQ7P": # support ca.crt mapping
            key_filename = "ca.key"
            
        key_path = os.path.join(self.workspace_path, key_filename)
        if not os.path.isfile(key_path):
            raise FileNotFoundError(f"Active private key not found on Host at {key_filename}")
            
        with open(key_path, 'rb') as f:
            pem_key = f.read()
            
        import json
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        import base64
        
        def _make_json_serializable(obj):
            if isinstance(obj, bytes):
                return base64.b64encode(obj).decode('utf-8')
            elif isinstance(obj, (list, tuple)):
                return [_make_json_serializable(i) for i in obj]
            elif isinstance(obj, dict):
                return {k: _make_json_serializable(v) for k, v in obj.items()}
            return obj

        params = params or []
        payload_dict = {"query": query, "params": _make_json_serializable(params)}
        payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
        
        private_key = load_pem_private_key(pem_key, password=None)
        signature = private_key.sign(
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return self.db.execute_signed(query, params, signature, self.current_user_cert_pem)


def execute_micro_app(code_func, workspace_path, db=None, current_user_cn=None, current_user_cert_pem=None):
    """
    Executes the micro-app's main function within a restricted sandbox.
    code_func should be a callable returned by dill.loads().
    Returns the Toga widget constructed by the micro-app.
    """
    # Create the host API bridge with the active db instance and current user
    host_api = HostAPI(workspace_path, db, current_user_cn, current_user_cert_pem)
    
    if callable(code_func):
        try:
            return code_func(toga, host_api)
        except Exception as e:
            # Fallback error UI
            box = toga.Box(style=toga.style.Pack(direction='column', padding=10))
            box.add(toga.Label("Error executing micro-app:", style=toga.style.Pack(color='red')))
            box.add(toga.Label(str(e)))
            return box
            
    raise ValueError("The stored code is not a callable function.")
