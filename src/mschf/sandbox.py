import os
import toga


class HubWriteResult:
    """Return value for homed-container mutations via ``hub_write``.

    Micro-apps treat mutations as fire-and-forget today (they only use the
    returned cursor for SELECTs). Homed writes therefore return this small
    object instead of a SQLite cursor:

    - ``status``: ``'committed'`` (landed on hub + pulled back) or
      ``'queued'`` (hub unreachable; intent held in ``sync_outbox``)
    - ``seq``: committed ledger sequence number, or ``None`` when queued
    """

    __slots__ = ('status', 'seq')

    def __init__(self, status, seq=None):
        self.status = status
        self.seq = seq

    def __repr__(self):
        return f"HubWriteResult(status={self.status!r}, seq={self.seq!r})"


class HostAPI:
    """Bridge API exposed to the micro-app. Restricted to local MSF, config, and ID files."""
    def __init__(self, workspace_path, db=None, current_user_cn=None, current_user_cert_pem=None, key_path=None, key_passphrase=None):
        self.workspace_path = os.path.abspath(workspace_path)
        self.db = db
        self.current_user_cn = current_user_cn or "Unknown"
        self.current_user_cert_pem = current_user_cert_pem or ""
        self.key_path = key_path
        self.key_passphrase = key_passphrase
        
    def _is_safe_path(self, filename):
        safe_path = os.path.abspath(os.path.join(self.workspace_path, filename))
        return safe_path.startswith(self.workspace_path) and os.path.isfile(safe_path)

    def list_local_msf(self):
        """Return a list of local .msf files in the workspace."""
        if not self.workspace_path or not os.path.isdir(self.workspace_path):
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

    def _load_private_key(self):
        """Load the active identity's private key (passphrase-aware)."""
        if not self.key_path or not os.path.isfile(self.key_path):
            raise FileNotFoundError(
                f"Active private key not found on host for identity '{self.current_user_cn}'"
                + (f" (expected at {self.key_path})" if self.key_path else "")
            )
        with open(self.key_path, 'rb') as f:
            pem_key = f.read()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        password = self.key_passphrase.encode('utf-8') if self.key_passphrase else None
        try:
            return load_pem_private_key(pem_key, password=password)
        except (TypeError, ValueError) as e:
            raise PermissionError(
                f"Could not unlock private key for '{self.current_user_cn}' "
                f"(bad or missing passphrase): {e}"
            )

    def _local_unsigned_read(self, query, params):
        """RBAC-checked local SELECT on a homed replica (no ledger append).

        Homed containers refuse signed reads (they would advance the chain);
        product reads therefore run unsigned after the same coarse RBAC gates
        as ``execute_signed`` (database-level + object-level for the parsed
        table). System tables remain admin-only.
        """
        identity = self.db._get_identity(self.current_user_cert_pem)
        operation, table_name = self.db._parse_sql_query(query)
        if operation != 'read':
            raise PermissionError(
                f"Local unsigned path is SELECT-only; got operation={operation!r}"
            )
        if not self.db.check_permission(identity, 'database', '*', 'read'):
            raise PermissionError(
                f"Access denied: Identity '{identity}' does not have database-level "
                f"read permissions ('No Access' active)."
            )
        if table_name != '*':
            if table_name in self.db.SYSTEM_TABLES:
                cursor = self.db.conn.cursor()
                cursor.execute(
                    "SELECT role FROM user_roles WHERE identity = ?", (identity,)
                )
                row = cursor.fetchone()
                role = row[0] if row else 'guest'
                if role != 'admin':
                    raise PermissionError(
                        f"Access denied: System table '{table_name}' can only be "
                        f"modified by admin."
                    )
            else:
                if not self.db.check_permission(
                    identity, 'object', table_name, 'read'
                ):
                    raise PermissionError(
                        f"Access denied: Identity '{identity}' does not have "
                        f"'read' permission on table '{table_name}'."
                    )
        cursor = self.db.conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor

    def _hub_mutation(self, query, params):
        """Submit a mutation through ``sync.hub_write`` for a homed container."""
        from mschf import sync as msync

        hub_url, hub_cn = msync.homing(self.db)
        if not hub_cn:
            raise PermissionError("Container is not homed; cannot hub_write.")
        private_key = self._load_private_key()
        container_id = os.path.splitext(
            os.path.basename(self.db.filename)
        )[0]
        cert_pem = self.current_user_cert_pem
        if isinstance(cert_pem, bytes):
            cert_pem = cert_pem.decode('utf-8')
        result = msync.hub_write(
            self.db,
            hub_url or '',
            container_id,
            private_key,
            cert_pem,
            self.current_user_cn,
            query,
            params,
            expected_hub_cn=hub_cn,
            ca_cert_path=getattr(self.db, '_ca_cert_path_arg', None),
            trust_dir=getattr(self.db, 'trust_dir', None),
        )
        return HubWriteResult(
            result.get('status', 'queued'),
            result.get('seq'),
        )

    def execute_signed_query(self, query, params=None):
        """Execute a database query on behalf of the sandboxed app.

        **Unhomed container** — signs with the active user's key and runs
        ``execute_signed`` locally (ledger advances; RBAC + authorizer enforce).
        Returns a SQLite cursor.

        **Homed container + SELECT** — RBAC-checked local unsigned read (no
        ledger row; the hub is the only chain serializer, so signed reads are
        refused on replicas). Returns a SQLite cursor so existing micro-apps
        keep working unmodified.

        **Homed container + mutation** — routes through ``sync.hub_write``
        (flush pending → submit → pull-back; queues to the outbox when the hub
        is unreachable). Returns a ``HubWriteResult`` with ``.status``
        (``'committed'`` / ``'queued'``) and ``.seq`` (or ``None``). Still
        raises ``PermissionError`` on RBAC/permission failures exactly as
        before. Offline queue is not an exception — apps take their normal
        success path; the GUI sync-status line shows the pending count.
        """
        if not self.db:
            raise PermissionError("Database not connected to HostAPI.")
        if not self.current_user_cn or self.current_user_cn == "Unknown":
            raise PermissionError("No valid active user identity.")

        params = params or []

        from mschf import sync as msync
        hub_url, hub_cn = msync.homing(self.db)

        if hub_cn:
            operation, _table = self.db._parse_sql_query(query)
            if operation == 'read':
                return self._local_unsigned_read(query, params)
            return self._hub_mutation(query, params)

        # Unhomed: local signed execute (unchanged).
        private_key = self._load_private_key()

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from mschf.storage import canonical_payload

        next_seq, prev_hash = self.db.get_chain_head()
        payload_bytes = canonical_payload(
            query, params, next_seq, prev_hash, self.db.container_uid)

        signature = private_key.sign(
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return self.db.execute_signed(
            query, params, signature, self.current_user_cert_pem
        )


def execute_micro_app(code_func, workspace_path, db=None, current_user_cn=None, current_user_cert_pem=None, key_path=None, key_passphrase=None):
    """
    Executes the micro-app's main function within a restricted sandbox.
    code_func should be a callable returned by dill.loads().
    Returns the Toga widget constructed by the micro-app.
    """
    # Create the host API bridge with the active db instance and current user
    host_api = HostAPI(workspace_path, db, current_user_cn, current_user_cert_pem, key_path, key_passphrase)
    
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
