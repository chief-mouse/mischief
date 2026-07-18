import sqlite3
import os
import json
import dill
import re
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from mschf.gen_cert import is_cert_signed_by_ca

# The trusted Root CA is anchored to the host installation, never to the .msf's
# own directory. Sourcing it from next to the (untrusted) container would let a
# malicious app ship its own ca.crt and have its signatures "verified" against it.
HOST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CA_CERT_PATH = os.path.join(HOST_ROOT, "ca.crt")


class MSFStorage:
    # Tables owned by the platform itself; writable only by admin identities.
    SYSTEM_TABLES = frozenset({'manifest', 'source_code', 'transactions', 'rbac_rules', 'user_roles'})

    def __init__(self, filename, ca_cert_path=None):
        self.filename = filename
        self.ca_cert_path = ca_cert_path or DEFAULT_CA_CERT_PATH
        self.conn = sqlite3.connect(filename)
        self.conn.execute("PRAGMA foreign_keys = ON")
        # current_signer(): SQL function returning the verified identity string
        # (e.g. 'cert:CN=admin') of the signed transaction currently executing,
        # or NULL outside one. Container triggers use it to stamp audit fields
        # from the cryptographic identity instead of trusting app-supplied
        # values. Note it also means out-of-band writes with a raw sqlite3
        # client fail on such triggers ("no such function") — a feature.
        self._active_signer = None
        self.conn.create_function('current_signer', 0, lambda: self._active_signer)
        # Optional host callback fired after a *mutating* signed transaction
        # commits (called with this storage). The GUI uses it to live-refresh
        # other open documents showing the same container.
        self.on_commit = None
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        
        # Manifest table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS manifest (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Source code table (storing pickled code)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS source_code (
                id TEXT PRIMARY KEY,
                code_blob BLOB
            )
        ''')
        
        # Transactions table (audit log of signed transactions)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT,
                params TEXT,
                signature BLOB,
                pub_key BLOB,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # RBAC table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rbac_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT CHECK(level IN ('database', 'object', 'view', 'field')),
                target TEXT,
                role TEXT,
                permission TEXT
            )
        ''')

        # User roles mapping table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_roles (
                identity TEXT PRIMARY KEY,
                role TEXT NOT NULL
            )
        ''')
        
        self.conn.commit()

    def _get_identity(self, pub_key_pem):
        """Extract a stable, readable cryptographic identity string from a PEM Cert/Public Key."""
        if isinstance(pub_key_pem, str):
            pub_key_bytes = pub_key_pem.encode('utf-8')
        else:
            pub_key_bytes = pub_key_pem

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            cert = x509.load_pem_x509_certificate(pub_key_bytes, default_backend())
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            return f"cert:CN={cn}"
        except Exception:
            # Fallback to key fingerprint if not a valid cert PEM
            try:
                # Strip headers/footers and newlines to get clean base64 data for stable fingerprinting
                cleaned = b"".join(line.strip() for line in pub_key_bytes.split(b"\n") if b"---" not in line)
                h = hashlib.sha256(cleaned).hexdigest()
                return f"key:{h[:16]}"
            except Exception as e:
                # Extreme fallback if bytes are corrupted or arbitrary
                h = hashlib.sha256(pub_key_bytes).hexdigest()
                return f"raw:{h[:16]}"

    def _parse_sql_query(self, query):
        """Extract (operation, table_name) from basic SQLite queries."""
        q = query.strip().upper()
        # Remove comment lines
        q = re.sub(r'--.*$', '', q, flags=re.MULTILINE)
        
        # CREATE TABLE IF NOT EXISTS table_name ...
        m = re.match(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)', q)
        if m:
            return 'create', m.group(1).lower()
            
        # DROP TABLE IF EXISTS table_name ...
        m = re.match(r'DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-zA-Z0-9_]+)', q)
        if m:
            return 'delete', m.group(1).lower()
            
        # INSERT INTO table_name ...
        m = re.match(r'INSERT\s+OR\s+REPLACE\s+INTO\s+([a-zA-Z0-9_]+)', q) or re.match(r'INSERT\s+INTO\s+([a-zA-Z0-9_]+)', q)
        if m:
            return 'write', m.group(1).lower()
            
        # UPDATE table_name ...
        m = re.match(r'UPDATE\s+([a-zA-Z0-9_]+)', q)
        if m:
            return 'write', m.group(1).lower()
            
        # DELETE FROM table_name ...
        m = re.match(r'DELETE\s+FROM\s+([a-zA-Z0-9_]+)', q)
        if m:
            return 'write', m.group(1).lower()
            
        # SELECT ... FROM table_name ...
        m = re.search(r'FROM\s+([a-zA-Z0-9_]+)', q)
        if m:
            return 'read', m.group(1).lower()
            
        return 'unknown', '*'

    def _rbac_snapshot(self, identity):
        """Resolve the identity's role and object-level rules up front.

        The authorizer callback fires while the engine is compiling the user's
        statement, so it must not issue queries on this connection re-entrantly;
        everything it needs is captured here first.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT role FROM user_roles WHERE identity = ?", (identity,))
        row = cursor.fetchone()
        role = row[0] if row else 'guest'
        cursor.execute("SELECT target, permission FROM rbac_rules WHERE level = 'object' AND role = ?", (role,))
        return role, cursor.fetchall()

    def _make_authorizer(self, identity, role, object_rules, denials):
        """Build a sqlite3 authorizer enforcing RBAC on every table the compiled
        statement actually touches.

        Unlike the regex pre-check (which only sees the first table named in the
        SQL text), SQLite consults this callback at prepare time for each
        table/column access the program will perform — including those reached
        through joins, subqueries, CTEs, views, and triggers — and for
        side-channel statements (PRAGMA, ATTACH) that the regex classifies as
        'unknown'. Denial reasons are appended to ``denials`` so the caller can
        raise a meaningful PermissionError.
        """
        def table_allowed(table, perm):
            if not table:
                return True
            t = table.lower()
            # Engine-internal schema bookkeeping (sqlite_master etc.). Direct
            # user writes to these are separately refused by SQLite itself
            # unless writable_schema is enabled — and PRAGMA is denied below.
            if t.startswith('sqlite_'):
                return True
            if role == 'admin':
                return True
            if t in self.SYSTEM_TABLES:
                # System tables are admin-only for every operation, matching
                # the pre-check (which denies non-admin reads too).
                return False
            for target, p in object_rules:
                if target and target.lower() in (t, '*') and p in (perm, '*'):
                    return True
            return False

        A = lambda name: getattr(sqlite3, name, None)

        always_allowed = {a for a in (
            A('SQLITE_SELECT'), A('SQLITE_TRANSACTION'), A('SQLITE_SAVEPOINT'),
            A('SQLITE_FUNCTION'), A('SQLITE_RECURSIVE'),
        ) if a is not None}
        always_denied = {a for a in (
            A('SQLITE_PRAGMA'), A('SQLITE_ATTACH'), A('SQLITE_DETACH'),
            A('SQLITE_CREATE_VTABLE'), A('SQLITE_DROP_VTABLE'),
        ) if a is not None}
        # action -> (permission, which arg carries the table name)
        table_actions = {a: v for a, v in {
            A('SQLITE_READ'): ('read', 1),
            A('SQLITE_INSERT'): ('write', 1),
            A('SQLITE_UPDATE'): ('write', 1),
            A('SQLITE_DELETE'): ('write', 1),
            A('SQLITE_CREATE_TABLE'): ('create', 1),
            A('SQLITE_CREATE_TEMP_TABLE'): ('create', 1),
            A('SQLITE_CREATE_VIEW'): ('create', 1),
            A('SQLITE_CREATE_TEMP_VIEW'): ('create', 1),
            A('SQLITE_CREATE_INDEX'): ('create', 2),
            A('SQLITE_CREATE_TEMP_INDEX'): ('create', 2),
            A('SQLITE_CREATE_TRIGGER'): ('create', 2),
            A('SQLITE_CREATE_TEMP_TRIGGER'): ('create', 2),
            A('SQLITE_ALTER_TABLE'): ('create', 2),
            A('SQLITE_REINDEX'): ('create', 1),
            A('SQLITE_ANALYZE'): ('create', 1),
            A('SQLITE_DROP_TABLE'): ('delete', 1),
            A('SQLITE_DROP_TEMP_TABLE'): ('delete', 1),
            A('SQLITE_DROP_VIEW'): ('delete', 1),
            A('SQLITE_DROP_TEMP_VIEW'): ('delete', 1),
            A('SQLITE_DROP_INDEX'): ('delete', 2),
            A('SQLITE_DROP_TEMP_INDEX'): ('delete', 2),
            A('SQLITE_DROP_TRIGGER'): ('delete', 2),
            A('SQLITE_DROP_TEMP_TRIGGER'): ('delete', 2),
        }.items() if a is not None}

        def authorize(action, arg1, arg2, db_name, source):
            if action in always_allowed:
                return sqlite3.SQLITE_OK
            if action in always_denied:
                denials.append(f"statement class (action {action}) is not permitted in signed transactions")
                return sqlite3.SQLITE_DENY
            if action in table_actions:
                perm, table_arg = table_actions[action]
                table = arg1 if table_arg == 1 else arg2
                if table_allowed(table, perm):
                    return sqlite3.SQLITE_OK
                denials.append(f"'{perm}' on table '{table}' denied for identity '{identity}'")
                return sqlite3.SQLITE_DENY
            denials.append(f"unrecognized action {action} denied")
            return sqlite3.SQLITE_DENY

        return authorize

    def check_permission(self, identity, level, target, permission):
        """
        Check if the resolved identity has a specific permission for a level/target.
        Returns True if allowed, False otherwise.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT role FROM user_roles WHERE identity = ?", (identity,))
        row = cursor.fetchone()
        role = row[0] if row else 'guest'  # default fallback role is guest
        
        # Admin bypass
        if role == 'admin':
            return True
            
        # Check rules matching level, target, role, permission (supports wildcard '*')
        cursor.execute('''
            SELECT COUNT(*) FROM rbac_rules
            WHERE level = ?
              AND (target = ? OR target = '*')
              AND role = ?
              AND (permission = ? OR permission = '*')
        ''', (level, target, role, permission))
        count = cursor.fetchone()[0]
        return count > 0

    def check_view_permission(self, view_name, pub_key_pem):
        """Check if an identity has permission to access a specific view."""
        identity = self._get_identity(pub_key_pem)
        return self.check_permission(identity, 'view', view_name, 'read')

    def check_field_permission(self, table_name, field_name, permission, pub_key_pem):
        """Check if an identity has permission to access a specific field on a table."""
        identity = self._get_identity(pub_key_pem)
        
        # Check hierarchical specificity: 
        # 1. table.field
        target_specific = f"{table_name}.{field_name}"
        if self.check_permission(identity, 'field', target_specific, permission):
            return True
            
        # 2. table.*
        target_table_wildcard = f"{table_name}.*"
        if self.check_permission(identity, 'field', target_table_wildcard, permission):
            return True
            
        # 3. Global wildcard '*'
        if self.check_permission(identity, 'field', '*', permission):
            return True
            
        return False

    def _signer_is_ca_trusted(self, pub_key_pem):
        """True only if the signer presented an X.509 cert that chains to the host Root CA.

        A bare public key (no certificate) has no chain to the CA and is therefore
        not trusted for the "verified" banner, even if its signature is valid.
        """
        pub_key_str = pub_key_pem.decode('utf-8') if isinstance(pub_key_pem, bytes) else pub_key_pem
        if "-----BEGIN CERTIFICATE-----" not in pub_key_str:
            return False
        if not os.path.isfile(self.ca_cert_path):
            return False
        with open(self.ca_cert_path, 'rb') as f:
            ca_cert_pem = f.read()
        return is_cert_signed_by_ca(pub_key_str, ca_cert_pem)

    def verify_signature(self, payload, signature, pub_key_pem):
        """Verify the signature of a payload using the provided PEM public key or certificate."""
        if isinstance(pub_key_pem, str):
            pub_key_bytes = pub_key_pem.encode('utf-8')
        else:
            pub_key_bytes = pub_key_pem

        try:
            from cryptography import x509
            try:
                cert = x509.load_pem_x509_certificate(pub_key_bytes, default_backend())
                public_key = cert.public_key()
            except Exception:
                public_key = serialization.load_pem_public_key(pub_key_bytes, backend=default_backend())
                
            public_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

    def execute_signed(self, query, params, signature, pub_key_pem, allow_bootstrap=False):
        """Execute a query only if the signature and RBAC checks pass.

        ``allow_bootstrap`` is the ONLY way the first-writer-becomes-admin
        bootstrap can fire; callers that run untrusted code (the sandbox) must
        never set it. Use ``bootstrap_admin`` for the deliberate authoring step.
        """
        import base64
        def _make_json_serializable(obj):
            if isinstance(obj, bytes):
                return base64.b64encode(obj).decode('utf-8')
            elif isinstance(obj, (list, tuple)):
                return [_make_json_serializable(i) for i in obj]
            elif isinstance(obj, dict):
                return {k: _make_json_serializable(v) for k, v in obj.items()}
            return obj

        # Verify Signature
        payload_dict = {"query": query, "params": _make_json_serializable(params)}
        payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
        
        if not self.verify_signature(payload_bytes, signature, pub_key_pem):
            raise PermissionError("Invalid transaction signature")
            
        # Cryptographic Chain-of-Trust Check for X.509 Certificates.
        # The trust anchor is the HOST's Root CA (self.ca_cert_path) — never a
        # ca.crt sitting next to the .msf container. Fail closed: if the trusted
        # CA is missing we cannot verify the chain, so the transaction is rejected.
        pub_key_str = pub_key_pem.decode('utf-8') if isinstance(pub_key_pem, bytes) else pub_key_pem
        if "-----BEGIN CERTIFICATE-----" in pub_key_str:
            if not os.path.isfile(self.ca_cert_path):
                raise PermissionError(
                    "Cryptographic Chain Verification Failed: trusted Root CA not found at "
                    f"{self.ca_cert_path}."
                )
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert_pem = f.read()
            # A self-signed Root CA verifies against itself, so signing directly
            # with the Root CA is still accepted; anything else must be CA-issued.
            if not is_cert_signed_by_ca(pub_key_str, ca_cert_pem):
                raise PermissionError(
                    "Cryptographic Chain Verification Failed: Identity certificate is not "
                    "signed by the trusted Root CA."
                )

        # Resolve identity
        identity = self._get_identity(pub_key_pem)

        # Admin bootstrapping is an explicit, opt-in authoring step, never a side
        # effect of a normal write. Otherwise anyone holding a CA-signed cert could
        # silently become admin of a fresh container just by writing to it first.
        # Running micro-apps go through the sandbox, which never sets allow_bootstrap.
        cursor = self.conn.cursor()
        if allow_bootstrap:
            cursor.execute("SELECT COUNT(*) FROM user_roles")
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO user_roles (identity, role) VALUES (?, 'admin')", (identity,))
                self.conn.commit()

        # Parse query for RBAC
        operation, table_name = self._parse_sql_query(query)
        
        # Enforce database level permission (No Access, Read-Only, or Full Access)
        db_perm_needed = 'read' if operation == 'read' else 'write'
        if not self.check_permission(identity, 'database', '*', db_perm_needed):
            raise PermissionError(f"Access denied: Identity '{identity}' does not have database-level {db_perm_needed} permissions ('No Access' active).")

        # Enforce object level permission
        if table_name != '*':
            if table_name in self.SYSTEM_TABLES:
                # System tables are strictly admin-only for schema modifications or data writes
                cursor.execute("SELECT role FROM user_roles WHERE identity = ?", (identity,))
                row = cursor.fetchone()
                role = row[0] if row else 'guest'
                if role != 'admin':
                    raise PermissionError(f"Access denied: System table '{table_name}' can only be modified by admin.")
            else:
                # Non-system dynamic table checks
                if not self.check_permission(identity, 'object', table_name, operation):
                    raise PermissionError(f"Access denied: Identity '{identity}' does not have '{operation}' permission on table '{table_name}'.")

        # Execute under the SQLite authorizer. The regex checks above are a
        # first, coarse gate kept for their clear error messages; the authorizer
        # is the authoritative enforcement — the engine consults it at prepare
        # time for every table/column the compiled statement touches, so access
        # smuggled past the regex (joins, subqueries, CTEs, views, triggers,
        # PRAGMA, ATTACH) is denied here. Installing/clearing the authorizer
        # also expires SQLite's prepared-statement cache, so every signed query
        # is freshly compiled with enforcement active.
        role, object_rules = self._rbac_snapshot(identity)
        denials = []
        self._active_signer = identity
        self.conn.set_authorizer(self._make_authorizer(identity, role, object_rules, denials))
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
        except sqlite3.DatabaseError as e:
            if denials:
                raise PermissionError(f"Access denied: {denials[0]}") from e
            raise
        finally:
            self.conn.set_authorizer(None)
            self._active_signer = None


        # Log the transaction using a separate cursor so we do not clobber the main query's results
        audit_cursor = self.conn.cursor()
        audit_cursor.execute('''
            INSERT INTO transactions (query, params, signature, pub_key)
            VALUES (?, ?, ?, ?)
        ''', (query, json.dumps(_make_json_serializable(params)), signature, pub_key_pem))
        
        self.conn.commit()

        # Reactive redraw: notify the host after mutating transactions only.
        # Signed reads also commit (they append an audit row), so notifying on
        # 'read' would let two open documents redraw each other forever.
        if operation != 'read' and self.on_commit:
            try:
                self.on_commit(self)
            except Exception as e:
                print(f"on_commit notification failed: {e}")

        return cursor

    def set_manifest_item(self, key, value, signature, pub_key_pem):
        """Set a manifest item securely."""
        query = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        self.execute_signed(query, [key, value], signature, pub_key_pem)

    def get_manifest_item(self, key):
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM manifest WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def store_code(self, id_val, code_obj, signature, pub_key_pem):
        """Store pickled Python code securely."""
        pickled_code = dill.dumps(code_obj)
        query = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
        self.execute_signed(query, [id_val, pickled_code], signature, pub_key_pem)

    def get_code(self, id_val):
        """Retrieve pickled Python code."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT code_blob FROM source_code WHERE id = ?", (id_val,))
        row = cursor.fetchone()
        if row and row[0]:
            return dill.loads(row[0])
        return None

    def get_code_signature_status(self, id_val):
        """
        Scan transactions to verify the signature of the code with ID id_val.
        Returns a dictionary: {
            'verified': bool,
            'signer': str,
            'method': str,
            'error': str or None
        }
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT query, params, signature, pub_key FROM transactions WHERE query LIKE 'INSERT OR REPLACE INTO source_code%' ORDER BY id DESC")
            rows = cursor.fetchall()
            
            for query, params_str, signature, pub_key_pem in rows:
                try:
                    params = json.loads(params_str)
                except Exception:
                    continue
                if isinstance(params, list) and len(params) > 0 and params[0] == id_val:
                    # Found the transaction that stored this code blob!
                    # Reconstruct payload_bytes
                    payload_dict = {"query": query, "params": params}
                    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
                    
                    # Verify signature
                    verified = self.verify_signature(payload_bytes, signature, pub_key_pem)
                    error = None if verified else "Signature verification failed (data was tampered with or key is invalid)"

                    # Cryptographic check: Ensure code blob in table matches the signed blob in transactions
                    if verified:
                        try:
                            cursor.execute("SELECT code_blob FROM source_code WHERE id = ?", (id_val,))
                            current_row = cursor.fetchone()
                            if current_row and current_row[0]:
                                current_blob = current_row[0]
                                import base64
                                signed_blob = base64.b64decode(params[1])
                                if current_blob != signed_blob:
                                    verified = False
                                    error = "Code blob does not match the signed transaction (tampered)"
                            else:
                                verified = False
                                error = "Code blob is missing from the container"
                        except Exception:
                            verified = False
                            error = "Signature verification failed (data was tampered with or key is invalid)"

                    # Trust check: a valid signature from a signer whose cert does not chain
                    # to the host Root CA is NOT "verified" — it only proves the blob matches
                    # whatever key is in the audit row, not that a trusted party signed it.
                    if verified and not self._signer_is_ca_trusted(pub_key_pem):
                        verified = False
                        error = "Signer certificate is not signed by the trusted Root CA"

                    signer_cn = "Unknown"
                    method = "RSA / SHA-256 / PKCS#1 v1.5"
                    try:
                        from cryptography import x509
                        from cryptography.x509.oid import NameOID
                        cert = x509.load_pem_x509_certificate(pub_key_pem if isinstance(pub_key_pem, bytes) else pub_key_pem.encode('utf-8'), default_backend())
                        signer_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        method = f"RSA-{cert.public_key().key_size} / SHA-256 / PKCS#1 v1.5"
                    except Exception:
                        signer_cn = self._get_identity(pub_key_pem)

                    return {
                        'verified': verified,
                        'signer': signer_cn,
                        'method': method,
                        'error': error
                    }
            
            return {
                'verified': False,
                'signer': 'None',
                'method': 'None',
                'error': "No matching code signing transaction found in the audit log"
            }
        except Exception as e:
            return {
                'verified': False,
                'signer': 'None',
                'method': 'None',
                'error': f"Failed to verify code signature: {e}"
            }

    def create_object_table(self, table_name, fields, signature, pub_key_pem):
        """Create a dynamic object table."""
        columns = ", ".join(f"{name} {definition}" for name, definition in fields.items())
        query = f"CREATE TABLE IF NOT EXISTS {table_name} (id INTEGER PRIMARY KEY AUTOINCREMENT, {columns})"
        self.execute_signed(query, [], signature, pub_key_pem)

    def add_rbac_rule(self, level, target, role, permission, signature, pub_key_pem):
        """Add an RBAC rule (Admin only)."""
        query = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
        self.execute_signed(query, [level, target, role, permission], signature, pub_key_pem)

    def assign_user_role(self, target_identity, role, signature, pub_key_pem):
        """Assign a role to a cryptographic identity (Admin only)."""
        query = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
        self.execute_signed(query, [target_identity, role], signature, pub_key_pem)

    def bootstrap_admin(self, query, params, signature, pub_key_pem):
        """Deliberately claim admin for a fresh container while making the first write.

        This is the single opt-in authoring entry point that lets first-writer
        bootstrapping fire. It only takes effect when ``user_roles`` is empty; on
        an already-provisioned container it behaves exactly like ``execute_signed``.
        """
        return self.execute_signed(query, params, signature, pub_key_pem, allow_bootstrap=True)

    def close(self):
        self.conn.close()
