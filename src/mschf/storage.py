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

class MSFStorage:
    def __init__(self, filename):
        self.filename = filename
        self.conn = sqlite3.connect(filename)
        self.conn.execute("PRAGMA foreign_keys = ON")
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

    def execute_signed(self, query, params, signature, pub_key_pem):
        """Execute a query only if the signature and RBAC checks pass."""
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
            
        # Cryptographic Chain-of-Trust Check for X.509 Certificates
        pub_key_str = pub_key_pem.decode('utf-8') if isinstance(pub_key_pem, bytes) else pub_key_pem
        if "-----BEGIN CERTIFICATE-----" in pub_key_str:
            # Locate ca.crt relative to database, current directory, or project root
            # Prioritize the directory of the SQLite database container first
            ca_paths = []
            if self.filename:
                db_dir = os.path.dirname(os.path.abspath(self.filename))
                ca_paths.append(os.path.join(db_dir, 'ca.crt'))
            ca_paths.extend([
                'ca.crt',
                os.path.abspath('ca.crt'),
            ])
            ca_cert_pem = None
            for p in ca_paths:
                if os.path.isfile(p):
                    try:
                        with open(p, 'rb') as f:
                            ca_cert_pem = f.read()
                        break
                    except Exception:
                        pass
            
            if ca_cert_pem:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                try:
                    user_cert_bytes = pub_key_str.encode('utf-8')
                    user_cert = x509.load_pem_x509_certificate(user_cert_bytes, default_backend())
                    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
                    
                    # If this is not the Root CA itself, check that it's issued and signed by Root CA
                    if user_cert.signature != ca_cert.signature:
                        from cryptography.hazmat.primitives.asymmetric import padding
                        ca_public_key = ca_cert.public_key()
                        ca_public_key.verify(
                            user_cert.signature,
                            user_cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            user_cert.signature_hash_algorithm
                        )
                except Exception as e:
                    raise PermissionError(f"Cryptographic Chain Verification Failed: Identity certificate is not signed by the trusted Root CA. (Detail: {e})")
            
        # Resolve identity
        identity = self._get_identity(pub_key_pem)
        
        # TOFU Bootstrapping: If user_roles is completely empty, assign first user to 'admin'
        cursor = self.conn.cursor()
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
            system_tables = {'manifest', 'source_code', 'transactions', 'rbac_rules', 'user_roles'}
            if table_name in system_tables:
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

        # Execute query
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
            
        # Log the transaction using a separate cursor so we do not clobber the main query's results
        audit_cursor = self.conn.cursor()
        audit_cursor.execute('''
            INSERT INTO transactions (query, params, signature, pub_key)
            VALUES (?, ?, ?, ?)
        ''', (query, json.dumps(_make_json_serializable(params)), signature, pub_key_pem))
        
        self.conn.commit()
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
                            else:
                                verified = False
                        except Exception:
                            verified = False
                    
                    signer_cn = "Unknown"
                    try:
                        from cryptography import x509
                        from cryptography.x509.oid import NameOID
                        cert = x509.load_pem_x509_certificate(pub_key_pem if isinstance(pub_key_pem, bytes) else pub_key_pem.encode('utf-8'), default_backend())
                        signer_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    except Exception:
                        signer_cn = self._get_identity(pub_key_pem)
                        
                    return {
                        'verified': verified,
                        'signer': signer_cn,
                        'method': 'RSA-1024 / SHA-256 / PKCS#1 v1.5',
                        'error': None if verified else "Signature verification failed (data was tampered with or key is invalid)"
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

    def close(self):
        self.conn.close()
