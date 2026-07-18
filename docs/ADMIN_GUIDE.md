# Mischief Micro-App Platform: Administrator Guide

This guide describes how to initialize, manage, secure, and govern Mischief Storage Facility (`.msf`) micro-app containers. As an Administrator, you are responsible for maintaining the cryptographic trust boundary and managing Role-Based Access Control (RBAC) rules.

---

## 1. Cryptographic Security Model

The Mischief platform operates on a **zero-trust model** for database modification:
1. **Signature Verification:** No data modification or schema change (such as creating tables, setting manifest values, or updating source code) can be committed without a valid cryptographic signature.
2. **Identity Extraction:** Identities are bound to X.509 Certificates or RSA Public Keys. When a transaction is submitted, the platform extracts a stable identifier:
    *   **Certificates:** Extracts the Common Name (e.g., `cert:CN=system_admin`).
    *   **Raw Public Keys:** Falls back to a stable SHA-256 fingerprint (e.g., `key:8e1fa92b`).
3. **Auditable Ledger:** Every executed write operation is cryptographically logged to the `transactions` table, preserving the query, serialized parameters, the signature, and the signer's public key.

### 1.1 Root Certificate Authority vs. User Certificates

The cryptographic hierarchy strictly separates the **Trust Anchor** from the **User Identities**:

*   **Root CA (`ca.crt` / `ca.key`):** This is a true Certificate Authority (contains `CA:TRUE` in its basic constraints). Its private key is kept highly isolated and is used *exclusively* to digitally sign/issue subordinate user certificates. The CA is never used to run micro-apps or sign transactional queries.
*   **User Certificates (`admin.crt`, `support.crt`):** These represent physical operators or automated service accounts, containing `CA:FALSE` under basic constraints. They are signed by the root CA. Transactions are signed using the user's specific key pair, which is then validated against their user certificate and verified back to the root CA.

---

## 2. Bootstrapping a New MSF Container

Mischief uses a **Trust on First Use (TOFU)** bootstrapping mechanism. When an MSF file is initialized, the `user_roles` table is empty. The identity that signs the **very first transaction** is automatically assigned the `admin` role.

### Step-by-Step Bootstrap Procedure

#### A. Generate your Admin Keypair
Create a self-signed X.509 certificate to establish your identity.

```python
from mschf.gen_cert import generate_selfsigned_cert

# Generate PEM-encoded certificate and private key
admin_cert, admin_key = generate_selfsigned_cert('system_admin')

with open('admin.crt', 'wb') as f:
    f.write(admin_cert)
with open('admin.key', 'wb') as f:
    f.write(admin_key)
```

#### B. Initialize and Sign the First Transaction
Initialize the storage engine and assign the first manifest element (typically the `entry_point` variable) to bootstrap your admin privilege.

```python
import json
import base64
from mschf.storage import MSFStorage
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 1. Open / create the container
db = MSFStorage('my_app.msf')

# 2. Prepare the query & parameters
query = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
params = ['entry_point', 'main_view']

# 3. Create a stable JSON payload to sign
payload_dict = {
    "query": query, 
    "params": ["entry_point", "main_view"]
}
payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')

# 4. Sign the payload using your Admin Private Key
private_key = serialization.load_pem_private_key(admin_key, password=None, backend=default_backend())
signature = private_key.sign(
    payload_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# 5. Execute transaction to bootstrap 'admin' role
db.set_manifest_item('entry_point', 'main_view', signature, admin_cert)
print("✓ Database initialized. Your identity is now registered as root admin.")
```

---

## 3. Provisioning Users & Roles

Once bootstrapped, administrators can register new users and assign them specific roles. Common roles include `support`, `auditor`, and `guest`.

### Assigning a Role to a Certificate
To register a support technician using their certificate:

```python
# Load support user certificate
with open('support_tech.crt', 'rb') as f:
    support_cert = f.read()

# Resolve the support user's stable identity string
support_identity = db._get_identity(support_cert)

# Define the SQL command to register the role
query = "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)"
params = [support_identity, 'support']

# Sign using Admin Private Key
payload_dict = {"query": query, "params": params}
payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())

# Commit the assignment
db.assign_user_role(support_identity, 'support', signature, admin_cert)
print(f"✓ Provisioned {support_identity} with role: support")
```

---

## 4. Configuring RBAC Rules

The administrator defines permission rules at four granular levels. Rules map a `role` to a `permission` (`*`, `read`, `write`, `create`, `delete`) on a specific `target`.

```python
# Helper to quickly authorize and sign an RBAC rule
def add_rule(level, target, role, permission):
    query = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
    params = [level, target, role, permission]
    
    payload_dict = {"query": query, "params": params}
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
    sig = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    
    db.add_rbac_rule(level, target, role, permission, sig, admin_cert)
```

### A. Database-Level Rules

Database rules authorize whether a role is allowed to access the database at all. These checks are split into read operations (`SELECT`) and write operations (`INSERT`, `UPDATE`, `DELETE`, etc.), providing three robust operational tiers:

1.  **No Access (Default / Unassigned):** If a user lacks database-level `read` permission, **any query execution is blocked** and the platform **completely hides and disables the micro-app UI**, displaying a locked **Access Denied Screen**.
2.  **Read-Only:** If a user is provisioned with database `read` permission but lacks `write` permission, they can read from tables but are strictly blocked from writing.
3.  **Full Access:** If a user has both `read` and `write` (or wildcard `*`) database permissions, they have unrestricted query capabilities.

```python
# Allow 'support' role read-only database-level capabilities
add_rule('database', '*', 'support', 'read')

# Allow 'admin' role complete read/write database capabilities
add_rule('database', '*', 'admin', 'write')
add_rule('database', '*', 'admin', 'read')
```

### B. Object-Level Rules
Object rules define access to dynamic custom tables created by the micro-app.
```python
# Allow 'support' role to read tickets
add_rule('object', 'tickets', 'support', 'read')

# Allow 'support' role to write/update customer data
add_rule('object', 'customers', 'support', 'write')
```

### C. View-Level Rules
View rules define access rights to native GUI views/panels inside the micro-app.
```python
# Allow 'support' to open the customer dashboard
add_rule('view', 'customer_dashboard', 'support', 'read')
```

### D. Field-Level Rules
Field rules restrict access to specific database columns. The format of the target must be `table.field`. Wildcards are checked hierarchically.
```python
# Allow 'support' to read the ticket title column
add_rule('field', 'tickets.title', 'support', 'read')

# Allow 'support' to read ALL columns on tickets except those restricted
add_rule('field', 'tickets.*', 'support', 'read')
```

### How rules are enforced

Every signed statement is executed under a SQLite **authorizer callback**: while compiling the statement, the engine asks the platform for a verdict on *each* table and column the program will actually touch — including tables reached through `JOIN`s, subqueries, CTEs, views, and triggers. A statement that references even one unauthorized table is rejected before it executes, is not appended to the `transactions` audit log, and leaves no side effects.

Consequences to be aware of:

- Reading a permitted table via a query that *also* touches a forbidden table (e.g. `SELECT t.title FROM tickets t JOIN secrets s`) is denied outright.
- System tables (`manifest`, `source_code`, `transactions`, `rbac_rules`, `user_roles`) are admin-only for **all** operations.
- `PRAGMA`, `ATTACH`, `DETACH`, and virtual-table DDL are never permitted inside signed transactions, for any role — including admin.
- DDL maps to the `create` permission (`CREATE TABLE`, `CREATE INDEX/TRIGGER/VIEW`, `ALTER TABLE`) and `delete` permission (`DROP ...`).

### Engine-enforced attribution (`current_signer()`)

Every `MSFStorage` connection registers a `current_signer()` SQL function that returns the verified identity string (e.g. `cert:CN=admin`) of the signed transaction currently executing, and `NULL` outside one. Use it in container triggers to stamp `created_by` / `updated_by`-style audit columns: the value comes from the verified signature, so micro-app code can neither spoof nor forget attribution, and out-of-band writes with a raw sqlite3 client fail on such triggers with "no such function". See `dev_tracker.py`'s `AUDIT_TRIGGERS` for the canonical pattern (insert/update stamping plus a `RAISE(ABORT)` immutability guard on the created-fields).

---

## 5. Deploying and Modifying Micro-App Code

Deploying micro-app code is restricted to administrators. The code is written as a pickled callable function using `dill`.

```python
import dill

# The micro-app entry-point function
def my_custom_app(toga, host_api):
    return toga.Box(children=[toga.Label("Hello World!")])

# Serialize code
pickled_bytes = dill.dumps(my_custom_app)

# Prepare query
query = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
# dill bytes must be encoded to base64 for signed transaction logging
params = ['main_app', base64.b64encode(pickled_bytes).decode('utf-8')]

payload_dict = {"query": query, "params": params}
payload_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
sig = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())

# Deploy to container
db.store_code('main_app', my_custom_app, sig, admin_cert)
print("✓ Successfully deployed updated micro-app code.")
```
