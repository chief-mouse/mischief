import sys
import os
import socket
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath('src'))

from mschf.storage import MSFStorage, canonical_payload
from mschf.gen_cert import generate_user_cert, x509, default_backend, serialization
import dill
from cryptography.hazmat.primitives import hashes, serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Resolve the absolute project directory
PROJ_DIR = os.path.abspath(os.path.dirname(__file__))
ca_cert_path = os.path.join(PROJ_DIR, 'ca.crt')
ca_key_path = os.path.join(PROJ_DIR, 'ca.key')

print(f"Project directory: {PROJ_DIR}")

# 1. Verify we have the Root CA cert and private key
if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
    print("Root CA not found in project directory. Creating self-signed Root CA...")
    from mschf.gen_cert import generate_selfsigned_cert
    host_name = socket.gethostname()
    ca_pem, ca_key_pem = generate_selfsigned_cert(host_name)
    with open(ca_cert_path, 'wb') as f:
        f.write(ca_pem)
    with open(ca_key_path, 'wb') as f:
        f.write(ca_key_pem)

with open(ca_cert_path, 'rb') as f:
    ca_cert_pem = f.read()
with open(ca_key_path, 'rb') as f:
    ca_key_pem = f.read()

# Helper to sign payloads against the container's current chain head. Must be
# called immediately before executing the query (the head moves on every
# signed transaction, including reads).
def chained_signature(db, query, params, pem_key_bytes):
    next_seq, prev_hash = db.get_chain_head()
    payload_bytes = canonical_payload(query, params, next_seq, prev_hash)
    private_key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())
    return private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())

# 2. Generate the identities this container recognizes.
# The admin identity is generated IN MEMORY only (used to sign the seed data below)
# and is deliberately NOT written to disk, so it never clobbers the GUI's own
# passphrase-protected admin.crt/admin.key. The container still grants admin to
# cert:CN=admin, so logging into the app as 'admin' administers this container.
# support / unregistered ARE written as GUI test logins, passphrase-encrypted
# (default 'changeit', overridable via MSCHF_ADMIN_PASSPHRASE) to match the app.
DEMO_PASSPHRASE = os.environ.get('MSCHF_ADMIN_PASSPHRASE', 'changeit')

user_certs = {}
user_keys = {}

print("Generating in-memory admin certificate for CN=admin (not written to disk)...")
user_certs['admin'], user_keys['admin'] = generate_user_cert('admin', ca_cert_pem, ca_key_pem)

for cn in ('support', 'unregistered'):
    print(f"Generating signed user certificate for CN={cn} (passphrase-protected)...")
    cert_pem, key_pem = generate_user_cert(cn, ca_cert_pem, ca_key_pem, passphrase=DEMO_PASSPHRASE)
    with open(os.path.join(PROJ_DIR, f'{cn}.crt'), 'wb') as f:
        f.write(cert_pem)
    with open(os.path.join(PROJ_DIR, f'{cn}.key'), 'wb') as f:
        f.write(key_pem)
    user_certs[cn] = cert_pem
    user_keys[cn] = key_pem

# 3. Create a clean test MSF container
db_path = os.path.join(PROJ_DIR, 'test_microapp.msf')
if os.path.exists(db_path):
    try:
        os.remove(db_path)
    except Exception as e:
        print(f"Warning: Could not delete existing {db_path}: {e}")

db = MSFStorage(db_path)

# Provision Custom Tickets schema (including customer_ssn for field-level test)
db.conn.execute("CREATE TABLE IF NOT EXISTS custom_tickets (id INTEGER PRIMARY KEY, title TEXT, customer_ssn TEXT, status TEXT)")
# Provision Confidential Billing schema (strictly secret object)
db.conn.execute("CREATE TABLE IF NOT EXISTS confidential_billing (id INTEGER PRIMARY KEY, client TEXT, amount REAL)")
db.conn.commit()

# Seed Confidential Billing Logs signed by Admin
signature = chained_signature(db, "INSERT OR REPLACE INTO confidential_billing (id, client, amount) VALUES (?, ?, ?)", [1, 'Mischief Dev LLC', 12500.00], user_keys['admin'])
# First write on a fresh container: explicitly claim admin (opt-in bootstrap).
db.bootstrap_admin("INSERT OR REPLACE INTO confidential_billing (id, client, amount) VALUES (?, ?, ?)", [1, 'Mischief Dev LLC', 12500.00], signature, user_certs['admin'])

# Seed support ticket with SSN signed by Admin
signature = chained_signature(db, "INSERT OR REPLACE INTO custom_tickets (id, title, customer_ssn, status) VALUES (?, ?, ?, ?)", [1, 'System Reset Needed', '999-12-3456', 'open'], user_keys['admin'])
db.execute_signed("INSERT OR REPLACE INTO custom_tickets (id, title, customer_ssn, status) VALUES (?, ?, ?, ?)", [1, 'System Reset Needed', '999-12-3456', 'open'], signature, user_certs['admin'])


# 4. Define the bespoke interactive Micro-App with real view switching, object & field-level filtering
def my_micro_app(toga, host_api):
    # Retrieve current user information from the Host
    cert_pem = ""
    cn = "Unknown User"
    try:
        user_info = host_api.get_current_user()
        cn = user_info.get("common_name", "Unknown User")
        cert_pem = user_info.get("certificate_pem", "")
    except Exception:
        pass

    # Gateway Perimeter View-Level Check
    has_admin_panel = False
    has_customer_dashboard = False
    if cert_pem:
        has_admin_panel = host_api.has_view_permission('admin_panel', cert_pem)
        has_customer_dashboard = host_api.has_view_permission('customer_dashboard', cert_pem)

    # 1. Access Denied / Lockout Screen
    if not has_admin_panel and not has_customer_dashboard:
        denied_box = toga.Box(style=toga.style.Pack(direction='column', padding=20, alignment='center'))
        denied_box.add(toga.Label("🚨 ACCESS DENIED", style=toga.style.Pack(font_size=24, font_weight='bold', color='red', margin=10)))
        denied_box.add(toga.Label(f"Active Identity: cert:CN={cn}", style=toga.style.Pack(font_weight='bold', margin=5)))
        denied_box.add(toga.Label("This identity does not have database-level permissions ('No Access' active).", style=toga.style.Pack(margin=5)))
        denied_box.add(toga.Label("The micro-app interface has been completely blocked for security.", style=toga.style.Pack(margin=5)))
        return denied_box

    # --- Build Customer Dashboard Screen ---
    customer_dashboard_box = toga.Box(style=toga.style.Pack(direction='column', padding=15))
    customer_dashboard_box.add(toga.Label("📞 Support Ticket Queue", style=toga.style.Pack(font_size=18, font_weight='bold', margin_bottom=5)))
    customer_dashboard_box.add(toga.Label(f"Logged-in CN: {cn} | Active Role: {'admin' if has_admin_panel else 'support'}", style=toga.style.Pack(font_style='italic', margin_bottom=10)))

    # FIELD-LEVEL SSN ACCESS CHECKS
    ssn_allowed = False
    try:
        ssn_allowed = host_api.has_field_permission('custom_tickets', 'customer_ssn', 'read', cert_pem)
    except Exception:
        pass

    # OBJECT-LEVEL TEST 1: General Support Tickets Table (Read Allowed for both, Write Only for admin)
    customer_dashboard_box.add(toga.Label("--- Tickets Table (Object & Field-Level Controls) ---", style=toga.style.Pack(font_weight='bold', margin_top=5)))
    ticket_input = toga.TextInput(placeholder="Enter new support ticket title", style=toga.style.Pack(margin=2))
    ssn_input = toga.TextInput(placeholder="Enter customer SSN (e.g. 123-45-6789)", style=toga.style.Pack(margin=2))
    status_label = toga.Label("Status: Ready.", style=toga.style.Pack(margin=5, font_style='italic'))
    tickets_label = toga.Label("Tickets: Click Refresh to load database.", style=toga.style.Pack(margin=5))

    def refresh_tickets(widget=None):
        try:
            # Query custom_tickets including customer_ssn column
            cursor = host_api.execute_signed_query("SELECT id, title, customer_ssn, status FROM custom_tickets")
            rows = cursor.fetchall()
            
            lines = []
            for r in rows:
                # Apply live field-level cryptographic redaction!
                display_ssn = r[2] if ssn_allowed else "•-•-• [REDACTED BY FIELD-LEVEL POLICY]"
                lines.append(f"🎫 Ticket #{r[0]} - {r[1]} | SSN: {display_ssn} [{r[3]}]")
                
            tickets_label.text = "\n".join(lines) if lines else "No tickets in database"
        except Exception as e:
            tickets_label.text = f"Tickets: Query Blocked ({e})"

    def add_ticket(widget):
        title = ticket_input.value
        ssn_val = ssn_input.value
        if not title:
            status_label.text = "Status: Please enter a ticket title."
            return
        try:
            # Check field-level write permission before allowing insert (implicit or explicit)
            host_api.execute_signed_query(
                "INSERT INTO custom_tickets (title, customer_ssn, status) VALUES (?, ?, ?)",
                [title, ssn_val if ssn_val else '000-00-0000', 'open']
            )
            status_label.text = f"Status: Ticket added! (Signed by {cn})"
            ticket_input.value = ""
            ssn_input.value = ""
            refresh_tickets()
        except Exception as e:
            status_label.text = f"Status: Blocked by RBAC! {e}"

    btn_add = toga.Button("Create Ticket (Signed DB Insert)", on_press=add_ticket, style=toga.style.Pack(margin=5))
    btn_refresh = toga.Button("Refresh Ticket List", on_press=refresh_tickets, style=toga.style.Pack(margin=5))

    customer_dashboard_box.add(ticket_input)
    customer_dashboard_box.add(ssn_input)
    customer_dashboard_box.add(btn_add)
    customer_dashboard_box.add(btn_refresh)
    customer_dashboard_box.add(status_label)
    customer_dashboard_box.add(tickets_label)

    # OBJECT-LEVEL TEST 2: Secret Billing Table (Denied completely for support role)
    customer_dashboard_box.add(toga.Label("--- Confidential Billing Table (Object-Level support: blocked) ---", style=toga.style.Pack(font_weight='bold', margin_top=15)))
    billing_label = toga.Label("Billing Records: Click Refresh Billing to load.", style=toga.style.Pack(margin=5))

    def refresh_billing(widget=None):
        try:
            cursor = host_api.execute_signed_query("SELECT client, amount FROM confidential_billing")
            rows = cursor.fetchall()
            billing_label.text = f"Billing Records: " + ", ".join([f"{r[0]} (${r[1]})" for r in rows]) if rows else "No records found"
        except Exception as e:
            billing_label.text = f"Billing Records: ACCESS DENIED ✖\n({e})"

    btn_refresh_billing = toga.Button("Query Billing Logs (Signed SELECT)", on_press=refresh_billing, style=toga.style.Pack(margin=5))
    
    customer_dashboard_box.add(btn_refresh_billing)
    customer_dashboard_box.add(billing_label)

    # Auto-refresh on startup
    try:
        refresh_tickets()
        refresh_billing()
    except Exception:
        pass

    # 2. Build the Admin Control Panel Screen (strictly if admin has view permissions)
    if has_admin_panel:
        admin_panel_box = toga.Box(style=toga.style.Pack(direction='column', padding=15))
        admin_panel_box.add(toga.Label("🛡️ Cryptographic Policy & RBAC Console", style=toga.style.Pack(font_size=18, font_weight='bold', margin_bottom=5)))
        admin_panel_box.add(toga.Label("Only Administrative identities can write to system configuration tables.", style=toga.style.Pack(font_style='italic', margin_bottom=10)))

        rules_label = toga.Label("Rules: Click load to query", style=toga.style.Pack(margin=5))
        roles_label = toga.Label("Roles: Click load to query", style=toga.style.Pack(margin=5))

        def refresh_rbac_data(widget=None):
            try:
                # Query rules
                cursor = host_api.execute_signed_query("SELECT level, target, role, permission FROM rbac_rules")
                rules = cursor.fetchall()
                rules_text = "\n".join([f"  • [{r[0]}] {r[1]} -> role:{r[2]} ({r[3]})" for r in rules])
                rules_label.text = f"Cryptographic Security Rules:\n{rules_text if rules_text else '  (None)'}"

                # Query roles
                cursor2 = host_api.execute_signed_query("SELECT identity, role FROM user_roles")
                roles = cursor2.fetchall()
                roles_text = "\n".join([f"  • {r[0]} -> {r[1]}" for r in roles])
                roles_label.text = f"Registered User Roles:\n{roles_text if roles_text else '  (None)'}"
            except Exception as e:
                rules_label.text = f"Security Policies: Blocked ({e})"
                roles_label.text = ""

        btn_refresh_rbac = toga.Button("Query Security Policies (Live DB)", on_press=refresh_rbac_data, style=toga.style.Pack(margin=5))

        # Add Rule Form
        admin_panel_box.add(toga.Label("--- Live RBAC Rules Provisioning ---", style=toga.style.Pack(font_weight='bold', margin_top=10)))
        rule_level = toga.TextInput(placeholder="Level (view / database / object / field)", style=toga.style.Pack(margin=2))
        rule_target = toga.TextInput(placeholder="Target (e.g. * or custom_tickets.customer_ssn)", style=toga.style.Pack(margin=2))
        rule_role = toga.TextInput(placeholder="Role (e.g. support)", style=toga.style.Pack(margin=2))
        rule_perm = toga.TextInput(placeholder="Permission (e.g. read / write / *)", style=toga.style.Pack(margin=2))
        rule_status = toga.Label("Rule Status: Ready.", style=toga.style.Pack(margin=2, font_style='italic'))

        def add_rule(widget):
            lvl, trg, rle, prm = rule_level.value, rule_target.value, rule_role.value, rule_perm.value
            if not (lvl and trg and rle and prm):
                rule_status.text = "Error: Fill out all rule fields."
                return
            try:
                # Signs & inserts a live RBAC rule to rbac_rules table
                host_api.execute_signed_query(
                    "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)",
                    [lvl, trg, rle, prm]
                )
                rule_status.text = f"Success: Signed rule inserted live for role '{rle}'!"
                refresh_rbac_data()
            except Exception as e:
                rule_status.text = f"Failed to write rule: {e}"

        btn_add_rule = toga.Button("Commit & Sign Rule", on_press=add_rule, style=toga.style.Pack(margin=5))

        # Assign Role Form
        admin_panel_box.add(toga.Label("--- Live User Promotion & Assignment ---", style=toga.style.Pack(font_weight='bold', margin_top=10)))
        user_cn_input = toga.TextInput(placeholder="User CN (e.g. unregistered)", style=toga.style.Pack(margin=2))
        user_role_input = toga.TextInput(placeholder="Role (e.g. support or admin)", style=toga.style.Pack(margin=2))
        role_status = toga.Label("Role Status: Ready.", style=toga.style.Pack(margin=2, font_style='italic'))

        def assign_role(widget):
            cn_val, role_val = user_cn_input.value, user_role_input.value
            if not (cn_val and role_val):
                role_status.text = "Error: Fill out both fields."
                return
            identity_str = f"cert:CN={cn_val}"
            try:
                # Signs & updates the user's role assignment live
                host_api.execute_signed_query(
                    "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)",
                    [identity_str, role_val]
                )
                role_status.text = f"Success: Promoted CN={cn_val} to role '{role_val}' live!"
                refresh_rbac_data()
            except Exception as e:
                role_status.text = f"Failed to assign role: {e}"

        btn_assign_role = toga.Button("Commit & Sign Role", on_press=assign_role, style=toga.style.Pack(margin=5))

        admin_panel_box.add(btn_refresh_rbac)
        admin_panel_box.add(rules_label)
        admin_panel_box.add(roles_label)
        admin_panel_box.add(rule_level)
        admin_panel_box.add(rule_target)
        admin_panel_box.add(rule_role)
        admin_panel_box.add(rule_perm)
        admin_panel_box.add(btn_add_rule)
        admin_panel_box.add(rule_status)
        admin_panel_box.add(user_cn_input)
        admin_panel_box.add(user_role_input)
        admin_panel_box.add(btn_assign_role)
        admin_panel_box.add(role_status)

        # Pre-refresh data for Admin
        try:
            refresh_rbac_data()
        except Exception:
            pass

        # Wrap each pane in a ScrollContainer so long forms scroll instead of
        # clipping at the bottom of the window.
        option_container = toga.OptionContainer(
            content=[
                ("Customer Dashboard", toga.ScrollContainer(horizontal=False, content=customer_dashboard_box, style=toga.style.Pack(flex=1))),
                ("Admin Control Panel", toga.ScrollContainer(horizontal=False, content=admin_panel_box, style=toga.style.Pack(flex=1)))
            ],
            style=toga.style.Pack(flex=1)
        )
        return option_container

    # Return only the Customer Dashboard (scrollable) for support users
    return toga.ScrollContainer(horizontal=False, content=customer_dashboard_box, style=toga.style.Pack(flex=1))

# 5. Sign and store the micro-app code using Admin credentials
print("Signing and storing micro-app code using admin certificate...")
id_val = 'main_app'
pickled_code = dill.dumps(my_micro_app)
signature = chained_signature(db, "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)", [id_val, pickled_code], user_keys['admin'])

db.store_code(id_val, my_micro_app, signature, user_certs['admin'])

# 6. Set manifest entry point signed by Admin
print("Setting manifest entry point...")
manifest_key = 'entry_point'
manifest_val = 'main_app'
signature = chained_signature(db, "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)", [manifest_key, manifest_val], user_keys['admin'])

db.set_manifest_item(manifest_key, manifest_val, signature, user_certs['admin'])

# 7. Provision RBAC rules in the container database
print("Provisioning cryptographic RBAC roles inside the database...")

# Get cryptographic identity strings for each user certificate
admin_id = db._get_identity(user_certs['admin'])
support_id = db._get_identity(user_certs['support'])

# Assign Role: admin to Admin identity
signature = chained_signature(db, "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)", [admin_id, 'admin'], user_keys['admin'])
db.assign_user_role(admin_id, 'admin', signature, user_certs['admin'])

# Assign Role: support to Support identity
signature = chained_signature(db, "INSERT OR REPLACE INTO user_roles (identity, role) VALUES (?, ?)", [support_id, 'support'], user_keys['admin'])
db.assign_user_role(support_id, 'support', signature, user_certs['admin'])

# Allow support role view-level access to the customer dashboard
signature = chained_signature(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['view', 'customer_dashboard', 'support', 'read'], user_keys['admin'])
db.add_rbac_rule('view', 'customer_dashboard', 'support', 'read', signature, user_certs['admin'])

# Allow support role read-only database-level access
signature = chained_signature(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['database', '*', 'support', 'read'], user_keys['admin'])
db.add_rbac_rule('database', '*', 'support', 'read', signature, user_certs['admin'])

# Allow support role read-only table object-level access on custom_tickets
signature = chained_signature(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['object', 'custom_tickets', 'support', 'read'], user_keys['admin'])
db.add_rbac_rule('object', 'custom_tickets', 'support', 'read', signature, user_certs['admin'])

# Allow admin role view-level access to the admin_panel
signature = chained_signature(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['view', 'admin_panel', 'admin', 'read'], user_keys['admin'])
db.add_rbac_rule('view', 'admin_panel', 'admin', 'read', signature, user_certs['admin'])

# EXPLICITLY ALLOW ADMIN FULL FIELD-LEVEL ACCESS TO custom_tickets.customer_ssn
signature = chained_signature(db, "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)", ['field', 'custom_tickets.customer_ssn', 'admin', 'read'], user_keys['admin'])
db.add_rbac_rule('field', 'custom_tickets.customer_ssn', 'admin', 'read', signature, user_certs['admin'])

db.close()
print(f"\nSuccessfully generated dual-tier container at {db_path}!")
print("Identities:")
print("  - CN=admin (Role=admin -> BOTH DASHBOARD & ADMIN PANEL) — in-memory only; log in with the app's own admin.crt")
print(f"  - support.crt (CN=support, Role=support -> CUSTOMER DASHBOARD ONLY; passphrase '{DEMO_PASSPHRASE}')")
print(f"  - unregistered.crt (CN=unregistered, No Role -> TOTAL LOCKOUT; passphrase '{DEMO_PASSPHRASE}')")
