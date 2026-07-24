# Mischief Micro-App Platform: Developer & User Guide

Welcome to the **Mischief Micro-App Platform**. This guide covers how to write, build, test, and run bespoke `.msf` single-file micro-apps using the Toga native UI toolkit and the Mischief Host API.

---

## 1. What is a Mischief Micro-App?

A `.msf` micro-app is a self-contained application bundle stored entirely inside a single SQLite database file. It contains:
1. **Metadata:** Defined in the `manifest` table (version, title, description, entry-point).
2. **Logic:** A pickled Python function stored in the `source_code` table.
3. **Data:** Bespoke relational SQLite tables containing custom application records.
4. **Permissions:** Custom RBAC configurations governing which users can read/write data or open specific views.

When opened by the Mischief Toga host application, the host validates database signatures, extracts the logic, and runs it inside a sandboxed execution bridge.

---

## 2. Anatomy of a Micro-App Entry Point

There are two ways to define a micro-app's UI:

- **Declarative (preferred for forms-over-data apps):** store a JSON widget
  tree in the manifest key `ui_spec` (via a signed `set_manifest_item`).
  The host renders it with no pickled code at all — widgets `box`, `label`,
  `table` (SELECT-only signed query binding), `text_input`, `button`
  (parameterized `exec` actions through `execute_signed_query`), and
  `status`. When both `ui_spec` and `entry_point` exist, the declarative
  spec wins, so containers can dual-publish during migration. The security
  banner verifies the `ui_spec` manifest value against its signing ledger
  row. See `docs/declarative-ui-notes.md` for the spec vocabulary.
- **Pickled entry point:** a Python function stored in `source_code` and
  named by the manifest key `entry_point`, described below.

Every pickled micro-app must define an entry-point function. This function must accept exactly two arguments:
1. **`toga`:** The native Python GUI framework.
2. **`host_api`:** The restricted bridge API provided by the host.

The entry point must construct and return a **`toga.Box`** widget containing your application's user interface.

### Minimal Micro-App Template

```python
def my_micro_app(toga, host_api):
    # Create a container box
    box = toga.Box(style=toga.style.Pack(direction='column', margin=20))
    
    # Add native Toga widgets
    title_lbl = toga.Label(
        "Welcome to My Micro-App!", 
        style=toga.style.Pack(font_size=18, font_weight='bold')
    )
    box.add(title_lbl)
    
    # Return the outer box to the host
    return box
```

---

## 3. Working with the Host API

The `host_api` parameter exposes safe host-level functions to your sandboxed micro-app. It allows safe interaction with the filesystem and local environment.

### A. Checking View Permissions (`has_view_permission`)
Before displaying administrative controls or secure dashboards to a user, check their cryptographic view privileges. This prevents rendering forbidden UI components.

```python
def my_micro_app(toga, host_api):
    box = toga.Box(style=toga.style.Pack(direction='column', margin=10))
    
    # Get active user certificate PEM dynamically from current logged-in identity
    user_info = host_api.get_current_user()
    user_cert_pem = user_info.get("certificate_pem", "")
    
    # Query permissions for 'admin_dashboard' view
    if host_api.has_view_permission('admin_dashboard', user_cert_pem):
        admin_btn = toga.Button("Admin Settings", on_press=open_admin_panel)
        box.add(admin_btn)
    else:
        box.add(toga.Label("Access level: Standard User"))
        
    return box
```

```python
user_info = host_api.get_current_user()
user_cert_pem = user_info.get("certificate_pem", "")

# Check if user has permission to read the 'salary' field on the 'employees' table
if host_api.has_field_permission('employees', 'salary', 'read', user_cert_pem):
    display_text = f"Salary: ${salary_val}"
else:
    display_text = "Salary: [REDACTED]"
```

### B. Checking Field-Level Permissions (`has_field_permission`)
When presenting a data-grid or details panel, verify if the user is authorized to read specific table columns.

### C. Checking Current User Identity (`get_current_user`)
You can query the host API to retrieve information about the currently logged-in user on the host platform. This is useful for personalizing the user interface or using their certificate directly for validation.

```python
def my_micro_app(toga, host_api):
    box = toga.Box(style=toga.style.Pack(direction='column', margin=15))
    
    # Get active user info
    user_info = host_api.get_current_user()
    cn = user_info.get("common_name", "Unknown")
    cert_pem = user_info.get("certificate_pem", "")
    
    box.add(toga.Label(f"Welcome back, {cn}!"))
    return box
```

### D. File Operations
You can list local micro-apps and read local configuration files within your project workspace:

*   **`host_api.list_local_msf()`:** Returns a list of all `.msf` files in the current workspace.
*   **`host_api.read_config(filename)`:** Safely reads configuration data (e.g. `settings.toml`) from the local workspace.
*   **`host_api.read_id(filename)`:** Reads identity files (e.g., your cryptographic certificate `ca.crt`).
*   **`host_api.get_current_user()`:** Returns details of the logged-in host identity (keys: `common_name`, `certificate_pem`).

---

## 4. Complete Micro-App Example

Here is a fully functional micro-app that renders a native support desk interface, queries local files, and conditionalizes widgets based on RBAC checks:

```python
def support_desk_app(toga, host_api):
    box = toga.Box(style=toga.style.Pack(direction='column', padding=15))
    
    # Title
    box.add(toga.Label(
        "Mischief Support Desk", 
        style=toga.style.Pack(font_size=20, font_weight='bold', padding_bottom=10)
    ))
    
    # Read system metadata
    try:
        settings_data = host_api.read_config('settings.toml')
        box.add(toga.Label(f"Workspace Settings:\n{settings_data}"))
    except Exception as e:
        box.add(toga.Label("Unable to load settings.toml"))
        
    # Query active user identity
    try:
        user_info = host_api.get_current_user()
        user_cert = user_info.get("certificate_pem", "")
        
        # Check permissions for View and Fields
        can_view_metrics = host_api.has_view_permission('performance_metrics', user_cert)
        can_read_ssn = host_api.has_field_permission('tickets', 'ssn', 'read', user_cert)
        
        box.add(toga.Label(f"Metrics Access Authorized: {can_view_metrics}"))
        box.add(toga.Label(f"SSN Access Authorized: {can_read_ssn}"))
        
        if can_view_metrics:
            metrics_box = toga.Box(style=toga.style.Pack(padding=10))
            metrics_box.add(toga.Label("Total Tickets Solved: 142 | Average Response: 12m"))
            box.add(metrics_box)
            
    except Exception as e:
        box.add(toga.Label(f"Permission Check Failure: {e}"))
        
    return box
```

---

## 5. Security & Development Guidelines

1. **Defensive UI Rendering:** Always wrap RBAC-governed UI controls inside `has_view_permission` checks.
2. **Never Hardcode Secrets:** Do not hardcode database structures, private keys, or credentials inside the pickled source code block. Use `host_api.read_config` or let user-supplied configurations drive operations.
3. **Graceful Exception Handling:** Because your micro-app runs inside a host application, uncaught exceptions will render a fallback error panel to the user rather than crashing the entire Mischief platform. Always wrap file operations or system-level queries in `try-except` blocks.
