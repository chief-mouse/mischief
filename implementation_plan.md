# Redesign Mischief as a Micro-App Platform (SQLite + BeeWare)

Redesign the `mischief` application as a modern BeeWare project managed by Briefcase. `mischief` will serve as a **micro-app platform**, where `.msf` files are bespoke, single-file applications powered by SQLite. 

The host Toga application will load these SQLite databases, verifying signatures, enforcing access control, and executing sandboxed Python code to render native Toga UIs.

## User Review Required

> [!IMPORTANT]
> Please review the finalized architecture below. Once approved, I will begin execution.

## Proposed Architecture & Changes

---

### Project Structure & Briefcase Migration

#### [NEW] [pyproject.toml](file:///c:/Users/admin/workspace/working-title/pyproject.toml)
Create the Briefcase configuration declaring dependencies (`toga`, `cryptography`, `pytz`, `toml`, `dill` for pickling).

#### [DELETE] [setup.py](file:///c:/Users/admin/workspace/working-title/setup.py) & [requirements.txt](file:///c:/Users/admin/workspace/working-title/requirements.txt)
Remove obsolete packaging scripts.

---

### Core Database Schema (MSF System Tables)

Every MSF file will be initialized with a core set of system tables to support the micro-app platform. 

#### 1. Manifest & About
A `manifest` table to store app metadata, versioning, and the `about` view content.

#### 2. Code Storage (`source_code`)
A table storing "pickled safe/sandboxed Python" logic. The host will load and execute this code within a restricted environment.

#### 3. Security & Transactions (`transactions` & `signatures`)
All database transactions (data modification and schema changes like creating objects/tables) will be signed using the user's cryptographic identity (`ca.crt`/`ca.key`). Signatures will be verified before applying changes.

#### 4. RBAC (`rbac_rules`)
A comprehensive set of tables to define and enforce Role-Based Access Control at four levels:
- **Database Level:** Overall access to the MSF file.
- **Object Level:** Access to specific dynamically created tables.
- **View Level:** Access to specific UI views defined by the micro-app.
- **Field Level:** Access to specific columns within dynamically created tables.

---

### Micro-App Platform Engine

#### [NEW] [storage.py](file:///c:/Users/admin/workspace/working-title/src/mschf/storage.py)
Implement the SQLite database handler to read the micro-app bundle:
- Initialize the core system tables (`manifest`, `source_code`, `transactions`, `rbac_rules`).
- Provide an API for the micro-app to create custom objects (tables) with support for SQLite generated columns (formula-based fields).
- Enforce signature verification on transactions.

#### [NEW] [sandbox.py](file:///c:/Users/admin/workspace/working-title/src/mschf/sandbox.py)
A module responsible for safely unpickling and executing the micro-app's Python code. It will provide a limited `Host API` bridge, restricting access to local MSF files, config files, and ID files.

#### [MODIFY] [msf.py](file:///c:/Users/admin/workspace/working-title/src/mschf/msf.py) 
- Adapt the Toga document class `MSF` to load the SQLite file and parse the manifest.
- Extract the entry-point code from the `source_code` table, pass it to the sandbox, and expect it to return native Toga widgets.
- Mount the returned Toga widgets into the document window (replacing the previous `WebView` approach).
- Handle the rendering of the default "About" page/view required by the manifest.

#### [MODIFY] [app.py](file:///c:/Users/admin/workspace/working-title/src/mschf/app.py) 
- Clean up `durus` and `twisted` imports.
- Re-configure the main window to act as the Workspace Manager, listing available local MSF micro-apps.

---

### Source Relocation
Move all other core files to the `src/` layout:
- `src/mschf/__init__.py`
- `src/mschf/__main__.py`
- `src/mschf/gen_cert.py`

## Verification Plan

### Automated Tests
- Run `briefcase dev` to boot the application.
- Create a test MSF file with a simple pickled Toga button to verify the sandbox and UI rendering loop.
- Verify that a transaction without a valid signature is rejected.

### Manual Verification
- Launch the application, create a new MSF file, and verify the system tables are created correctly. 
- Open the MSF file and ensure the "About" view renders natively.
