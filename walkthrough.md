# Walkthrough: Mischief Micro-App Platform Redesign

## What Changed

### 1. Project Structure → BeeWare Briefcase Layout

| Before | After |
|--------|-------|
| `mschf/` (root-level package) | `src/mschf/` (standard src layout) |
| `setup.py` + `requirements.txt` | `pyproject.toml` (Briefcase config) |
| Durus + Twisted dependencies | `toga`, `cryptography`, `dill`, `pytz`, `toml` |

### 2. New Files Created

#### [pyproject.toml](file:///c:/Users/admin/workspace/working-title/pyproject.toml)
Briefcase project configuration declaring app metadata, source paths, and dependencies.

#### [storage.py](file:///c:/Users/admin/workspace/working-title/src/mschf/storage.py)
SQLite storage engine (`MSFStorage`) that initializes four system tables:
- **`manifest`** — key/value app metadata (name, version, entry point)
- **`source_code`** — pickled Python callables (via `dill`)
- **`transactions`** — signed audit log of all write operations
- **`rbac_rules`** — role-based access control at database/object/view/field levels

All write operations require a valid cryptographic signature verified against a PEM certificate.

#### [sandbox.py](file:///c:/Users/admin/workspace/working-title/src/mschf/sandbox.py)
Sandboxed execution engine with a `HostAPI` bridge that limits micro-app access to:
- Local `.msf` files
- Config files (e.g. `settings.toml`)
- Identity files (e.g. `ca.crt`)

### 3. Modified Files

#### [app.py](file:///c:/Users/admin/workspace/working-title/src/mschf/app.py)
- Removed all `durus` and `twisted` imports and logic
- Replaced Twisted TCP server/client with a simple Toga Workspace Manager
- Main window lists local `.msf` files with Open and Refresh buttons

#### [msf.py](file:///c:/Users/admin/workspace/working-title/src/mschf/msf.py)
- Replaced `durus.Connection`/`FileStorage` with `MSFStorage`
- Loads micro-app entry point from `source_code` table, executes via sandbox
- Falls back to a native "About" view when no entry point is defined
- Properly closes SQLite connection on window close

### 4. Deleted Files
- `setup.py` — replaced by `pyproject.toml`
- `requirements.txt` — dependencies now in `pyproject.toml`

## What Was Tested

1. **MSF creation**: `test_microapp.py` generates a fresh SQLite `.msf` file with all system tables
2. **Signed transactions**: Pickled code and manifest entries are stored with PKCS1v15/SHA256 signatures verified against a self-signed X.509 certificate
3. **Code retrieval**: Verified that `dill.loads()` correctly deserializes the stored callable from the database
4. **Schema integrity**: All four system tables (`manifest`, `source_code`, `transactions`, `rbac_rules`) created successfully

## Validation Results

```
Generating certificates...
Signing and storing micro-app code...
Setting manifest entry point...
Successfully created test_microapp.msf with signed micro-app code!

Manifest entry_point: main_app
Code loaded: True
All checks passed!
```
