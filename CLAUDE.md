# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Mischief (`mschf`) is a BeeWare/Briefcase desktop app (Toga UI) that acts as a "Workspace Manager" for micro-apps. A micro-app is a single `.msf` file — a SQLite database containing app metadata, dill-pickled Python UI code, RBAC rules, and a ledger of cryptographically signed transactions. The host loads an `.msf`, verifies signatures against a local X.509 CA, enforces RBAC, and executes the app's code in a sandbox to render native Toga widgets.

## Commands

```bash
pip install briefcase        # one-time setup; app deps are declared in pyproject.toml [tool.briefcase.app.mschf]
briefcase dev                # run the Workspace Manager in dev mode

python test_microapp.py      # generates test_microapp.msf (signed code deployment + RBAC seed data)
python verify_microapp.py    # end-to-end: loads test_microapp.msf and runs it through the sandbox
python test_rbac.py          # multi-actor RBAC/signature verification (admin, support_staff, malicious_hacker)
```

There is no pytest/lint setup — the three test scripts are standalone integration scripts run directly with `python`. They insert `src/` into `sys.path` themselves and read/write artifacts (`.msf` files, certs) in the project root. `verify_microapp.py` depends on `test_microapp.py` having produced `test_microapp.msf` (it auto-runs it if missing).

Dependencies live in `pyproject.toml` under `[tool.briefcase.app.mschf].requires` (toga, cryptography, pytz, toml, dill) — there is no requirements.txt. Briefcase's dev venv is in `.briefcase/` (generated, don't touch).

## Architecture

Code lives in `src/mschf/` (src layout, managed by Briefcase).

- **`app.py`** — the `Mschf` Toga App (Workspace Manager). On startup it: generates a Root CA (`ca.crt`/`ca.key`) and an admin identity (`admin.crt`/`admin.key`) in the project root if missing; loads the active user identity from `settings.toml` (`user_id`) and verifies it is CA-signed (invalid identity → "No Access", open buttons disabled); loads plugins; scans cwd + project root for `*.msf` files. Switching identity via `set_active_identity()` live-redraws all open documents.
- **`msf.py`** — `MSF(toga.Document)`, the document class for `.msf` files. `redraw()` checks database-level read permission for the active identity, executes the manifest's `entry_point` code via the sandbox, and wraps the returned widget with a signature-status banner ("CRYPTO ACTIVE: VERIFIED" vs tampered). Falls back to an "About" view rendered from the manifest when no entry point exists.
- **`storage.py`** — `MSFStorage`, the SQLite container handler. Initializes the system tables (`manifest`, `source_code`, `transactions`, `rbac_rules`, `user_roles`). The heart is `execute_signed(query, params, signature, pub_key_pem)`: verifies the payload signature (RSA PKCS#1 v1.5 / SHA-256) → verifies the cert chains to the **host's** trusted Root CA (`self.ca_cert_path`, defaulting to `DEFAULT_CA_CERT_PATH` = the host root's `ca.crt`, never one shipped beside the `.msf`; fails closed if absent) → regex-parses the SQL to derive (operation, table) → enforces database-level then object-level RBAC (system tables are admin-only for writes) → executes and appends to the `transactions` audit log. First-writer-becomes-`admin` bootstrapping is **opt-in**: it only fires when `allow_bootstrap=True`, reachable solely through the deliberate `bootstrap_admin()` authoring method — the sandbox/running path never sets it, so opening or running a `.msf` can't make you its admin. Code blobs are stored/loaded with `dill`; `get_code_signature_status()` re-verifies a blob against its signing transaction, detects tampering, **and** requires the signer to chain to the trusted CA before reporting `verified` (a valid signature from an untrusted signer is not "VERIFIED").
- **`identity.py`** — `Identity`, the single source of truth for the active user. `Identity.load(cert_path, ca_cert_path)` reads a cert, extracts the CN, verifies it chains to the Root CA, and locates the sibling `<stem>.key`. It bundles `cn`, `cert_path`, `key_path`, `cert_pem`, and `is_valid`. `app.py` holds one on `self.active_identity`; nothing downstream reconstructs a key filename from a CN.
- **`sandbox.py`** — `execute_micro_app(code_func, ...)` calls the unpickled callable as `code_func(toga, host_api)` and expects a Toga widget back. `HostAPI` is the only bridge exposed to micro-apps: workspace-scoped file reads, RBAC permission checks (view/field/database level), current-user info, and `execute_signed_query()` which signs on behalf of the active user using the `key_path` carried by the active `Identity` (passed in via `msf.py`).
- **`plugins/`** — `PluginManager` loads built-ins listed in `load_all()` (currently only `AuthPlugin`). Plugins subclass `plugins/base.py:BasePlugin` and may implement `extend_ui(app, outer_box)` to inject panels into the main window. The auth plugin (`plugins/auth/`) has password/OAuth/passkey providers; on successful auth it provisions an ephemeral CA-signed X.509 cert for the identity and hot-swaps it as the active identity.

### Signing protocol (must stay consistent)

The signed payload is `json.dumps({"query": ..., "params": ...}, sort_keys=True).encode('utf-8')`, with bytes params base64-encoded first. This exact canonicalization is duplicated in `storage.py` (`execute_signed`, `get_code_signature_status`), `sandbox.py` (`HostAPI.execute_signed_query`), and the test scripts — a change in one place breaks verification everywhere, including previously signed `.msf` files.

RBAC identities are derived from the cert/key, not usernames: `cert:CN=<common_name>` for certs, `key:<sha256-prefix>` for bare public keys (see `MSFStorage._get_identity`). RBAC has four levels: `database`, `object`, `view`, `field` (field targets support `table.field`, `table.*`, `*` specificity).

## Notes

- Windows is the primary target (WinForms-specific tweaks in `app.py` guarded by try/except); keep changes platform-tolerant.
- Runtime artifacts in the project root are generated, not source: `ca.crt`/`ca.key`, `admin.crt`/`admin.key`, provisioned `*.crt`/`*.key`, `*.msf` files, `settings.toml` (auto-created), `logs/`.
- `docs/ADMIN_GUIDE.md` (key generation, role assignment, signed transactions) and `docs/USER_GUIDE.md` (micro-app entry points, HostAPI usage) document the platform APIs — update them when changing those surfaces.
