# Mischief: Cryptographically Secured Micro-App Platform

Mischief (`mschf`) is a modern micro-app platform powered by **BeeWare Briefcase**, **Toga**, and **SQLite**. It allows single-file applications (stored as `.msf` files) to run natively on host environments. 

The Mischief host application functions as a Workspace Manager, dynamically listing local `.msf` bundles, verifying their cryptographic signatures, and executing sandboxed Python code to render native UIs.

---

## 🏛️ Core Architecture

The Mischief platform transitions away from bloated web-view or heavy runtime wrappers, utilizing a compact, local-first database container model:

```
[ .msf Micro-App Container (SQLite) ]
  ├── manifest       --> App metadata & entry-point declaration
  ├── source_code    --> Signed, pickled Python callables (via dill)
  ├── rbac_rules     --> Granular multi-level authorization configurations
  ├── user_roles     --> Cryptographic identities mapped to roles
  └── transactions   --> Ledger of cryptographically signed write transactions
```

### Key Capabilities

*   **Workspace Manager:** A native desktop interface that automatically detects and launches local `.msf` apps.
*   **Signed Transactions:** Every write transaction (schema modifications, data insertions, and logic deployments) is signed using PKCS#1 v1.5 with SHA-256 and verified against an X.509 certificate.
*   **Multi-Level RBAC:** Secures access across four distinct scopes:
    1.  *Database Level:* Overall read/write execution permission.
    2.  *Object Level:* Specific table CRUD constraints.
    3.  *View Level:* Permission-based native GUI rendering.
    4.  *Field Level:* Column-level selective data redaction.
*   **Execution Sandbox:** Runs logic through a secure, restricted `HostAPI` bridge, limiting micro-app access to local directories, configs, and approved identities.

---

## 🚀 Getting Started

### 1. Installation & Setup
Ensure you have Python 3.10+ installed. Install the platform dependencies listed in `pyproject.toml` (managed by Briefcase):

```bash
# Clone the repository
git clone https://github.com/pshouse/mischief.git
cd mischief

# Install Briefcase
pip install briefcase
```

### 2. Booting the Workspace Manager
Run the platform in development mode:

```bash
briefcase dev
```
This command initializes the main window listing local `.msf` apps, generating a local Root Certificate Authority (`ca.crt`/`ca.key`) and an issued Admin user identity certificate (`admin.crt`/`admin.key`) if not present.

---

## 🧪 Verification & Development Sandbox

Mischief comes with pre-configured automated integration tests to verify the platform engine, serialization, and cryptographic handshakes:

### Run the End-to-End Micro-App Flow
This script creates a test `.msf` file, signs and deploys a custom Toga widget function, and boots it via the execution sandbox:
```bash
python verify_microapp.py
```

### Run the Cryptographic RBAC Verification
This script simulates multiple actors (`admin_user`, `support_staff`, and `malicious_hacker`), verifying that unauthorized queries are trapped and rejected, while authorized role-based selections bypass correctly:
```bash
python test_rbac.py
```

---

## 📖 Platform Guides

To configure or build on top of the platform, refer to the following comprehensive guides in the `docs/` folder:

*   **[Administrator Guide](docs/ADMIN_GUIDE.md):** Learn how to initialize MSF files, generate administrative keys, bootstrap root admin privileges, manage role assignments, and construct signed database transactions.
*   **[Developer & User Guide](docs/USER_GUIDE.md):** Learn how to structure micro-app entry points, use native Toga components, access the `HostAPI` bridge, check fine-grained runtime permissions, and safely inspect environment configurations.

---

## 📄 License

Mischief is distributed under the MIT License. See `LICENSE` for details.
