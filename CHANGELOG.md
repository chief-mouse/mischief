# Changelog

All notable changes to Mischief (`mschf`) are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/). Pre-1.0: a
MINOR bump means new features (and possibly breaking changes), a PATCH bump
means fixes only. The version lives in `pyproject.toml` (`[tool.briefcase]
version`) and `src/mschf/__init__.py` (`__version__`) — bump both, then add an
entry here.

## [Unreleased]

## [0.4.2] - 2026-07-18

### Added

- Runtime log with liveness heartbeat: a rotating `mschf-runtime.log` in the
  user data dir records a heartbeat every 30s (open-doc count, active identity,
  and GDI/USER handle counts). If the app freezes — e.g. the WinForms/pythonnet
  stack wedging across a screen lock — the last heartbeat pins when it happened
  and whether the poll loop was still ticking and resources were climbing.

### Fixed

- File menu no longer offers commands that don't fit the `.msf` model: New
  (opened a meaningless empty document window), Save, Save As, and Save All
  (no-ops — containers are never "saved"; every change is a signed transaction
  committed immediately) are removed. Open and Exit remain.
- Starter-app intro copy referred to a "'by' column"; the notes list shows the
  signer on an attribution line beneath each note, and the text now says so.

## [0.4.1] - 2026-07-18

### Fixed

- Progressive disclosure in the Workspace Manager: the window now shows only
  what the current state needs. Logged out — onboarding banner + Auth Gateway
  (no disabled workspace buttons, no empty table); signed in with an empty
  workspace — banner with starter creation + workspace; signed in with apps —
  just the workspace. Widgets are composed in/out of the layout rather than
  css-hidden (Pack display toggling proved unreliable on WinForms — the
  disabled starter button leaked through in 0.4.0). Default window size is
  narrower (760×640).

## [0.4.0] - 2026-07-18

### Added

- **First-run onboarding**: the Workspace Manager now tells a fresh user what
  to do. A contextual banner shows the next step — logged out: how to sign in
  (the built-in `admin` identity, with the default-passphrase hint; a custom
  `MSCHF_ADMIN_PASSPHRASE` is referenced but never displayed); signed in with
  an empty workspace: where apps live plus a **Create Starter App** button;
  otherwise hidden. The Auth Gateway prefills `admin` and shows the same hint.
- **Starter micro-app** (`src/mschf/starter.py`): one click authors a real
  signed `.msf` ("Getting Started") — the creating identity bootstraps as
  container admin, audit triggers install via signed DDL, welcome notes are
  seeded, and the UI (signed notes demo) deploys as a signed by-value code
  blob. The authored container passes the replay audit. `test_starter.py`
  covers authoring headlessly (CI) and the container is render-verified
  through the sandbox locally.
- Workspace scanning now includes the per-user data directory (where the
  starter app is created) — the meaningful workspace for installed builds
  whose cwd/install dir aren't user-writable locations.

## [0.3.1] - 2026-07-18

### Fixed

- Installer Welcome/Exit dialog text was unreadable — the branded `dialog.bmp`
  filled the whole panel with navy, but WiX renders its title/body in dark ink
  over the right two-thirds. The bitmaps now keep the text areas white (WiX
  convention) with the Mischief mark confined to a navy left panel on the
  dialog and the right of the banner; the glyph is extracted with a real alpha
  channel so it composites cleanly onto either background.

## [0.3.0] - 2026-07-18

### Fixed

- `LICENSE` now attributes copyright to Mischief Dev LLC (2026), replacing the
  Briefcase template's "Jane Developer, 2019" — this is the text shown as the
  EULA in the Windows installer.
- Windows installer is branded with Mischief bitmaps (WiX banner + dialog),
  replacing WiX's default red artwork. `installer/{banner,dialog}.bmp` are
  committed (regenerable from the logo via `scripts/make_installer_art.py`),
  and `scripts/brand_installer.py` injects the `WixUIBannerBmp`/`WixUIDialogBmp`
  variables into the generated scaffold — wired into the CI package job.

### Added

- **Ledger replay audit** (`src/mschf/audit.py`, `dev_tracker.py audit`):
  rebuilds a shadow database by replaying the signed `transactions` ledger and
  diffs it against the live tables, detecting any write that bypassed
  `execute_signed` (e.g. a raw sqlite3 edit). Re-verifies every ledger
  signature and CA-trust chain, replays recorded timestamps so time-stamped
  columns/triggers reproduce, replays trigger DDL from the ledger (rather than
  pre-seeding it) so guards fire only where they historically existed, and
  folds in per-blob code verification for `source_code`. `test_ledger_audit.py`
  proves a clean pass plus detection of doctored rows, injected rows, deleted
  rows, edited ledger entries (broken signature), and the trigger shield that
  blocks raw writes to guarded tables outright.
- GitHub Actions workflow (`ci-package.yml`): storage-layer integration tests
  (RBAC, authorizer, reactive redraw, container generation) plus a
  version-sources-agree check run on every push/PR to master; version tags and
  manual dispatch additionally build the Windows MSI via Briefcase and attach
  it to the GitHub Release.

## [0.2.0] - 2026-07-18

### Added

- **Reactive redraw**: open documents live-refresh when their container
  changes. Mutating signed transactions broadcast in-process via
  `MSFStorage.on_commit` (a document's micro-app writes → other windows on the
  same file redraw immediately); external writers (e.g. the `dev_tracker.py`
  CLI) are detected within ~2s by polling `PRAGMA data_version`, gated on the
  ledger's non-SELECT high-water mark so audit rows from signed *reads* never
  trigger redraws (which would otherwise loop between two open documents).
  Covered by `test_reactive.py`.

### Fixed

- Removed the committed `src/mschf.dist-info/` (generated Briefcase metadata —
  the source of the stale "Jane Developer 0.0.1" About data) and untracked the
  auto-created `settings.toml`; both are now gitignored.

### Changed

- Packaging `url` points at the canonical development repo
  (`chief-mouse/mischief`), matching the in-app homepage.

## [0.1.0] - 2026-07-18

First curated version — everything to date, replacing the template's 0.0.1.

### Added

- **Micro-app platform**: `.msf` containers (SQLite) holding manifest,
  dill-pickled Toga UI code, RBAC rules, and a ledger of RSA-signed
  transactions; sandboxed execution via `HostAPI` with a signature-status
  banner (VERIFIED vs tampered).
- **Identity & auth**: host Root CA + X.509 identities with
  passphrase-encrypted private keys; Auth Gateway plugin with an authoritative
  protocol dropdown — existing-identity passphrase login (default), PBKDF2
  password mock, real Google OIDC (auth code + PKCE + JWKS verification), and
  simulated Microsoft/passkey providers; app starts logged out.
- **RBAC**: four levels (database, object, view, field) bound to cryptographic
  identities (`cert:CN=...`), with opt-in first-writer admin bootstrap.
- **Authorizer enforcement**: every signed statement executes under a SQLite
  authorizer consulted for each table/column the compiled program touches;
  system tables admin-only; `PRAGMA`/`ATTACH`/`DETACH`/vtable DDL denied.
- **`current_signer()`**: SQL function exposing the verified signer identity to
  container triggers, enabling engine-enforced audit attribution
  (`dev_tracker.py`'s `AUDIT_TRIGGERS` is the canonical pattern).
- **Dev tracker dogfood**: `dev_tracker.py` / `dev_tracker.msf`, a task-board
  micro-app managing this project's own backlog through signed transactions,
  with hot code redeployment (`update-app`) and signed schema migrations.
- Integration test suite: `test_microapp.py`, `verify_microapp.py`,
  `test_rbac.py`, `test_authorizer.py`.

### Changed

- Real project metadata (name, author, description, version) shown in the
  About dialog, replacing Briefcase template placeholders; Help > Visit
  homepage opens the development fork.
- Mischief logo replaces the Toga/Briefcase template icons — app icon
  (title bar, taskbar, About) and per-row icons in the workspace file list —
  with `scripts/make_icons.py` regenerating the multi-size icon set from the
  brand asset.
