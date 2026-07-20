# Changelog

All notable changes to Mischief (`mschf`) are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/). Pre-1.0: a
MINOR bump means new features (and possibly breaking changes), a PATCH bump
means fixes only. The version lives in `pyproject.toml` (`[tool.briefcase]
version`) and `src/mschf/__init__.py` (`__version__`) — bump both, then add an
entry here.

## [Unreleased]

### Added

- **Packaged-app smoke tests on CI**: after packaging, `smoke-linux` installs
  the freshly built `.deb` on the noble runner (dependency resolution is part
  of the test) and `smoke-macos` mounts the DMG and launches the copied
  `.app` (quarantine-stripped) — each starting the real GUI with `MSCHF_HOME`
  isolated, asserting the process survives startup and that first-run
  artifacts (`ca.crt`, `admin.crt`, `settings.toml`) are generated in the
  per-user root (live verification of the packaged-paths fix), then
  uploading a screenshot + app log artifact — the first-ever renders of the
  app on GTK and Cocoa. Binary/app names are discovered from the package
  contents, never hardcoded; jobs are `continue-on-error` while they
  stabilize. Implemented by the grok agent; reviewed and runner-verified by
  Claude.

## [0.6.1] - 2026-07-20

The packaging release: installers for all three desktop platforms (Windows
MSI, macOS DMG, Linux .deb) built and release-attached by a three-OS CI
matrix that also proves the crypto/ledger/sync core on Windows, Ubuntu, and
macOS on every push — plus the packaged-app runtime-paths fix that makes
installed bundles actually work on first run.

### Added

- **Cross-platform CI matrix + packaging jobs**: the integration test job now
  runs the 10 headless suites on Windows, Ubuntu, and macOS runners
  (`test_declarative`/`verify_microapp` excluded — they need toga), proving
  the crypto/ledger/sync core platform-clean on every push. Packaging gains
  per-OS jobs: the existing Windows MSI, a macOS `.dmg` (ad-hoc signed —
  Gatekeeper right-click-open until an Apple Developer ID exists), and a
  best-effort Linux system package (`continue-on-error` while GTK runner
  deps stabilize). Implemented by the grok agent; reviewed by Claude;
  matrix verified on real runners post-merge.

### Fixed

- **Packaged-app runtime paths**: `app.py` no longer derives its artifact
  root from its own file location — which in an installed bundle is the
  read-only application directory, so first-run CA/identity/settings writes
  would fail (this plausibly affected the shipped v0.6.0 MSI). Runtime
  artifacts (CA, admin identity, provisioned identities, `settings.toml`,
  logs, workspace scan root) now root at `mschf.paths.host_root()` —
  unchanged repo root in dev, per-user data dir when installed,
  `MSCHF_HOME` override honored — created on demand. Implemented by the
  grok agent; reviewed and independently re-tested by Claude.

- **Release CI failure on v0.6.0**: the 0.6.0 version bump rewrote
  `pyproject.toml` with a UTF-8 BOM (PowerShell `Set-Content -Encoding utf8`),
  which `toml.load` in the CI version-agreement gate can't parse — failing the
  workflow before any tests ran and skipping the MSI build. File rewritten
  BOM-free; the `v0.6.0` tag was retargeted to the fixed commit so the release
  pipeline could complete.

## [0.6.0] - 2026-07-20

The hardening release: every security limit documented in 0.5.0's multi-user
stack is now closed — replicas re-enforce historical RBAC, pre-chaining
history is checkpoint-fenced, benign version skew no longer masquerades as
tampering — plus the package installs headless via pip (`mschf-hub`), the
tracker gains planning horizons, task links, and description validation, and
the Windows freeze is resolved by pinning out a toga regression.

### Added

- **Replica-side RBAC re-enforcement on replay**: closes the hub-sync v1
  limit where replicas applied hub rows without re-checking RBAC — a
  malicious hub colluding with a trusted-but-unprivileged signer could feed
  replicas a signed, correctly-chained row the historical RBAC state would
  have denied (e.g. privilege escalation via `user_roles`). A shared
  `historical_rbac_check` evaluates each mutating row against the RBAC state
  at its point in history: `replay_audit` flags denials as failing
  `rbac_violations` (still replaying, so table diffs stay clean and the
  violation is the finding), and `sync.pull_and_apply` refuses the row
  outright, rolling back the batch. Coarse (operation, table) gates —
  authorizer-depth replica checks remain future work. Also fixes the
  mid-pull hub-advanced race (benign, no longer raises after commit) and
  simplifies the head-sidecar bookkeeping. Implemented by the grok agent;
  reviewed and independently re-tested by Claude.

- **Legacy-prefix checkpoint**: closes the documented gap where rows inside a
  pre-chaining legacy prefix weren't linked to each other, so deleting a
  state-neutral legacy audit row (e.g. a signed read) was undetectable.
  `create_legacy_checkpoint` performs a signed manifest write committing to a
  SHA-256 digest of the entire legacy prefix (`legacy_prefix_digest`), and
  `replay_audit` recomputes and verifies it on every audit — a scrubbed or
  altered legacy row now fails the audit with a checkpoint mismatch.
  Idempotent (same digest → no-op), refuses containers with no legacy rows,
  and containers without a checkpoint keep today's behavior. Implemented by
  the grok agent; reviewed and independently re-tested by Claude.

- **Tracker validation rules — descriptions required**: dev_tasks items can
  no longer be saved without a description. Enforced engine-level via the
  platform's signed-trigger pattern (BEFORE INSERT/UPDATE `RAISE(ABORT)` on
  NULL/blank detail, installed through the idempotent signed `_ensure_schema`
  migration), so every writer — CLI, GUI, sandboxed micro-app, raw sqlite —
  is bound, and replay applies the rule only from its historical point.
  CLI `add` now requires the detail argument; new `describe <id> "text"`
  verb; GUI add row gains a required description input, with engine
  rejections surfaced in the status line. Deliberate strictness on legacy
  empty-detail rows: the next status/horizon touch requires `describe`
  first (clean guidance, no traceback). Establishes validation rules as
  signed, auditable container content. Implemented by the grok agent;
  reviewed and independently re-tested by Claude.

- **Version-skew downgrade policy**: `replay_audit` now distinguishes a
  benign stale-writer row from a malicious downgrade splice. A v2 row amid
  v3 history is classified as non-failing `version_skew` only when its
  signature is valid and CA-trusted, seq is continuous, AND its `prev_hash`
  matches the previous row hashed under the old no-container derivation —
  the precise fingerprint of a writer running pre-v3 code. Anything else
  (untrusted signer, modern-derivation or garbage prev_hash, seq gap)
  remains a failing chain break. Fixes the live incident where an old-code
  GUI's signed reads amid new-code writes made dev_tracker.msf audit-fail.
  Also adds a forward guard: an optional `payload_fmt_floor` in
  `container_meta` makes writers below the floor fail closed, so future
  format bumps can fence today's code (`set_payload_fmt_floor`).
  Implemented by the grok agent; reviewed and independently re-tested by
  Claude.

- **Pip-installable package + `mschf-hub` entry point**: the same `mschf`
  package now installs via pip with a standard `[project]` table (setuptools,
  src layout) — headless core dependencies only, with the GUI stack as an
  extra (`mschf[gui]`, toga pinned at 0.5.4). `pip install mschf` gives a
  server operator the hub + sync + crypto core and a `mschf-hub` console
  command with no toga. Path defaults are packaging-aware via the new
  `mschf.paths.host_root()`: `MSCHF_HOME` env override → source-checkout
  root in dev mode (behavior unchanged) → per-user data dir when installed
  (`%APPDATA%\mschf` / `~/Library/Application Support/mschf` /
  `~/.config/mschf`), so installed builds no longer point cert/trust-store
  defaults into site-packages. Briefcase config untouched; `briefcase dev`
  unaffected. Implemented by the grok agent; reviewed and independently
  re-tested by Claude.

- **Dev-tracker planning horizons + task links**: tasks now carry a `horizon`
  (`near`/`later`, NULL = near) so near-term plans and someday items stop
  sharing one backlog — new `horizon <id> <near|later>` CLI verb, board
  ordering in_progress → near → later → done, `◷ Later` styling, defer/return
  GUI buttons, and horizon counts. Tasks can also be related: an append-only
  `task_links` table (`from -[kind]-> to`, default `related`, UNIQUE-deduped,
  `created_by` trigger-stamped from the signing cert, immutability-guarded)
  with `link <from> <to> [kind]` / `links <id>` CLI verbs, link annotations in
  the list, and a links section in the GUI detail pane. Both arrive via the
  signed idempotent `_ensure_schema` migration (admin-run once); the `agent`
  role gets read/write on `task_links` so claude/grok can relate items.
  Implemented by the grok agent from a written spec; reviewed and
  independently re-tested by Claude.

### Fixed

- **Pin toga to 0.5.4 to dodge the WinForms freeze regression.** toga 0.5.5
  introduced a proactor event-loop bug ([beeware/toga#4532](https://github.com/beeware/toga/issues/4532))
  where, after the app sits idle for minutes, the event loop spins hot on the
  UI thread (~a full core) and leaks threads, starving Win32 input so the
  window becomes completely unresponsive (won't even drag) while the Python
  process stays alive. Root-caused on a live repro with py-spy + CPU sampling;
  the earlier "window ghosting" diagnosis was wrong (ghost windows drag and
  burn no CPU — a hot spin keeps the heartbeat's asyncio lag at zero, so the
  heartbeat never distinguished healthy from runaway). Requirement changed
  from an unpinned `toga>=0.4.0` (which pulled 0.5.5) to `toga==0.5.4`. The
  underlying proactor polling design ([beeware/toga#2613](https://github.com/beeware/toga/issues/2613))
  is unchanged in 0.5.4; reducing our own sustained asyncio timer load remains
  a tracked follow-up.

## [0.5.0] - 2026-07-19

The multi-user release: a `.msf` container can now be shared, verified, and
concurrently edited across machines and organizations — hash-chained signed
ledgers bound to a container identity, org-CA trust stores, hub-and-spoke
replication with countersigned heads, an identity directory, per-agent
identities with engine-enforced attribution, and a pickle-free declarative
UI prototype.

### Added

- **Container identity binding (payload format v3)**: every container mints a
  unique `container_uid` (stored in the new unsigned `container_meta` system
  table; legacy containers upgrade in place on open), and every newly signed
  payload embeds it. This closes the last replay vector: a captured signed
  history starting at genesis can no longer be transplanted into a different
  empty container — whole-file replicas (which share the uid) remain
  legitimate. The `transactions` table records each row's `payload_fmt`, so
  verifiers reconstruct exactly the signed form (v1/v2/v3) with no guessing,
  and `replay_audit` flags a v2 row after v3 history as a format-downgrade
  chain break. Hub head responses carry the uid; spoke submits can pin an
  expected uid. Covered by `test_container_binding.py`. Implemented by the
  grok agent; protocol diff reviewed line-by-line and independently
  re-tested by Claude.

- **Declarative UI prototype**: `src/mschf/declarative.py` renders micro-app
  UI from a pure-data JSON spec (manifest key `ui_spec`) instead of a
  dill-pickled callable — no exec/eval/pickle anywhere, tables bound to
  SELECT-only signed queries, actions restricted to parameterized SQL through
  the sandbox's signed-query path (RBAC and authorizer apply unchanged), and
  hard errors on unknown constructs. Removes arbitrary-code execution from
  documents, Python-bytecode version lock-in, and the App Store dynamic-code
  problem for containers that adopt it. Exploration deliverable — findings
  and v1 recommendation in `docs/declarative-ui-notes.md`; document-loader
  integration is future work. Covered by `test_declarative.py`. Implemented
  by the grok agent; reviewed and integrated by Claude.

- **Identity directory container**: `src/mschf/directory.py` authors a signed
  `.msf` phonebook of org identities — public certificates + metadata
  (CN, DER fingerprint, display name, org, active/revoked status) with
  trigger-stamped attribution and `directory_admin`/`member` roles — so
  admins can grant roles to identities from other machines without manual
  cert exchange. `register_identity` refuses certificates that don't chain
  to the local trust store; `set_identity_status` handles revocation
  bookkeeping; a read-only browser micro-app ships in the container. HARD
  RULE (enforced by design and stated in the module): the directory is
  never a trust anchor — signature verification consults only the host
  trust store. Covered by `test_directory.py`. Implemented by the grok
  agent from a written spec; reviewed and integrated by Claude.

- **Hub-and-spoke ledger sync (v1)**: multi-machine collaboration on a shared
  `.msf`. `src/mschf/hub.py` is a small stdlib HTTP server (`python -m
  mschf.hub`) holding the authoritative containers — trusted for ordering and
  availability only, never integrity: every submission runs through
  `execute_signed` (signature, chain position, CA trust, RBAC, authorizer),
  stale-head submissions return 409 with the fresh head, and every head
  response carries a hub-countersigned **attestation** — the external head
  record that makes ledger tail truncation detectable. `src/mschf/sync.py` is
  the spoke client: verified head fetch (attestation must chain to the trust
  store and match the pinned CN from the container's `sync_hub_url` /
  `sync_hub_cn` manifest homing keys), sign-against-hub-head submit with
  retry, bootstrap by downloading the container and refusing it unless
  `replay_audit` passes, and replay-apply that re-verifies each row's
  signature and chain linkage, executes with the historical signer so
  attribution triggers stamp correctly, and refuses hub heads that regress
  the sidecar-recorded attestation. Covered by `test_hub_sync.py` (bootstrap,
  write-through attribution, multi-spoke convergence, stale-head retry,
  bad-signature/untrusted-CA rejection, attestation checks, timestamp
  fidelity). Known v1 limits: replicas do not re-enforce RBAC on replayed
  rows (hub-side enforcement; tracked as follow-up), and the post-pull
  `datetime()` shim handles one-argument forms only. Implemented by the grok
  agent from a written spec; reviewed, independently re-tested, and
  integrated by Claude.

- **Dev-tracker CLI identity selection**: `dev_tracker.py` can now sign as any
  host identity — `--identity <cn>` (global flag) or `MSCHF_TRACKER_IDENTITY`,
  defaulting to `admin`; key passphrase from `MSCHF_TRACKER_PASSPHRASE` →
  `MSCHF_ADMIN_PASSPHRASE` → `changeit`. Purpose: per-agent identities
  (`claude`, `grok`, role `agent`: dev_tasks read/write only) record their own
  work with engine-enforced attribution via `current_signer()` triggers,
  instead of everything signing as admin. `init` always bootstraps as admin
  (a non-admin first writer would claim the container); pending schema
  migrations and `update-app` exit with clear messages (not tracebacks) for
  non-admin identities. Implemented by the grok agent from a written spec;
  reviewed, independently verified, and integrated by Claude.

- **Configurable trust anchors (org CA / trust store)**: the host now trusts
  its own `ca.crt` **plus** every `*.crt`/`*.pem` certificate in a
  `trusted_cas/` directory next to it (overridable via `MSCHF_TRUST_DIR`, or
  per-storage with `MSFStorage(..., trust_dir=...)`). Dropping an
  organization's root CA cert into the trust store lets the host verify
  transactions signed by identities that organization issued — the
  prerequisite for multi-user `.msf` collaboration across machines. Anchors
  are re-resolved on every verification (no restart needed), unparseable
  files are skipped with a warning, and verification **fails closed** when no
  anchors exist at all — including `Identity.load`, which previously skipped
  the chain check when the CA file was missing and now rejects instead.
  `replay_audit`'s shadow store mirrors the audited storage's trust
  configuration. New module `src/mschf/trust.py`
  (`resolve_trust_anchors` / `is_cert_trusted`); covered by
  `test_trust_store.py`. Implemented by the grok agent from a written spec;
  reviewed, verified, and integrated by Claude.

- **Ledger hash-chaining**: every signed transaction now embeds a sequence
  number and the SHA-256 of the previous ledger row (payload + signature) in
  its signed payload, making the `transactions` ledger a hash chain. Dropping,
  reordering, or splicing ledger rows now breaks verification even though each
  surviving row's own signature stays valid — `replay_audit` reports these as
  `chain_breaks` (tail truncation remains undetectable without an external
  head record, by nature of hash chains). Signers fetch
  `MSFStorage.get_chain_head()` immediately before signing;
  `execute_signed` re-derives the expected head under a `BEGIN IMMEDIATE`
  transaction, so stale-head signatures fail closed and concurrent writers
  cannot fork the chain. Payload canonicalization is now centralized in
  `storage.canonical_payload()` (previously copy-pasted across nine files).
  Backward compatible: pre-chaining rows (NULL `seq`) verify under the legacy
  payload format, existing containers are migrated in place (two new nullable
  ledger columns), and the chain anchors onto the last legacy row.
  Groundwork for multi-user ledger replication.

### Security

- **Chain-head hardening** (independent-review follow-up): `get_chain_head`
  now derives `next_seq` from `MAX(seq)` over the whole ledger instead of the
  newest row, so an out-of-band NULL-seq row appended after chained history
  (already flagged by `replay_audit`) can no longer reset the sequence to 1 —
  the chain continues past it and the pollution stays localized to the
  injected row (regression-tested in `test_ledger_audit.py`). Also documented
  a second inherent hash-chain limit alongside tail truncation: rows *within*
  a pre-chaining legacy prefix are not linked to each other, so deleting a
  legacy audit row that doesn't change replayed state (e.g. a signed read) is
  undetectable; containers created after chaining are fully protected from
  genesis.

### Fixed

- **Window-freeze mitigation**: disable Windows window-ghosting at startup
  (`DisableProcessWindowsGhosting`). Root-caused via the runtime heartbeat —
  across three freezes the app stayed fully alive (event loop ticking, up to
  ~21.7h), with `loop_lag_max=0.000s` (GUI thread pumping with zero latency, so
  not stalled) and flat, trivially-low GDI/USER counts (handle exhaustion ruled
  out). A live, healthy GUI thread behind an unresponsive window is Windows
  ghosting: the OS substitutes a dead "ghost" that never recovers. Disabling it
  keeps the real window so it resumes once the transient passes. No-op off
  Windows.
- `pyproject.toml` description shortened to ≤80 chars (Briefcase warned it was
  133); the fuller text moved to `long_description`.
- Runtime-log heartbeat diagnostics, after a second freeze (a live process with
  a normal last frame but unresponsive input — heartbeats kept firing on time
  throughout, ruling out a hang/crash/sleep):
  - GDI/USER handle counts were always 0 — `GetCurrentProcess()`'s pseudo-handle
    was passed truncated to `GetGuiResources` on 64-bit Windows; with explicit
    `argtypes`/`restype` it now reports real counts (verified 18/20 in a bare
    Toga app), so a future freeze shows whether handles are climbing.
  - Heartbeat now logs `loop_lag_max` — the worst asyncio-resume latency in the
    window. Because toga marshals every loop iteration onto the GUI thread,
    low lag during a freeze means the pump is healthy and input is being routed
    away (window ghosting); high lag means the GUI thread itself stalled. This
    is the discriminator to root-cause the freeze on its next occurrence.

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
