# Declarative UI exploration — findings

**Status:** v0 vocabulary, **integrated into the document loader** as of 0.8.0
(`msf.py` renders manifest `ui_spec` through `resolve_ui_mode`, preferring it
over a pickled `entry_point`; banner backed by
`MSFStorage.get_manifest_signature_status`).  
**Artifacts:** `src/mschf/declarative.py`, `test_declarative.py`, this note.  
**Date:** 2026-07.

## Motivation (restated)

Today every micro-app UI is a dill-pickled Python callable stored in `source_code`. That is powerful, but:

1. **Arbitrary code** runs from a document (pickle + `code_func(toga, host_api)`).
2. **Bytecode is Python-version-locked** — a 3.11-authored container can fail on 3.12, which breaks heterogeneous fleets and any mobile story.
3. **App Store §3.3.2** — downloading and executing interpreted code is a review risk; pure data specs are not.

The bet: most micro-apps are forms-over-data and can be a JSON **spec** — pure data, no exec/eval/pickle in the render path.

## What v0 implements

| Surface | Behavior |
|--------|----------|
| `render_declarative(spec, toga, host_api)` | Builds a Toga tree; raises `DeclarativeSpecError` on unknown/malformed constructs |
| `spec_from_manifest(storage)` | Reads signed manifest key `ui_spec` (JSON string) |
| Widgets | `box`, `label` (+ `text_from.user.common_name`), `table` (SELECT-only bound query), `text_input`, `button`, `status` |
| Actions | `exec` (parameterized `?` only via `execute_signed_query`) + `then_refresh`; `refresh` |
| Gate | `has_database_permission('read', cert)` → fixed lockout box (not caller data) |
| Failures | RBAC denials on button actions are caught and written to the status line |

Security invariants asserted in tests: no `exec`/`eval`/`dill` in `declarative.py`; SQL only through `HostAPI.execute_signed_query`; unknown kinds → hard error.

Authoring a declarative container is ordinary signed authoring: bootstrap → triggers → seed rows → RBAC → `set_manifest_item('ui_spec', json_string, ...)`. No code blob required for the UI itself.

## Coverage vs existing micro-apps

### Starter notes (`starter.py` / Getting Started)

| Feature | v0? | Notes |
|--------|-----|-------|
| Title + “signed in as {cn}” | **Yes** | `label` + `text_from` |
| Intro multiline prose block | **No** | No `multiline` / readonly text widget |
| Notes as a scrolling text dump | Partial | v0 uses a **table** bound to SELECT (clearer than the starter’s MultilineTextInput dump) |
| Text input + signed INSERT | **Yes** | `text_input` + `button`/`exec` |
| Status / RBAC denial line | **Yes** | `status` + caught exceptions |
| Trigger-stamped `created_by` | **Yes** | Engine-side; declarative does not touch attribution |

**Verdict:** Starter’s *read + add note* loop is expressible. The long intro copy and multiline notes presentation are not, without a `multiline` widget or a richer `label`.

### Dev Tracker (`dev_tracker.py`)

| Feature | v0? | Notes |
|--------|-----|-------|
| Task table from signed SELECT | **Yes** | `table` + columns projection |
| Header counts (“N backlog · …”) | **No** | Needs computed/aggregate bindings or a second query label |
| Per-row detail pane on select | **No** | No `on_select` / selection binding; no detail store |
| Status transition buttons (selection → UPDATE) | **No** | Actions cannot read `table.selection`; no row-context args |
| WinForms column-sizing hack (`tune_columns` / `_resize_columns`) | **No** | Host-native polish; not data-driven and platform-specific |
| Conditional admin tabs / role-based view trees | **No** | No `if role` / view-permission branching in the tree |
| “+ Add Task” insert + refresh | **Yes** | Same pattern as notes |
| Dynamic button labels from row state | **No** | Static `text` only |

**Verdict:** The tracker’s *read surface* (table of tasks) and *add task* form fit v0. The interactive board — select row, show detail, change status — needs selection-bound actions and at least one detail widget. Platform hacks stay in host Python forever (or in a declarative “host chrome” layer, not in the container).

## Integration (`msf.py` — landed in 0.8.0)

The loader now implements this path via `declarative.resolve_ui_mode`
(declarative > pickle > about; malformed `ui_spec` is a hard error view,
never a fallback to executing code) and
`MSFStorage.get_manifest_signature_status('ui_spec')` for the banner.
The original sketch, kept for context:

1. **Manifest keys**
   - Keep `entry_point` for pickled apps.
   - Add `ui_spec` (JSON string) **or** `ui_mode = "declarative" | "pickle"` plus the payload location.
2. **`MSF.redraw()` branch** (conceptual):
   ```
   if ui_spec := storage.get_manifest_item('ui_spec'):
       widget = render_declarative(json.loads(ui_spec), toga, host_api)
   elif entry_point:
       widget = execute_micro_app(get_code(entry_point), ...)
   else:
       about_view(...)
   ```
3. **Coexistence:** Containers may ship both during migration; prefer declarative when present so authors can dual-publish. Signature banner for pickle remains `get_code_signature_status`; for declarative, the **ledger already covers** the `ui_spec` manifest write — surface “UI from signed manifest” rather than a code-blob banner.
4. **Migration:** Convert starter first (smallest surface). Tracker later once selection actions and multiline exist. Leave advanced admin consoles on pickle until a larger vocabulary exists.
5. **Reactive redraw:** Unchanged — `on_commit` / `check_external_change` already re-call `redraw()`; a declarative tree simply rebuilds from the same spec (stateless render is a feature).

## Security comparison

| Threat | dill path | declarative v0 |
|--------|-----------|----------------|
| Arbitrary Python from document | Full (pickle + call) | **Removed** — data only |
| Pickle gadget / RCE on load | Present | **N/A** |
| SQL injection via UI | App author controls query strings in Python | Spec authors still write SQL in JSON, but **args bind only via `?`**; renderer never formats user input into the SQL string; non-SELECT rejected for tables |
| RBAC bypass | Same surface: `execute_signed_query` | **Same** — intentional |
| Authorizer / chain / CA trust | Enforced in storage | **Same** |
| Spec smuggling exotic widgets | N/A | Unknown `type`/`kind` → `DeclarativeSpecError` |
| Over-privileged static SQL in the spec | Author can embed any SELECT/INSERT the role allows | **Remains** — trust model is still “signed author + RBAC,” not “end user cannot run SQL.” The end user only supplies bound parameter values from inputs |

**What remains:** A malicious *author* with admin can still put harmful SQL in the signed spec (e.g. `DELETE FROM notes WHERE 1=1` on a button). That is equivalent to a malicious pickled app calling the same query. Defense is the same: CA trust on the author, RBAC for each actor who presses the button, ledger audit. Declarative removes the *execution* attack surface of untrusted or version-skewed code, not the *authorization* problem.

SQL injection *via the end user* is prevented by: (1) never interpolating input into SQL; (2) requiring `?` when `args` are present; (3) SELECT-only for data-bound tables.

## Portability

| Concern | dill | declarative |
|---------|------|-------------|
| CPython minor version | Bytecode / opcode lock | **Independent** — JSON + host renderer |
| Mobile / iOS App Store | §3.3.2 risk (downloaded code) | Spec is data; renderer ships with the binary |
| Non-Python hosts | Impossible | Possible later (same JSON → SwiftUI/Compose) |
| Widget parity | Full Toga API | Bound to vocabulary the host implements |

Caveat: the *renderer* still depends on the host’s Toga (or future native) version. Portability is about the **container artifact**, not the host binary.

## Recommendation

**Pursue.** The prototype already covers the starter’s core loop and the tracker’s read+add path with real signing and RBAC. That is enough to prove the architecture without touching `msf.py`.

### v1 to replace the starter app

Minimum vocabulary additions / polish:

1. **`multiline`** (readonly + optional editable) for intro copy and note bodies if table is not preferred.
2. Loader branch in `msf.py` + banner text for manifest-driven UI.
3. Authoring helper (`create_declarative_starter` or a flag on `create_starter_container`) that writes `ui_spec` instead of a dill blob.
4. Docs in `USER_GUIDE.md` / `ADMIN_GUIDE.md` for the schema.
5. Optional: `enabled_when` / view-permission gates for simple role UI without full scripting.

### v1+ for tracker parity

- Table **selection** as an action arg source (`{"selection": "table_id", "column": 0}`).
- Detail pane widget or bound label from selection.
- Aggregate/query labels for header counts (or a second small table).

### What not to do

- Do not reintroduce `exec` of expressions in the spec (“JSONPath but with Python”). Keep the language total and boring.
- Do not put CA or trust logic in the spec; trust stays host-side.
- Do not treat declarative as a full replacement for pickle yet — leave an escape hatch for complex apps.

### Bottom line

v0 is a successful exploration: forms-over-data micro-apps can be pure signed data, keep the cryptographic story intact, and shrink the App Store / version-skew problem. **Integrate after a short v1 that can ship the starter without dill**; keep pickle for complex UIs until selection and a few more widgets land.
