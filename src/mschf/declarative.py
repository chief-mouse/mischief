"""Manifest-driven declarative UI renderer (exploration prototype).

Micro-app UIs are expressed as pure JSON widget trees — no exec, eval, or
pickled code. Data flows only through ``HostAPI.execute_signed_query`` so
signing, RBAC, and the SQLite authorizer apply exactly as for dill apps.

This module is intentionally standalone: document-loader integration
(``msf.py`` / ``sandbox.py``) is future work; see ``docs/declarative-ui-notes.md``.
"""
from __future__ import annotations

import json

from toga.style import Pack

# Security invariant: this module must never import exec/eval/dill (asserted
# by test_declarative.py). Only stdlib + toga Pack + caller's host_api objects.


class DeclarativeSpecError(Exception):
    """Raised when a declarative UI spec is malformed or uses unknown constructs."""


# Fixed lockout tree — never built from caller data.
_LOCKOUT_SPEC = {
    "type": "box",
    "direction": "column",
    "margin": 20,
    "children": [
        {
            "type": "label",
            "text": "ACCESS DENIED",
            "font_size": 20,
            "bold": True,
            "color": "red",
        },
        {
            "type": "label",
            "text": (
                "This identity does not have database-level read permission "
                "on this container."
            ),
        },
    ],
}

_ALLOWED_WIDGETS = frozenset({
    "box", "label", "table", "text_input", "button", "status",
})
_ALLOWED_ACTIONS = frozenset({"exec", "refresh"})


def spec_from_manifest(storage):
    """Read manifest key ``ui_spec`` (JSON string) and return a parsed dict.

    Returns ``None`` when the key is absent. Raises ``DeclarativeSpecError``
    when the value is present but not valid JSON or not a JSON object.
    """
    raw = storage.get_manifest_item("ui_spec")
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as e:
        raise DeclarativeSpecError(
            f"manifest ui_spec is not valid JSON: {e}"
        ) from e
    if not isinstance(parsed, dict):
        raise DeclarativeSpecError(
            f"manifest ui_spec must be a JSON object, got {type(parsed).__name__}"
        )
    return parsed


def render_declarative(spec, toga, host_api):
    """Render a declarative widget-tree spec into a Toga widget tree.

    Gates on ``host_api.has_database_permission('read', cert)``. Without
    database-level read, returns a fixed lockout box (not derived from
    caller data). Raises ``DeclarativeSpecError`` on any malformed or
    unknown construct — never falls back to executing code.
    """
    if not isinstance(spec, dict):
        raise DeclarativeSpecError(
            f"spec must be a dict, got {type(spec).__name__}"
        )

    user = {}
    try:
        user = host_api.get_current_user() or {}
    except Exception:
        pass
    cert = user.get("certificate_pem") or ""

    if not host_api.has_database_permission("read", cert):
        # Build lockout from the fixed internal spec only.
        ctx = _RenderContext(toga, host_api)
        return ctx.build(_LOCKOUT_SPEC)

    ctx = _RenderContext(toga, host_api)
    # Collect declared ids first so action refs can be validated regardless
    # of widget declaration order in the tree.
    ctx.collect_ids(spec)
    root = ctx.build(spec)
    # Initial table loads after the full tree exists (status targets, etc.).
    ctx.refresh_all_tables()
    return root


def _is_select_sql(sql):
    """True if sql (after stripping) is a SELECT statement."""
    if not isinstance(sql, str):
        return False
    return sql.lstrip().upper().startswith("SELECT")


def _placeholder_count(sql):
    """Count ``?`` bind placeholders (not inside single-quoted string literals)."""
    # Simple scan: toggle in_string on unescaped single quotes.
    count = 0
    i = 0
    in_string = False
    while i < len(sql):
        ch = sql[i]
        if in_string:
            if ch == "'":
                # SQL escape: '' inside a string
                if i + 1 < len(sql) and sql[i + 1] == "'":
                    i += 2
                    continue
                in_string = False
        else:
            if ch == "'":
                in_string = True
            elif ch == "?":
                count += 1
        i += 1
    return count


class _RenderContext:
    """Shared state while building one widget tree."""

    def __init__(self, toga, host_api):
        self.toga = toga
        self.host_api = host_api
        self.inputs = {}       # id -> TextInput
        self.tables = {}       # id -> {"widget", "sql", "params", "columns"}
        self.status = {}       # id -> Label
        self.declared_ids = {} # id -> widget type (from collect_ids)

    def collect_ids(self, node, path="root"):
        """Two-pass: register every id, then validate action cross-refs.

        Status/table widgets often appear *after* the buttons that target
        them, so action validation must wait until the full tree is known.
        """
        self._collect_ids_pass(node, path)
        self._validate_actions_pass(node, path)

    def _collect_ids_pass(self, node, path):
        if not isinstance(node, dict):
            raise DeclarativeSpecError(
                f"{path}: widget node must be an object, got {type(node).__name__}"
            )
        wtype = node.get("type")
        if wtype not in _ALLOWED_WIDGETS:
            raise DeclarativeSpecError(
                f"{path}: unknown widget type {wtype!r} "
                f"(allowed: {sorted(_ALLOWED_WIDGETS)})"
            )
        wid = node.get("id")
        if wid is not None:
            if not isinstance(wid, str) or not wid:
                raise DeclarativeSpecError(f"{path}: id must be a non-empty string")
            if wid in self.declared_ids:
                raise DeclarativeSpecError(
                    f"{path}: duplicate widget id {wid!r}"
                )
            self.declared_ids[wid] = wtype

        if wtype == "box":
            children = node.get("children", [])
            if not isinstance(children, list):
                raise DeclarativeSpecError(f"{path}: box children must be a list")
            for i, child in enumerate(children):
                self._collect_ids_pass(child, f"{path}.children[{i}]")

    def _validate_actions_pass(self, node, path):
        if not isinstance(node, dict):
            return
        wtype = node.get("type")
        if wtype == "box":
            for i, child in enumerate(node.get("children") or []):
                self._validate_actions_pass(child, f"{path}.children[{i}]")
        elif wtype == "button":
            action = node.get("action")
            if action is not None:
                self._validate_action(action, f"{path}.action")

    def _validate_action(self, action, path):
        if not isinstance(action, dict):
            raise DeclarativeSpecError(
                f"{path}: action must be an object, got {type(action).__name__}"
            )
        kind = action.get("kind")
        if kind not in _ALLOWED_ACTIONS:
            raise DeclarativeSpecError(
                f"{path}: unknown action kind {kind!r} "
                f"(allowed: {sorted(_ALLOWED_ACTIONS)})"
            )
        if kind == "exec":
            sql = action.get("sql")
            if not isinstance(sql, str) or not sql.strip():
                raise DeclarativeSpecError(f"{path}: exec action requires a non-empty sql string")
            args = action.get("args", [])
            if args is None:
                args = []
            if not isinstance(args, list):
                raise DeclarativeSpecError(f"{path}: args must be a list")
            n_ph = _placeholder_count(sql)
            if args and n_ph == 0:
                raise DeclarativeSpecError(
                    f"{path}: sql has no ? placeholders but args are present "
                    f"({len(args)} arg(s)); bind parameters with ? — "
                    "string-formatted SQL is not allowed"
                )
            if n_ph != len(args):
                raise DeclarativeSpecError(
                    f"{path}: sql has {n_ph} ? placeholder(s) but {len(args)} arg(s)"
                )
            for i, arg in enumerate(args):
                self._validate_arg(arg, f"{path}.args[{i}]")
            for tid in action.get("then_refresh") or []:
                if tid not in self.declared_ids:
                    raise DeclarativeSpecError(
                        f"{path}: then_refresh target {tid!r} is not a declared widget id"
                    )
                if self.declared_ids[tid] != "table":
                    raise DeclarativeSpecError(
                        f"{path}: then_refresh target {tid!r} is type "
                        f"{self.declared_ids[tid]!r}, expected 'table'"
                    )
            status_id = action.get("status")
            if status_id is not None and status_id not in self.declared_ids:
                raise DeclarativeSpecError(
                    f"{path}: status target {status_id!r} is not a declared widget id"
                )
        elif kind == "refresh":
            targets = action.get("targets", [])
            if not isinstance(targets, list) or not targets:
                raise DeclarativeSpecError(f"{path}: refresh action requires non-empty targets")
            for tid in targets:
                if tid not in self.declared_ids:
                    raise DeclarativeSpecError(
                        f"{path}: refresh target {tid!r} is not a declared widget id"
                    )
                if self.declared_ids[tid] != "table":
                    raise DeclarativeSpecError(
                        f"{path}: refresh target {tid!r} is type "
                        f"{self.declared_ids[tid]!r}, expected 'table'"
                    )

    def _validate_arg(self, arg, path):
        if not isinstance(arg, dict):
            raise DeclarativeSpecError(
                f"{path}: arg must be an object with 'input' or 'const', "
                f"got {type(arg).__name__}"
            )
        if "input" in arg:
            iid = arg["input"]
            if iid not in self.declared_ids:
                raise DeclarativeSpecError(
                    f"{path}: action references missing input id {iid!r}"
                )
            if self.declared_ids[iid] != "text_input":
                raise DeclarativeSpecError(
                    f"{path}: input ref {iid!r} is type "
                    f"{self.declared_ids[iid]!r}, expected 'text_input'"
                )
            if "const" in arg:
                raise DeclarativeSpecError(
                    f"{path}: arg must have exactly one of 'input' or 'const'"
                )
        elif "const" in arg:
            pass
        else:
            raise DeclarativeSpecError(
                f"{path}: arg must have 'input' or 'const' key"
            )

    def build(self, node, path="root"):
        if not isinstance(node, dict):
            raise DeclarativeSpecError(
                f"{path}: widget node must be an object, got {type(node).__name__}"
            )
        wtype = node.get("type")
        if wtype not in _ALLOWED_WIDGETS:
            raise DeclarativeSpecError(
                f"{path}: unknown widget type {wtype!r} "
                f"(allowed: {sorted(_ALLOWED_WIDGETS)})"
            )
        builder = {
            "box": self._build_box,
            "label": self._build_label,
            "table": self._build_table,
            "text_input": self._build_text_input,
            "button": self._build_button,
            "status": self._build_status,
        }[wtype]
        return builder(node, path)

    def _pack_kwargs(self, node):
        """Map common style fields from the node into Pack kwargs."""
        kw = {}
        if "direction" in node:
            d = node["direction"]
            if d not in ("column", "row"):
                raise DeclarativeSpecError(
                    f"direction must be 'column' or 'row', got {d!r}"
                )
            kw["direction"] = d
        if "margin" in node:
            kw["margin"] = node["margin"]
        if "flex" in node:
            kw["flex"] = node["flex"]
        return kw

    def _build_box(self, node, path):
        style_kw = self._pack_kwargs(node)
        if "direction" not in style_kw:
            style_kw["direction"] = "column"
        box = self.toga.Box(style=Pack(**style_kw))
        for i, child in enumerate(node.get("children") or []):
            box.add(self.build(child, f"{path}.children[{i}]"))
        return box

    def _build_label(self, node, path):
        text = node.get("text", "")
        if "text_from" in node:
            text = self._resolve_text_from(node["text_from"], path)
        style_kw = {}
        if "font_size" in node:
            style_kw["font_size"] = node["font_size"]
        if node.get("bold"):
            style_kw["font_weight"] = "bold"
        if "color" in node:
            style_kw["color"] = node["color"]
        if "margin" in node:
            style_kw["margin"] = node["margin"]
        if "flex" in node:
            style_kw["flex"] = node["flex"]
        return self.toga.Label(str(text), style=Pack(**style_kw) if style_kw else Pack())

    def _resolve_text_from(self, text_from, path):
        if not isinstance(text_from, dict):
            raise DeclarativeSpecError(
                f"{path}.text_from: must be an object, got {type(text_from).__name__}"
            )
        if "user" in text_from:
            key = text_from["user"]
            try:
                user = self.host_api.get_current_user() or {}
            except Exception:
                user = {}
            # Support dotted path like common_name; only known simple keys.
            if key == "common_name":
                return user.get("common_name", "Unknown")
            raise DeclarativeSpecError(
                f"{path}.text_from: unsupported user field {key!r} "
                "(v0 supports only 'common_name')"
            )
        raise DeclarativeSpecError(
            f"{path}.text_from: unsupported substitution {text_from!r}"
        )

    def _build_table(self, node, path):
        tid = node.get("id")
        if not tid:
            raise DeclarativeSpecError(f"{path}: table requires an id")
        headings = node.get("headings")
        if not isinstance(headings, list) or not headings:
            raise DeclarativeSpecError(f"{path}: table requires non-empty headings list")
        query = node.get("query")
        if not isinstance(query, dict):
            raise DeclarativeSpecError(f"{path}: table requires a query object")
        sql = query.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            raise DeclarativeSpecError(f"{path}: table query requires a sql string")
        if not _is_select_sql(sql):
            raise DeclarativeSpecError(
                f"{path}: table query sql must be SELECT-only "
                f"(got: {sql.strip()[:40]!r}...)"
            )
        params = query.get("params", [])
        if params is None:
            params = []
        if not isinstance(params, list):
            raise DeclarativeSpecError(f"{path}: query params must be a list")
        columns = node.get("columns")
        if columns is None:
            columns = list(range(len(headings)))
        if not isinstance(columns, list):
            raise DeclarativeSpecError(f"{path}: columns must be a list of indices")

        style_kw = {}
        if "flex" in node:
            style_kw["flex"] = node["flex"]
        if "margin" in node:
            style_kw["margin"] = node["margin"]

        table = self.toga.Table(
            columns=list(headings),
            data=[],
            style=Pack(**style_kw) if style_kw else Pack(),
        )
        self.tables[tid] = {
            "widget": table,
            "sql": sql,
            "params": list(params),
            "columns": list(columns),
        }
        return table

    def _build_text_input(self, node, path):
        tid = node.get("id")
        if not tid:
            raise DeclarativeSpecError(f"{path}: text_input requires an id")
        style_kw = {}
        if "flex" in node:
            style_kw["flex"] = node["flex"]
        if "margin" in node:
            style_kw["margin"] = node["margin"]
        widget = self.toga.TextInput(
            placeholder=str(node.get("placeholder", "")),
            style=Pack(**style_kw) if style_kw else Pack(),
        )
        self.inputs[tid] = widget
        return widget

    def _build_status(self, node, path):
        tid = node.get("id")
        if not tid:
            raise DeclarativeSpecError(f"{path}: status requires an id")
        style_kw = {"font_style": "italic"}
        if "margin" in node:
            style_kw["margin"] = node["margin"]
        if "font_size" in node:
            style_kw["font_size"] = node["font_size"]
        label = self.toga.Label("", style=Pack(**style_kw))
        self.status[tid] = label
        return label

    def _build_button(self, node, path):
        text = str(node.get("text", "Button"))
        action = node.get("action")
        if action is None:
            raise DeclarativeSpecError(f"{path}: button requires an action")
        # Re-validate in case collect_ids was skipped (e.g. lockout path).
        if self.declared_ids:
            self._validate_action(action, f"{path}.action")
        elif not isinstance(action, dict) or action.get("kind") not in _ALLOWED_ACTIONS:
            raise DeclarativeSpecError(
                f"{path}: unknown or missing action kind"
            )

        handler = self._make_action_handler(action, f"{path}.action")
        style_kw = {}
        if "margin" in node:
            style_kw["margin"] = node["margin"]
        if "flex" in node:
            style_kw["flex"] = node["flex"]
        return self.toga.Button(
            text,
            on_press=handler,
            style=Pack(**style_kw) if style_kw else Pack(),
        )

    def _make_action_handler(self, action, path):
        kind = action.get("kind")

        if kind == "refresh":
            targets = list(action.get("targets") or [])

            def on_refresh(widget):
                self.refresh_tables(targets)

            return on_refresh

        if kind == "exec":
            sql = action["sql"]
            arg_specs = list(action.get("args") or [])
            then_refresh = list(action.get("then_refresh") or [])
            status_id = action.get("status")

            def on_exec(widget):
                try:
                    params = self._resolve_args(arg_specs)
                    self.host_api.execute_signed_query(sql, params)
                    if status_id and status_id in self.status:
                        self.status[status_id].text = "Success."
                    self.refresh_tables(then_refresh)
                except Exception as e:
                    # RBAC denials and other runtime errors surface in the
                    # status line; they must not crash the UI.
                    msg = f"Blocked: {e}"
                    if status_id and status_id in self.status:
                        self.status[status_id].text = msg
                    elif self.status:
                        # Fall back to any status line if the named one is missing
                        next(iter(self.status.values())).text = msg

            return on_exec

        raise DeclarativeSpecError(f"{path}: unknown action kind {kind!r}")

    def _resolve_args(self, arg_specs):
        params = []
        for arg in arg_specs:
            if "input" in arg:
                iid = arg["input"]
                widget = self.inputs.get(iid)
                if widget is None:
                    raise DeclarativeSpecError(
                        f"action references missing input id {iid!r}"
                    )
                params.append(widget.value)
            elif "const" in arg:
                params.append(arg["const"])
            else:
                raise DeclarativeSpecError(
                    "arg must have 'input' or 'const' key"
                )
        return params

    def refresh_tables(self, targets):
        for tid in targets:
            entry = self.tables.get(tid)
            if entry is None:
                continue
            self._load_table(entry)

    def refresh_all_tables(self):
        for entry in self.tables.values():
            self._load_table(entry)

    def _load_table(self, entry):
        try:
            cursor = self.host_api.execute_signed_query(
                entry["sql"], entry["params"]
            )
            rows = cursor.fetchall()
            cols = entry["columns"]
            data = []
            for row in rows:
                data.append(tuple(row[i] if i < len(row) else None for i in cols))
            entry["widget"].data = data
        except Exception as e:
            # Leave existing data; surface error on a status line if any.
            if self.status:
                next(iter(self.status.values())).text = f"Query blocked: {e}"


# Re-export for tests that want the SELECT helper (optional).
__all__ = [
    "DeclarativeSpecError",
    "render_declarative",
    "spec_from_manifest",
]
