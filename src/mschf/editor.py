"""No-code editor v1: validated ui_spec / schema_spec editing + pure helpers.

All logic is headless-testable (no toga import). Saves are ordinary signed
transactions so the banner, ledger, and ``replay_audit`` keep working.
Homed replicas refuse saves in v1 (edit the hub's copy).
"""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from mschf.declarative import DeclarativeSpecError, _RenderContext
from mschf.schemaspec import (
    SchemaSpecError,
    apply_schema_spec,
    validate_schema_spec,
)
from mschf.storage import canonical_payload


class EditorError(Exception):
    """Raised when a save or helper cannot proceed (clear, user-facing message)."""


# Homed-replica refusal (v1). Exact phrase is asserted by tests / product copy.
HOMED_EDIT_REFUSAL = (
    "This container is homed on a sync hub (sync_hub_cn is set). "
    "Edit the hub's copy; hub-routed editing is future work."
)


# ---------------------------------------------------------------------------
# Identity / access helpers (GUI + tests)
# ---------------------------------------------------------------------------


def is_homed(storage) -> bool:
    """True when the container manifest carries ``sync_hub_cn``."""
    return bool(storage.get_manifest_item("sync_hub_cn"))


def is_container_admin(storage, cert_pem) -> bool:
    """True when *cert_pem*'s identity has role ``admin`` in this container."""
    if not cert_pem:
        return False
    identity = storage._get_identity(cert_pem)
    row = storage.conn.execute(
        "SELECT role FROM user_roles WHERE identity = ?",
        (identity,),
    ).fetchone()
    return bool(row and row[0] == "admin")


def can_edit_app(storage, cert_pem) -> bool:
    """Admin of this container and not a homed replica — show Edit App."""
    return is_container_admin(storage, cert_pem) and not is_homed(storage)


def _refuse_if_homed(storage) -> None:
    if is_homed(storage):
        raise EditorError(HOMED_EDIT_REFUSAL)


def _make_signer(storage, private_key):
    """Return ``sign(query, params) -> signature bytes`` (live chain head)."""
    if callable(private_key):
        return private_key

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    def sign(query, params):
        next_seq, prev_hash = storage.get_chain_head()
        payload = canonical_payload(
            query, params, next_seq, prev_hash, storage.container_uid
        )
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return sign


# ---------------------------------------------------------------------------
# Validation (never raises for invalid input — returns error strings)
# ---------------------------------------------------------------------------


def _fake_toga():
    """Minimal stand-in so ``_RenderContext`` can run without importing toga."""
    return SimpleNamespace(style=SimpleNamespace(Pack=object))


def _validate_ui_spec_dict(spec) -> list:
    """Structural validation via declarative's toga-free collect_ids path."""
    errors = []
    if not isinstance(spec, dict):
        return [f"ui_spec must be a JSON object, got {type(spec).__name__}"]
    try:
        ctx = _RenderContext(_fake_toga(), host_api=None)
        ctx.collect_ids(spec)
    except DeclarativeSpecError as e:
        errors.append(str(e))
    except Exception as e:
        errors.append(f"ui_spec validation failed: {e}")
    return errors


def validate_ui_spec_text(text) -> list:
    """Validate a ui_spec JSON string. Empty list = valid. Never raises."""
    if text is None:
        return ["ui_spec text is missing"]
    if not isinstance(text, str):
        return [f"ui_spec text must be a string, got {type(text).__name__}"]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        return [f"ui_spec is not valid JSON: {e}"]
    except TypeError as e:
        return [f"ui_spec is not valid JSON: {e}"]
    return _validate_ui_spec_dict(parsed)


def validate_schema_spec_text(text) -> list:
    """Validate a schema_spec JSON string. Empty list = valid. Never raises."""
    if text is None:
        return ["schema_spec text is missing"]
    if not isinstance(text, str):
        return [f"schema_spec text must be a string, got {type(text).__name__}"]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        return [f"schema_spec is not valid JSON: {e}"]
    except TypeError as e:
        return [f"schema_spec is not valid JSON: {e}"]
    try:
        validate_schema_spec(parsed)
    except SchemaSpecError as e:
        return [str(e)]
    except Exception as e:
        return [f"schema_spec validation failed: {e}"]
    return []


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def load_spec_texts(storage) -> dict:
    """Return pretty-printed ``ui_spec`` / ``schema_spec`` texts (or None each).

    Reads only — safe on homed replicas.
    """
    out = {"ui_spec": None, "schema_spec": None}

    raw_ui = storage.get_manifest_item("ui_spec")
    if raw_ui is not None:
        try:
            parsed = json.loads(raw_ui)
            out["ui_spec"] = json.dumps(parsed, indent=2, sort_keys=True)
        except (TypeError, json.JSONDecodeError):
            # Surface the raw bytes for the admin to fix in the editor.
            out["ui_spec"] = raw_ui if isinstance(raw_ui, str) else str(raw_ui)

    raw_schema = storage.get_manifest_item("schema_spec")
    if raw_schema is not None:
        try:
            parsed = json.loads(raw_schema)
            out["schema_spec"] = json.dumps(parsed, indent=2, sort_keys=True)
        except (TypeError, json.JSONDecodeError):
            out["schema_spec"] = (
                raw_schema if isinstance(raw_schema, str) else str(raw_schema)
            )

    return out


def save_ui_spec(storage, private_key, cert_pem, spec_text):
    """Validate, canonicalize (sort_keys), and signed-write ``ui_spec``.

    Refuses invalid specs and homed replicas without signing.
    *private_key* may be a key object or a ``sign(query, params)`` callable.
    """
    _refuse_if_homed(storage)
    errors = validate_ui_spec_text(spec_text)
    if errors:
        raise EditorError(
            "ui_spec validation failed — not signed:\n" + "\n".join(errors)
        )

    parsed = json.loads(spec_text)
    value = json.dumps(parsed, sort_keys=True)
    query = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    params = ["ui_spec", value]
    sign = _make_signer(storage, private_key)
    signature = sign(query, params)
    storage.execute_signed(query, params, signature, cert_pem)
    return value


def save_schema_spec(storage, private_key, cert_pem, spec_text):
    """Validate and apply via ``apply_schema_spec`` (additive evolution rules).

    Surfaces ``SchemaSpecError`` messages verbatim; chain head is untouched
    when apply refuses (apply validates/plans before any signing).
    """
    _refuse_if_homed(storage)
    errors = validate_schema_spec_text(spec_text)
    if errors:
        raise EditorError(
            "schema_spec validation failed — not signed:\n" + "\n".join(errors)
        )

    parsed = json.loads(spec_text)
    # Delegate evolution/apply; errors (SchemaSpecError) propagate verbatim.
    return apply_schema_spec(storage, private_key, cert_pem, parsed)


# ---------------------------------------------------------------------------
# Pure helpers (no I/O; callers re-validate + save)
# ---------------------------------------------------------------------------


def _walk_ids(node, ids=None):
    """Collect widget ids from a ui_spec tree (lenient; no full validation)."""
    if ids is None:
        ids = set()
    if not isinstance(node, dict):
        return ids
    wid = node.get("id")
    if isinstance(wid, str) and wid:
        ids.add(wid)
    for child in node.get("children") or []:
        _walk_ids(child, ids)
    return ids


def collect_ids(ui_spec) -> dict:
    """Return ``{id: widget_type}`` using declarative's ``collect_ids``.

    Raises ``DeclarativeSpecError`` if the tree is structurally invalid.
    """
    ctx = _RenderContext(_fake_toga(), host_api=None)
    ctx.collect_ids(ui_spec)
    return dict(ctx.declared_ids)


def _unique_id(base: str, existing: set) -> str:
    if base not in existing:
        return base
    n = 2
    while f"{base}_{n}" in existing:
        n += 1
    return f"{base}_{n}"


def helper_add_object(schema_spec, name, fields):
    """Return a new schema_spec with an added object.

    *fields* is a sequence of ``(name, type, [rules])`` triples (rules optional).
    Does not mutate *schema_spec*.
    """
    if not isinstance(schema_spec, dict):
        raise EditorError(
            f"schema_spec must be a dict, got {type(schema_spec).__name__}"
        )
    if not isinstance(name, str) or not name:
        raise EditorError("object name must be a non-empty string")

    new_spec = copy.deepcopy(schema_spec)
    objects = new_spec.setdefault("objects", [])
    if not isinstance(objects, list):
        raise EditorError("schema_spec.objects must be a list")

    for obj in objects:
        if isinstance(obj, dict) and obj.get("name") == name:
            raise EditorError(f"object {name!r} already exists")

    field_list = []
    for entry in fields or []:
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            raise EditorError(
                "each field must be (name, type) or (name, type, [rules])"
            )
        fname, ftype = entry[0], entry[1]
        rules = list(entry[2]) if len(entry) >= 3 and entry[2] is not None else []
        field_list.append({"name": fname, "type": ftype, "rules": rules})

    if not field_list:
        raise EditorError(f"object {name!r} requires at least one field")

    objects.append({"name": name, "fields": field_list})
    return new_spec


def helper_add_list_view(ui_spec, object_name, columns):
    """Append a list+insert pattern for *object_name* to a ui_spec copy.

    Canonical pattern: table (SELECT over the object), text_input(s) + button
    with INSERT action and ``then_refresh``, status line. Generated ids avoid
    collisions with ids already present in the tree.
    """
    if not isinstance(ui_spec, dict):
        raise EditorError(f"ui_spec must be a dict, got {type(ui_spec).__name__}")
    if not isinstance(object_name, str) or not object_name:
        raise EditorError("object_name must be a non-empty string")
    if not columns or not isinstance(columns, (list, tuple)):
        raise EditorError("columns must be a non-empty list of field names")
    columns = list(columns)
    for c in columns:
        if not isinstance(c, str) or not c:
            raise EditorError(f"invalid column name {c!r}")

    new_spec = copy.deepcopy(ui_spec)
    existing = _walk_ids(new_spec)

    table_id = _unique_id(f"{object_name}_table", existing)
    existing.add(table_id)
    status_id = _unique_id(f"{object_name}_status", existing)
    existing.add(status_id)

    input_ids = []
    for col in columns:
        iid = _unique_id(f"{object_name}_{col}_input", existing)
        existing.add(iid)
        input_ids.append(iid)

    col_sql = ", ".join(columns)
    # Include id for a usable list; headings/columns stay aligned with SELECT.
    select_cols = ["id"] + columns
    headings = [c.replace("_", " ").title() for c in select_cols]
    col_indices = list(range(len(select_cols)))

    placeholders = ", ".join("?" for _ in columns)
    insert_sql = f"INSERT INTO {object_name} ({col_sql}) VALUES ({placeholders})"

    input_widgets = [
        {
            "type": "text_input",
            "id": iid,
            "placeholder": col,
            "flex": 1,
            "margin": 4,
        }
        for iid, col in zip(input_ids, columns)
    ]

    row_children = list(input_widgets) + [
        {
            "type": "button",
            "text": f"Add {object_name}",
            "margin": 4,
            "action": {
                "kind": "exec",
                "sql": insert_sql,
                "args": [{"input": iid} for iid in input_ids],
                "then_refresh": [table_id],
                "status": status_id,
            },
        }
    ]

    section = {
        "type": "box",
        "direction": "column",
        "margin": 8,
        "children": [
            {
                "type": "label",
                "text": object_name.replace("_", " ").title(),
                "font_size": 14,
                "bold": True,
                "margin": 4,
            },
            {
                "type": "table",
                "id": table_id,
                "headings": headings,
                "query": {
                    "sql": (
                        f"SELECT {', '.join(select_cols)} "
                        f"FROM {object_name} ORDER BY id DESC"
                    ),
                    "params": [],
                },
                "columns": col_indices,
                "flex": 1,
                "margin": 4,
            },
            {
                "type": "box",
                "direction": "row",
                "children": row_children,
            },
            {
                "type": "status",
                "id": status_id,
                "margin": 6,
                "font_size": 10,
            },
        ],
    }

    if new_spec.get("type") == "box":
        children = list(new_spec.get("children") or [])
        children.append(section)
        new_spec["children"] = children
    else:
        new_spec = {
            "type": "box",
            "direction": "column",
            "children": [new_spec, section],
        }
    return new_spec


def helper_add_rule(schema_spec, object_name, field_name_or_None, rule):
    """Return a new schema_spec with *rule* appended (field or object level).

    *field_name_or_None* is ``None`` for object-level rules (``object_rules``).
    Unknown object/field raises ``EditorError``.
    """
    if not isinstance(schema_spec, dict):
        raise EditorError(
            f"schema_spec must be a dict, got {type(schema_spec).__name__}"
        )
    if not isinstance(object_name, str) or not object_name:
        raise EditorError("object_name must be a non-empty string")
    if rule is None or rule == "":
        raise EditorError("rule must be non-empty")

    new_spec = copy.deepcopy(schema_spec)
    objects = new_spec.get("objects")
    if not isinstance(objects, list):
        raise EditorError("schema_spec.objects must be a list")

    target_obj = None
    for obj in objects:
        if isinstance(obj, dict) and obj.get("name") == object_name:
            target_obj = obj
            break
    if target_obj is None:
        raise EditorError(f"unknown object {object_name!r}")

    if field_name_or_None is None:
        rules = target_obj.setdefault("object_rules", [])
        if not isinstance(rules, list):
            raise EditorError(
                f"object {object_name!r}: object_rules must be a list"
            )
        rules.append(rule)
        return new_spec

    fields = target_obj.get("fields")
    if not isinstance(fields, list):
        raise EditorError(f"object {object_name!r}: fields must be a list")
    target_field = None
    for f in fields:
        if isinstance(f, dict) and f.get("name") == field_name_or_None:
            target_field = f
            break
    if target_field is None:
        raise EditorError(
            f"unknown field {field_name_or_None!r} on object {object_name!r}"
        )
    frules = target_field.setdefault("rules", [])
    if not isinstance(frules, list):
        raise EditorError(
            f"field {object_name}.{field_name_or_None}: rules must be a list"
        )
    frules.append(rule)
    return new_spec


__all__ = [
    "EditorError",
    "HOMED_EDIT_REFUSAL",
    "can_edit_app",
    "collect_ids",
    "helper_add_list_view",
    "helper_add_object",
    "helper_add_rule",
    "is_container_admin",
    "is_homed",
    "load_spec_texts",
    "save_schema_spec",
    "save_ui_spec",
    "validate_schema_spec_text",
    "validate_ui_spec_text",
]
