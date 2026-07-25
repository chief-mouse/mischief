"""Schema as data: versioned ``schema_spec`` → deterministic signed DDL train.

Extends the "app as data" principle from UI (``ui_spec``) to schema. A JSON
manifest entry describes objects (tables), fields, and validation rules; a
pure compiler emits the CREATE TABLE / trigger / index / RBAC statements that
authoring scripts currently write by hand. No exec, eval, or dill.

Enforcement is engine-side (SQLite CHECKs, FKs, triggers + ``current_signer()``),
the same pattern as ``dev_tracker.AUDIT_TRIGGERS`` and ``directory.py``.

Limitation (v1 ``owner_only_update``): the guard is strictly row-owner —
``current_signer() IS OLD.created_by``. There is no admin bypass and no role
lookup. The host authorizer denies non-admin ``user_roles`` reads inside
trigger bodies at prepare time, so a role-based exception would need a
non-system mirror table (as directory's ``attestation_authz`` does). v1 does
not add that mirror; document callers must not expect admin override.
"""
from __future__ import annotations

import json
import re

from mschf.storage import MSFStorage, canonical_payload

# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------


class SchemaSpecError(Exception):
    """Raised when a schema_spec is malformed, uses unknown constructs, or
    proposes an evolution that needs a rebuild migration."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_SPEC_VERSION = 1
SUPPORTED_TYPES = frozenset({"text", "integer", "real"})
TYPE_SQL = {"text": "TEXT", "integer": "INTEGER", "real": "REAL"}

# Named (string) field rules and the sole object rule.
FIELD_RULE_NAMES = frozenset({
    "required", "unique", "immutable_after_create",
})
OBJECT_RULE_NAMES = frozenset({"owner_only_update"})

# Canonical audit columns every object table carries; reserved as field names.
AUDIT_COLUMNS = ("id", "created_at", "created_by", "updated_at", "updated_by")
RESERVED_FIELD_NAMES = frozenset(AUDIT_COLUMNS)

# SQL identifier: must not be a system table or other reserved name.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")

# Access permissions we emit as object-level rbac_rules.
_ACCESS_PERMS = frozenset({"read", "write"})


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _reserved_names():
    """Object names that collide with platform tables or audit columns."""
    return set(MSFStorage.SYSTEM_TABLES) | set(RESERVED_FIELD_NAMES)


def _check_ident(name, kind):
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise SchemaSpecError(
            f"Invalid {kind} name {name!r}: must match {_IDENT_RE.pattern}"
        )


def _sql_string(value):
    """Quote a Python value as a SQLite string literal (deterministic)."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        # bool is int subclass — reject explicitly (not a supported enum type).
        raise SchemaSpecError(f"enum values must be str/int/float, not bool: {value!r}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str):
        raise SchemaSpecError(
            f"enum values must be str/int/float, got {type(value).__name__}: {value!r}"
        )
    return "'" + value.replace("'", "''") + "'"


def _normalize_field_rules(rules, field_name):
    """Return a list of normalized rule tokens for a field.

    Tokens: ``'required'``, ``'unique'``, ``'immutable_after_create'``,
    ``('enum', (v1, v2, ...))``, ``('reference', 'table.column')``.
    """
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise SchemaSpecError(
            f"Field {field_name!r}: rules must be a list, got {type(rules).__name__}"
        )
    out = []
    seen = set()
    for r in rules:
        if isinstance(r, str):
            if r not in FIELD_RULE_NAMES:
                raise SchemaSpecError(
                    f"Field {field_name!r}: unknown rule {r!r}"
                )
            if r in seen:
                raise SchemaSpecError(
                    f"Field {field_name!r}: duplicate rule {r!r}"
                )
            seen.add(r)
            out.append(r)
        elif isinstance(r, dict):
            if not r:
                raise SchemaSpecError(
                    f"Field {field_name!r}: empty rule object"
                )
            if len(r) != 1:
                raise SchemaSpecError(
                    f"Field {field_name!r}: rule object must have exactly one key, got {sorted(r)!r}"
                )
            key, val = next(iter(r.items()))
            if key == "enum":
                if "enum" in seen:
                    raise SchemaSpecError(
                        f"Field {field_name!r}: duplicate enum rule"
                    )
                if not isinstance(val, list) or len(val) == 0:
                    raise SchemaSpecError(
                        f"Field {field_name!r}: enum must be a non-empty list"
                    )
                # Preserve order; reject non-scalar later via _sql_string.
                for v in val:
                    _sql_string(v)
                seen.add("enum")
                out.append(("enum", tuple(val)))
            elif key == "reference":
                if "reference" in seen:
                    raise SchemaSpecError(
                        f"Field {field_name!r}: duplicate reference rule"
                    )
                if not isinstance(val, str) or not _REF_RE.match(val):
                    raise SchemaSpecError(
                        f"Field {field_name!r}: malformed reference {val!r} "
                        f"(expected table.column)"
                    )
                seen.add("reference")
                out.append(("reference", val))
            else:
                raise SchemaSpecError(
                    f"Field {field_name!r}: unknown rule {key!r}"
                )
        else:
            raise SchemaSpecError(
                f"Field {field_name!r}: rule must be str or object, got {type(r).__name__}"
            )
    return out


def _normalize_object_rules(rules, object_name):
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise SchemaSpecError(
            f"Object {object_name!r}: object_rules must be a list"
        )
    out = []
    seen = set()
    for r in rules:
        if not isinstance(r, str) or r not in OBJECT_RULE_NAMES:
            raise SchemaSpecError(
                f"Object {object_name!r}: unknown object rule {r!r}"
            )
        if r in seen:
            raise SchemaSpecError(
                f"Object {object_name!r}: duplicate object rule {r!r}"
            )
        seen.add(r)
        out.append(r)
    return out


def _normalize_access(access, object_name):
    """Return sorted list of (role, permission) pairs."""
    if access is None:
        return []
    if not isinstance(access, dict):
        raise SchemaSpecError(
            f"Object {object_name!r}: access must be an object mapping role → [permissions]"
        )
    pairs = []
    for role, perms in access.items():
        if not isinstance(role, str) or not role:
            raise SchemaSpecError(
                f"Object {object_name!r}: invalid access role {role!r}"
            )
        if not isinstance(perms, list):
            raise SchemaSpecError(
                f"Object {object_name!r}: access[{role!r}] must be a list of permissions"
            )
        for p in perms:
            if p not in _ACCESS_PERMS:
                raise SchemaSpecError(
                    f"Object {object_name!r}: unknown access permission {p!r} "
                    f"(expected read/write)"
                )
            pairs.append((role, p))
    # Deterministic order: by role then permission.
    pairs.sort(key=lambda x: (x[0], x[1]))
    # Dedup while preserving sorted order.
    deduped = []
    seen = set()
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            deduped.append(pair)
    return deduped


def _rule_has(rules, name):
    return name in rules


def _rule_enum(rules):
    for r in rules:
        if isinstance(r, tuple) and r[0] == "enum":
            return r[1]
    return None


def _rule_reference(rules):
    for r in rules:
        if isinstance(r, tuple) and r[0] == "reference":
            return r[1]
    return None


def validate_schema_spec(spec):
    """Validate a schema_spec dict. Raises SchemaSpecError; returns None on success.

    Nothing is written. Call before any signing.
    """
    if not isinstance(spec, dict):
        raise SchemaSpecError(
            f"schema_spec must be a JSON object, got {type(spec).__name__}"
        )
    if spec.get("v") != SCHEMA_SPEC_VERSION:
        raise SchemaSpecError(
            f"Unsupported schema_spec version {spec.get('v')!r}; "
            f"only v={SCHEMA_SPEC_VERSION} is supported"
        )
    objects = spec.get("objects")
    if not isinstance(objects, list) or len(objects) == 0:
        raise SchemaSpecError("schema_spec.objects must be a non-empty list")

    reserved = _reserved_names()
    seen_objects = set()
    object_fields = {}  # name -> {field_name: type}

    for obj in objects:
        if not isinstance(obj, dict):
            raise SchemaSpecError("Each object entry must be a JSON object")
        name = obj.get("name")
        _check_ident(name, "object")
        if name.lower() in {r.lower() for r in reserved} or name in reserved:
            raise SchemaSpecError(
                f"Object name {name!r} is reserved (system table or audit column)"
            )
        if name in seen_objects:
            raise SchemaSpecError(f"Duplicate object name {name!r}")
        seen_objects.add(name)

        fields = obj.get("fields")
        if not isinstance(fields, list) or len(fields) == 0:
            raise SchemaSpecError(
                f"Object {name!r}: fields must be a non-empty list"
            )
        seen_fields = set()
        field_map = {}
        for field in fields:
            if not isinstance(field, dict):
                raise SchemaSpecError(
                    f"Object {name!r}: each field must be a JSON object"
                )
            fname = field.get("name")
            _check_ident(fname, "field")
            if fname in RESERVED_FIELD_NAMES:
                raise SchemaSpecError(
                    f"Field name {fname!r} is reserved (canonical audit column)"
                )
            if fname in seen_fields:
                raise SchemaSpecError(
                    f"Object {name!r}: duplicate field name {fname!r}"
                )
            seen_fields.add(fname)
            ftype = field.get("type")
            if ftype not in SUPPORTED_TYPES:
                raise SchemaSpecError(
                    f"Field {name}.{fname}: unknown type {ftype!r} "
                    f"(supported: {sorted(SUPPORTED_TYPES)})"
                )
            rules = _normalize_field_rules(field.get("rules"), f"{name}.{fname}")
            field_map[fname] = {"type": ftype, "rules": rules}

        _normalize_object_rules(obj.get("object_rules"), name)
        _normalize_access(obj.get("access"), name)
        object_fields[name] = field_map

    # Reference targets: format already checked; target table.column should
    # resolve to a known object field or the implicit id PK on a known object.
    for obj in objects:
        name = obj["name"]
        for field in obj["fields"]:
            rules = _normalize_field_rules(field.get("rules"), f"{name}.{field['name']}")
            ref = _rule_reference(rules)
            if ref is None:
                continue
            tname, cname = ref.split(".", 1)
            if tname not in object_fields:
                # Allow reference to a table not in this spec (pre-existing);
                # format is valid. Evolution/apply can still fail at SQLite FK
                # time if the parent is missing.
                continue
            if cname == "id":
                continue
            if cname not in object_fields[tname]:
                raise SchemaSpecError(
                    f"Field {name}.{field['name']}: reference {ref!r} "
                    f"target column does not exist on object {tname!r}"
                )

    return None


def _parsed_objects(spec):
    """Return ordered list of normalized object dicts (post-validation)."""
    validate_schema_spec(spec)
    result = []
    for obj in spec["objects"]:
        fields = []
        for field in obj["fields"]:
            fields.append({
                "name": field["name"],
                "type": field["type"],
                "rules": _normalize_field_rules(
                    field.get("rules"), f"{obj['name']}.{field['name']}"
                ),
            })
        result.append({
            "name": obj["name"],
            "fields": fields,
            "object_rules": _normalize_object_rules(
                obj.get("object_rules"), obj["name"]
            ),
            "access": _normalize_access(obj.get("access"), obj["name"]),
        })
    return result


# ---------------------------------------------------------------------------
# Compiler (deterministic)
# ---------------------------------------------------------------------------


def _column_sql(field):
    """Single column fragment for CREATE TABLE (no trailing comma)."""
    name = field["name"]
    parts = [name, TYPE_SQL[field["type"]]]
    rules = field["rules"]
    if _rule_has(rules, "required"):
        if field["type"] == "text":
            parts.append(f"NOT NULL CHECK(length(trim({name})) > 0)")
        else:
            parts.append("NOT NULL")
    enum_vals = _rule_enum(rules)
    if enum_vals is not None:
        in_list = ", ".join(_sql_string(v) for v in enum_vals)
        parts.append(f"CHECK({name} IN ({in_list}))")
    ref = _rule_reference(rules)
    if ref is not None:
        t, c = ref.split(".", 1)
        parts.append(f"REFERENCES {t}({c})")
    return " ".join(parts)


def _create_table_sql(obj):
    cols = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
    for field in obj["fields"]:
        cols.append(_column_sql(field))
    cols.extend([
        "created_at TEXT",
        "created_by TEXT",
        "updated_at TEXT",
        "updated_by TEXT",
    ])
    return f"CREATE TABLE {obj['name']} ({', '.join(cols)})"


def _audit_triggers(table):
    """Canonical insert/update stamp + created_* immutability (dev_tracker pattern).

    Bodies deliberately avoid a bare ``FROM <ident>`` token so
    ``storage._parse_sql_query`` does not misclassify CREATE TRIGGER as a read
    (see directory.py ATTESTATION_AUTHZ_TRIGGERS comment).
    """
    return [
        (
            f"CREATE TRIGGER trg_{table}_insert_audit AFTER INSERT ON {table}\n"
            f"       BEGIN\n"
            f"         UPDATE {table} SET\n"
            f"           created_at = COALESCE(NEW.created_at, datetime('now')),\n"
            f"           updated_at = COALESCE(NEW.updated_at, datetime('now')),\n"
            f"           created_by = COALESCE(current_signer(), 'unsigned'),\n"
            f"           updated_by = COALESCE(current_signer(), 'unsigned')\n"
            f"         WHERE id = NEW.id;\n"
            f"       END"
        ),
        (
            f"CREATE TRIGGER trg_{table}_update_audit AFTER UPDATE ON {table}\n"
            f"       BEGIN\n"
            f"         UPDATE {table} SET\n"
            f"           updated_at = datetime('now'),\n"
            f"           updated_by = COALESCE(current_signer(), 'unsigned')\n"
            f"         WHERE id = NEW.id;\n"
            f"       END"
        ),
        (
            f"CREATE TRIGGER trg_{table}_created_immutable BEFORE UPDATE ON {table}\n"
            f"       WHEN OLD.created_by IS NOT NULL\n"
            f"        AND (NEW.created_at IS NOT OLD.created_at OR NEW.created_by IS NOT OLD.created_by)\n"
            f"       BEGIN\n"
            f"         SELECT RAISE(ABORT, 'created_at/created_by are immutable audit fields');\n"
            f"       END"
        ),
    ]


def _unique_index_sql(table, field_name):
    return f"CREATE UNIQUE INDEX ux_{table}_{field_name} ON {table}({field_name})"


def _immutable_trigger_sql(table, field_name):
    msg = f"{table}.{field_name} is immutable after create"
    return (
        f"CREATE TRIGGER trg_{table}_{field_name}_immutable BEFORE UPDATE ON {table}\n"
        f"       WHEN NEW.{field_name} IS NOT OLD.{field_name}\n"
        f"       BEGIN\n"
        f"         SELECT RAISE(ABORT, {_sql_string(msg)});\n"
        f"       END"
    )


def _owner_only_trigger_sql(table):
    """Strict owner-only UPDATE. NULL signer refused (IS NOT semantics).

    WHEN OLD.created_by IS NOT NULL lets the insert-audit AFTER INSERT stamp
    run while created_by is still NULL (recursive_triggers is off, but the
    stamp is an UPDATE that fires BEFORE UPDATE triggers).
    """
    msg = f"{table}: only the creating owner may update this row"
    return (
        f"CREATE TRIGGER trg_{table}_owner_only BEFORE UPDATE ON {table}\n"
        f"       WHEN OLD.created_by IS NOT NULL\n"
        f"        AND current_signer() IS NOT OLD.created_by\n"
        f"       BEGIN\n"
        f"         SELECT RAISE(ABORT, {_sql_string(msg)});\n"
        f"       END"
    )


def _required_check_triggers(table, field):
    """BEFORE INSERT/UPDATE value checks for evolution (CHECK can't be added post-hoc)."""
    name = field["name"]
    if field["type"] == "text":
        when = f"NEW.{name} IS NULL OR length(trim(NEW.{name})) = 0"
        msg = f"{table}.{name} is required (non-empty text)"
    else:
        when = f"NEW.{name} IS NULL"
        msg = f"{table}.{name} is required"
    return [
        (
            f"CREATE TRIGGER trg_{table}_{name}_req_ins BEFORE INSERT ON {table}\n"
            f"       WHEN {when}\n"
            f"       BEGIN\n"
            f"         SELECT RAISE(ABORT, {_sql_string(msg)});\n"
            f"       END",
            [],
        ),
        (
            f"CREATE TRIGGER trg_{table}_{name}_req_upd BEFORE UPDATE ON {table}\n"
            f"       WHEN {when}\n"
            f"       BEGIN\n"
            f"         SELECT RAISE(ABORT, {_sql_string(msg)});\n"
            f"       END",
            [],
        ),
    ]


def _enum_check_triggers(table, field, enum_vals):
    name = field["name"]
    in_list = ", ".join(_sql_string(v) for v in enum_vals)
    # NULL is allowed unless also required (separate triggers handle required).
    when = f"NEW.{name} IS NOT NULL AND NEW.{name} NOT IN ({in_list})"
    msg = f"{table}.{name} must be one of: {', '.join(str(v) for v in enum_vals)}"
    return [
        (
            f"CREATE TRIGGER trg_{table}_{name}_enum_ins BEFORE INSERT ON {table}\n"
            f"       WHEN {when}\n"
            f"       BEGIN\n"
            f"         SELECT RAISE(ABORT, {_sql_string(msg)});\n"
            f"       END",
            [],
        ),
        (
            f"CREATE TRIGGER trg_{table}_{name}_enum_upd BEFORE UPDATE ON {table}\n"
            f"       WHEN {when}\n"
            f"       BEGIN\n"
            f"         SELECT RAISE(ABORT, {_sql_string(msg)});\n"
            f"       END",
            [],
        ),
    ]


def _rbac_inserts(table, access_pairs):
    """Return list of (query, params) for object-level access grants."""
    q = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
    return [(q, ["object", table, role, perm]) for role, perm in access_pairs]


def _compile_new_object(obj):
    """Full DDL train for one new object: table → audit → rules → access."""
    statements = []  # list of (sql, params)
    statements.append((_create_table_sql(obj), []))
    for ddl in _audit_triggers(obj["name"]):
        statements.append((ddl, []))

    # Rule triggers / indexes in field order, then object rules.
    for field in obj["fields"]:
        rules = field["rules"]
        if _rule_has(rules, "unique"):
            statements.append((_unique_index_sql(obj["name"], field["name"]), []))
        if _rule_has(rules, "immutable_after_create"):
            statements.append((_immutable_trigger_sql(obj["name"], field["name"]), []))
    if _rule_has(obj["object_rules"], "owner_only_update"):
        statements.append((_owner_only_trigger_sql(obj["name"]), []))

    statements.extend(_rbac_inserts(obj["name"], obj["access"]))
    return statements


def compile_schema_spec(spec):
    """Validate and compile a full schema_spec into a deterministic DDL train.

    Returns a list of ``(sql, params)`` tuples. Same spec always yields
    byte-identical SQL strings and params (objects/fields in spec order;
    access grants sorted by role then permission).
    """
    objects = _parsed_objects(spec)
    statements = []
    for obj in objects:
        statements.extend(_compile_new_object(obj))
    return statements


def canonical_schema_json(spec):
    """Canonical JSON for the manifest ``schema_spec`` value (sort_keys)."""
    return json.dumps(spec, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Evolution (additive only)
# ---------------------------------------------------------------------------


def _index_by_name(objects):
    return {o["name"]: o for o in objects}


def _table_row_count(storage, table):
    try:
        return storage.conn.execute(
            f'SELECT COUNT(*) FROM "{table}"'
        ).fetchone()[0]
    except Exception:
        return 0


def _field_by_name(obj):
    return {f["name"]: f for f in obj["fields"]}


def _rebuild_msg(change):
    return (
        f"{change}; this change requires a rebuild migration "
        f"(not yet supported in schema_spec v1)"
    )


def plan_schema_evolution(old_spec, new_spec, storage=None):
    """Diff old → new and return the additive DDL train, or raise SchemaSpecError.

    When *storage* is provided, used to detect non-empty tables for
    required-on-add refusal. Validation of the whole plan happens before any
    statement is returned; callers must not sign until this returns.
    """
    old_objs = _parsed_objects(old_spec)
    new_objs = _parsed_objects(new_spec)
    old_by = _index_by_name(old_objs)
    new_by = _index_by_name(new_objs)

    # Removals / renames (missing names).
    for name in old_by:
        if name not in new_by:
            raise SchemaSpecError(
                _rebuild_msg(f"object {name!r} was removed")
            )

    statements = []

    for new_obj in new_objs:
        name = new_obj["name"]
        if name not in old_by:
            # Brand-new object: full train.
            statements.extend(_compile_new_object(new_obj))
            continue

        old_obj = old_by[name]
        old_fields = _field_by_name(old_obj)
        new_fields = _field_by_name(new_obj)

        for fname in old_fields:
            if fname not in new_fields:
                raise SchemaSpecError(
                    _rebuild_msg(f"field {name}.{fname} was removed")
                )

        # Existing fields: type stable; rules only additive; enum not narrowed.
        for fname, new_f in new_fields.items():
            if fname not in old_fields:
                continue
            old_f = old_fields[fname]
            if old_f["type"] != new_f["type"]:
                raise SchemaSpecError(
                    _rebuild_msg(
                        f"field {name}.{fname} retyped "
                        f"from {old_f['type']!r} to {new_f['type']!r}"
                    )
                )
            old_rules = old_f["rules"]
            new_rules = new_f["rules"]
            old_set = set(old_rules)
            # New named rules / structured rules not previously present.
            for r in new_rules:
                if r in old_set:
                    continue
                if r == "required":
                    statements.extend(_required_check_triggers(name, new_f))
                elif r == "unique":
                    statements.append((_unique_index_sql(name, fname), []))
                elif r == "immutable_after_create":
                    statements.append((_immutable_trigger_sql(name, fname), []))
                elif isinstance(r, tuple) and r[0] == "enum":
                    statements.extend(_enum_check_triggers(name, new_f, r[1]))
                elif isinstance(r, tuple) and r[0] == "reference":
                    raise SchemaSpecError(
                        _rebuild_msg(
                            f"new reference {r[1]!r} on existing field {name}.{fname}"
                        )
                    )
                else:
                    raise SchemaSpecError(
                        f"Field {name}.{fname}: cannot add rule {r!r} via evolution"
                    )

            # Enum set change: refuse narrowing (and any other set change that
            # would leave a stale CHECK out of sync — treat non-equal as rebuild).
            old_enum = _rule_enum(old_rules)
            new_enum = _rule_enum(new_rules)
            if old_enum is not None and new_enum is not None:
                old_e, new_e = set(old_enum), set(new_enum)
                if new_e != old_e:
                    if new_e.issubset(old_e) and new_e != old_e:
                        raise SchemaSpecError(
                            _rebuild_msg(
                                f"enum on {name}.{fname} narrowed "
                                f"from {list(old_enum)!r} to {list(new_enum)!r}"
                            )
                        )
                    raise SchemaSpecError(
                        _rebuild_msg(
                            f"enum on {name}.{fname} changed "
                            f"from {list(old_enum)!r} to {list(new_enum)!r}"
                        )
                    )

            # Dropped rules on existing fields need rebuild.
            for r in old_rules:
                if r not in new_rules:
                    raise SchemaSpecError(
                        _rebuild_msg(
                            f"rule {r!r} removed from field {name}.{fname}"
                        )
                    )

        # New fields (ALTER TABLE ADD COLUMN).
        for field in new_obj["fields"]:
            fname = field["name"]
            if fname in old_fields:
                continue
            col_type = TYPE_SQL[field["type"]]
            ref = _rule_reference(field["rules"])
            col_sql = f"{fname} {col_type}"
            if ref is not None:
                t, c = ref.split(".", 1)
                col_sql += f" REFERENCES {t}({c})"
            # required on non-empty table → refuse.
            if _rule_has(field["rules"], "required"):
                if storage is not None and _table_row_count(storage, name) > 0:
                    raise SchemaSpecError(
                        _rebuild_msg(
                            f"cannot add required field {name}.{fname} "
                            f"on non-empty table"
                        )
                    )
            statements.append(
                (f"ALTER TABLE {name} ADD COLUMN {col_sql}", [])
            )
            # Evolution path: enforce required/enum via triggers (no post-hoc CHECK).
            if _rule_has(field["rules"], "required"):
                statements.extend(_required_check_triggers(name, field))
            enum_vals = _rule_enum(field["rules"])
            if enum_vals is not None:
                statements.extend(_enum_check_triggers(name, field, enum_vals))
            if _rule_has(field["rules"], "unique"):
                statements.append((_unique_index_sql(name, fname), []))
            if _rule_has(field["rules"], "immutable_after_create"):
                statements.append((_immutable_trigger_sql(name, fname), []))

        # Object rules: additive only.
        old_or = set(old_obj["object_rules"])
        new_or = set(new_obj["object_rules"])
        for r in old_or - new_or:
            raise SchemaSpecError(
                _rebuild_msg(f"object rule {r!r} removed from {name}")
            )
        for r in new_or - old_or:
            if r == "owner_only_update":
                statements.append((_owner_only_trigger_sql(name), []))
            else:
                raise SchemaSpecError(
                    f"Object {name}: cannot add object rule {r!r} via evolution"
                )

        # Access: additive grants only.
        old_access = set(old_obj["access"])
        new_access = set(new_obj["access"])
        removed = old_access - new_access
        if removed:
            raise SchemaSpecError(
                _rebuild_msg(
                    f"access grants removed from {name}: {sorted(removed)!r}"
                )
            )
        added = sorted(new_access - old_access, key=lambda x: (x[0], x[1]))
        statements.extend(_rbac_inserts(name, added))

    return statements


# ---------------------------------------------------------------------------
# Authoring API
# ---------------------------------------------------------------------------


def get_schema_spec(storage):
    """Return the parsed ``schema_spec`` dict, or ``None`` if absent."""
    raw = storage.get_manifest_item("schema_spec")
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as e:
        raise SchemaSpecError(
            f"manifest schema_spec is not valid JSON: {e}"
        ) from e
    if not isinstance(parsed, dict):
        raise SchemaSpecError(
            f"manifest schema_spec must be a JSON object, got {type(parsed).__name__}"
        )
    return parsed


def verify_schema_spec(storage):
    """Thin wrapper over ``get_manifest_signature_status('schema_spec')``."""
    return storage.get_manifest_signature_status("schema_spec")


def _make_signer(storage, private_key_or_sign_callable):
    """Return ``sign(query, params) -> signature bytes``."""
    if callable(private_key_or_sign_callable):
        return private_key_or_sign_callable

    private_key = private_key_or_sign_callable
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    def sign(query, params):
        next_seq, prev_hash = storage.get_chain_head()
        payload = canonical_payload(
            query, params, next_seq, prev_hash, storage.container_uid
        )
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return sign


def _has_admin(storage):
    row = storage.conn.execute("SELECT COUNT(*) FROM user_roles").fetchone()
    return row is not None and row[0] > 0


def apply_schema_spec(storage, private_key_or_sign_callable, cert_pem, spec):
    """Validate, compile (or evolve), and sign-execute a schema_spec onto *storage*.

    Sequence: validate → plan/compile → execute DDL train through
    ``execute_signed`` → write canonical JSON ``schema_spec`` manifest entry.
    On a fresh container (empty ``user_roles``) the first statement uses
    ``bootstrap_admin`` so the signer becomes admin; subsequent statements and
    already-provisioned containers use ``execute_signed``.

    Evolution supports only additive changes (new objects, new fields, new
    rules/triggers/indexes/access). Non-additive diffs raise
    ``SchemaSpecError`` before any signing (chain head unchanged).
    """
    # 1. Validate the new spec completely first.
    validate_schema_spec(spec)

    existing = get_schema_spec(storage)
    if existing is None:
        statements = compile_schema_spec(spec)
    else:
        # Whole-diff validation before any signing.
        statements = plan_schema_evolution(existing, spec, storage=storage)

    sign = _make_signer(storage, private_key_or_sign_callable)
    bootstrapped = _has_admin(storage)

    for sql, params in statements:
        sig = sign(sql, params)
        if not bootstrapped:
            storage.bootstrap_admin(sql, params, sig, cert_pem)
            bootstrapped = True
        else:
            storage.execute_signed(sql, params, sig, cert_pem)

    # Manifest last: canonical JSON so verify_schema_spec + determinism tests agree.
    manifest_q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
    value = canonical_schema_json(spec)
    params = ["schema_spec", value]
    sig = sign(manifest_q, params)
    if not bootstrapped:
        storage.bootstrap_admin(manifest_q, params, sig, cert_pem)
    else:
        storage.execute_signed(manifest_q, params, sig, cert_pem)

    return statements
