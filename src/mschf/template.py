"""Instantiate a fresh micro-app from a template container.

Templates are **recipes, not replicas**. A byte-copy of an ``.msf`` would be a
replica of the original container (same ``container_uid``, same ledger, original
author remains admin) — payload v3 rejects transplanted genesis by design.
``create_from_template`` therefore authors a **fresh container** and re-signs
the template's *content* (schema, triggers/indexes, role definitions, UI/schema
manifest entries) as new transactions by the creating identity.

v1 lifts structure + UI only — **no app data rows**. Seed/welcome copy belongs
in the declarative ``ui_spec`` (as the starter app does), not in user tables.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from mschf.audit import format_report, replay_audit
from mschf.storage import MSFStorage, canonical_payload

# Manifest keys that describe the app and are safe to carry across instantiate.
# Never lift homing keys — the new app must remain unhomed even when the
# template is a homed replica.
_MANIFEST_LIFT_KEYS = frozenset({"description", "version"})
_MANIFEST_NEVER_LIFT = frozenset({
    "sync_hub_url",
    "sync_hub_cn",
    # Re-set explicitly: name from app_name; ui_spec/schema_spec verified + re-signed.
    "name",
    "ui_spec",
    "schema_spec",
    # Pickle path is refused entirely for templates.
    "entry_point",
})


class TemplateError(Exception):
    """Raised when a template is refused or instantiation cannot proceed."""


def _summarize_audit_failure(report):
    """First failing category + count from a ``replay_audit`` report.

    Used so refusal messages name the actual problem (untrusted signers,
    chain break, table diff, …) rather than a generic catch-all.
    """
    txr = report.get("transactions") or {}
    for label, key in (
        ("untrusted signers", "untrusted_signers"),
        ("invalid signatures", "invalid_signatures"),
        ("chain breaks", "chain_breaks"),
        ("replay anomalies", "replay_anomalies"),
        ("rbac violations", "rbac_violations"),
    ):
        items = txr.get(key) or []
        if items:
            return f"{label} ({len(items)})"

    mismatched = [
        name
        for name, result in (report.get("tables") or {}).items()
        if result.get("status") not in ("match", "skew")
    ]
    if mismatched:
        sample = ", ".join(mismatched[:3])
        more = f" +{len(mismatched) - 3} more" if len(mismatched) > 3 else ""
        return f"table mismatch ({len(mismatched)}: {sample}{more})"

    bad_code = [
        cid
        for cid, st in (report.get("code") or {}).items()
        if not st.get("verified")
    ]
    if bad_code:
        return f"code signature failure ({len(bad_code)})"

    cp = (txr.get("legacy_checkpoint") or {}).get("status")
    if cp == "mismatch":
        return "legacy checkpoint mismatch"

    return "integrity audit failed"


def check_template(path, ca_cert_path=None, trust_dir=None):
    """Cheap eligibility probe for using *path* as a template recipe.

    Safe to call on every workspace ``.msf`` when the New App dialog opens.
    Does **not** run ``replay_audit`` (that remains the authoritative gate
    inside ``create_from_template``). Never raises — garbage / locked /
    non-sqlite input yields ``eligible=False`` with a reason string.

    Returns
    -------
    dict
        ``{"eligible": bool, "reason": str}``
    """
    try:
        if not path or not os.path.isfile(path):
            return {"eligible": False, "reason": "not a valid container"}

        # Read-only probe for a manifest table before opening via MSFStorage
        # (which would CREATE system tables on a random sqlite file).
        try:
            try:
                probe = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
            except sqlite3.Error:
                probe = sqlite3.connect(path)
            try:
                tables = {
                    r[0]
                    for r in probe.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
            finally:
                probe.close()
        except Exception:
            return {"eligible": False, "reason": "not a valid container"}

        if "manifest" not in tables:
            return {"eligible": False, "reason": "not a valid container"}

        storage = MSFStorage(
            path, ca_cert_path=ca_cert_path, trust_dir=trust_dir
        )
        try:
            # Prefer the pickled-code reason over "no declarative spec" so
            # legacy bytecode containers surface the actionable cause first.
            code_count = storage.conn.execute(
                "SELECT COUNT(*) FROM source_code"
            ).fetchone()[0]
            if code_count:
                return {"eligible": False, "reason": "contains pickled code"}

            has_ui = storage.get_manifest_item("ui_spec") is not None
            has_schema = storage.get_manifest_item("schema_spec") is not None
            if not has_ui and not has_schema:
                return {
                    "eligible": False,
                    "reason": "no declarative spec (ui_spec/schema_spec)",
                }

            signers = []
            for key in ("ui_spec", "schema_spec"):
                if storage.get_manifest_item(key) is None:
                    continue
                status = storage.get_manifest_signature_status(key)
                if not status.get("verified"):
                    err = status.get("error") or "not verified"
                    return {
                        "eligible": False,
                        "reason": f"{key} signature unverified: {err}",
                    }
                signer = status.get("signer")
                if signer and signer not in signers:
                    signers.append(signer)

            signer_label = signers[0] if signers else "unknown"
            return {
                "eligible": True,
                "reason": f"declarative, specs verified (signer: {signer_label})",
            }
        finally:
            try:
                storage.close()
            except Exception:
                pass
    except Exception as e:
        msg = str(e).strip() or type(e).__name__
        # Keep the reason short and never raise.
        if "not a database" in msg.lower() or "file is not a database" in msg.lower():
            return {"eligible": False, "reason": "not a valid container"}
        return {"eligible": False, "reason": f"not a valid container ({msg[:80]})"}


def _load_private_key(identity):
    with open(identity.key_path, "rb") as f:
        key_pem = f.read()
    password = (
        identity.key_passphrase.encode("utf-8")
        if getattr(identity, "key_passphrase", None)
        else None
    )
    return load_pem_private_key(key_pem, password=password)


def _make_sign(db, private_key):
    def sign(query, params):
        next_seq, prev_hash = db.get_chain_head()
        payload = canonical_payload(
            query, params, next_seq, prev_hash, db.container_uid
        )
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return sign


def _user_table_names(storage):
    """Non-system user table names from sqlite_master."""
    rows = storage.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return [
        r[0] for r in rows
        if r[0] not in MSFStorage.SYSTEM_TABLES
    ]


def _master_ddl(storage, type_name, user_tables):
    """Return (name, tbl_name, sql) for signed DDL objects on user tables.

    Prefer verbatim ``sqlite_master.sql`` so replay-regex constraints on
    trigger bodies stay identical to the template.
    """
    if not user_tables:
        return []
    placeholders = ",".join("?" for _ in user_tables)
    rows = storage.conn.execute(
        f"SELECT name, tbl_name, sql FROM sqlite_master "
        f"WHERE type=? AND sql IS NOT NULL AND tbl_name IN ({placeholders}) "
        f"AND name NOT LIKE 'sqlite_%' "
        f"ORDER BY name",
        [type_name, *user_tables],
    ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def _existing_master_names(storage, type_name):
    return {
        r[0]
        for r in storage.conn.execute(
            "SELECT name FROM sqlite_master WHERE type=?", (type_name,)
        ).fetchall()
    }


def _verify_template(template):
    """Fail closed: clean ledger, trusted ui_spec/schema_spec, no pickled code."""
    report = replay_audit(template)
    if not report.get("ok"):
        detail = _summarize_audit_failure(report)
        raise TemplateError(
            f"Template failed integrity audit: {detail}. "
            f"Refusing to instantiate.\n{format_report(report)}"
        )

    for key in ("ui_spec", "schema_spec"):
        if template.get_manifest_item(key) is not None:
            status = template.get_manifest_signature_status(key)
            if not status.get("verified"):
                err = status.get("error") or "not verified"
                raise TemplateError(
                    f"Template manifest key '{key}' is not verified ({err}). "
                    "Refusing to instantiate."
                )

    code_count = template.conn.execute(
        "SELECT COUNT(*) FROM source_code"
    ).fetchone()[0]
    if code_count:
        raise TemplateError(
            "Template contains pickled source_code; only declarative "
            "(ui_spec / schema_spec) templates are supported. Refusing to "
            "silently inherit bytecode."
        )


def _lift_rbac_rules(template, dest, sign, cert_pem):
    """Copy role definitions; never copy user_roles (per-deployment)."""
    existing = {
        (r[0], r[1], r[2], r[3])
        for r in dest.conn.execute(
            "SELECT level, target, role, permission FROM rbac_rules"
        ).fetchall()
    }
    rows = template.conn.execute(
        "SELECT level, target, role, permission FROM rbac_rules "
        "ORDER BY id"
    ).fetchall()
    q = "INSERT INTO rbac_rules (level, target, role, permission) VALUES (?, ?, ?, ?)"
    for level, target, role, permission in rows:
        key = (level, target, role, permission)
        if key in existing:
            continue
        params = [level, target, role, permission]
        dest.execute_signed(q, params, sign(q, params), cert_pem)
        existing.add(key)


def _lift_manifest(template, dest, sign, cert_pem, app_name, schema_already_set):
    """Re-sign selected manifest keys; never lift sync_hub_*."""
    q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"

    # name always becomes the new app name.
    dest.set_manifest_item("name", app_name, sign(q, ["name", app_name]), cert_pem)

    ui = template.get_manifest_item("ui_spec")
    if ui is not None:
        dest.set_manifest_item("ui_spec", ui, sign(q, ["ui_spec", ui]), cert_pem)

    if not schema_already_set:
        schema = template.get_manifest_item("schema_spec")
        if schema is not None:
            dest.set_manifest_item(
                "schema_spec", schema, sign(q, ["schema_spec", schema]), cert_pem
            )

    for key in sorted(_MANIFEST_LIFT_KEYS):
        value = template.get_manifest_item(key)
        if value is None:
            continue
        dest.set_manifest_item(key, value, sign(q, [key, value]), cert_pem)


def create_from_template(
    template_path,
    dest_path,
    identity,
    app_name,
    ca_cert_path=None,
    trust_dir=None,
):
    """Author a fresh ``.msf`` from *template_path*, signed by *identity*.

    Templates are recipes, not replicas: the result gets a new ``container_uid``
    and a fresh ledger; the creating identity becomes container admin via
    ``bootstrap_admin``. Content is re-signed as new transactions — structure
    and UI only; **no app data rows** are copied in v1.

    Parameters
    ----------
    template_path :
        Path to an existing ``.msf`` used as the recipe.
    dest_path :
        Destination path for the new container (must not already exist).
    identity :
        Unlocked ``Identity`` (cert_pem, key_path, key_passphrase if encrypted).
    app_name :
        Value written to the new container's ``manifest.name``.
    ca_cert_path, trust_dir :
        Trust-anchor resolution for both template verification and new writes.

    Returns
    -------
    dict
        Summary with ``dest_path``, ``container_uid``, ``app_name``,
        ``creator_cn``, and ``tables``.

    Raises
    ------
    TemplateError
        Template refused (tamper, untrusted, pickled code, missing identity).
    FileExistsError
        *dest_path* already exists.
    """
    if identity is None or not getattr(identity, "is_valid", False):
        raise TemplateError(
            "An active, trusted identity is required to instantiate a template."
        )
    if not app_name or not str(app_name).strip():
        raise TemplateError("app_name is required.")
    app_name = str(app_name).strip()

    if not os.path.isfile(template_path):
        raise TemplateError(f"Template not found: {template_path}")

    if os.path.exists(dest_path):
        raise FileExistsError(
            f"{dest_path} already exists — not overwriting."
        )

    template = MSFStorage(
        template_path, ca_cert_path=ca_cert_path, trust_dir=trust_dir
    )
    try:
        _verify_template(template)
        template_uid = template.container_uid
        user_tables = _user_table_names(template)
        trigger_ddl = _master_ddl(template, "trigger", user_tables)
        index_ddl = _master_ddl(template, "index", user_tables)
        table_sql = {
            name: template.conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone()[0]
            for name in user_tables
        }
        schema_raw = template.get_manifest_item("schema_spec")
        schema_spec = None
        if schema_raw is not None:
            try:
                schema_spec = json.loads(schema_raw)
            except (TypeError, json.JSONDecodeError) as e:
                raise TemplateError(
                    f"Template schema_spec is not valid JSON: {e}"
                ) from e
        # Snapshot rbac + manifest values we need after template may close.
        # (We keep template open until after we finish reading.)
    except Exception:
        template.close()
        raise

    private_key = _load_private_key(identity)
    cert_pem = identity.cert_pem
    dest = None
    try:
        dest = MSFStorage(dest_path, ca_cert_path=ca_cert_path, trust_dir=trust_dir)
        sign = _make_sign(dest, private_key)
        schema_already_set = False

        if schema_spec is not None:
            from mschf.schemaspec import apply_schema_spec

            # Full enforcement train (tables, rule triggers, indexes, access
            # rbac, signed schema_spec manifest). Bootstraps admin when needed.
            apply_schema_spec(dest, private_key, cert_pem, schema_spec)
            schema_already_set = True
        else:
            # No schema_spec: replay CREATE TABLE SQL verbatim as signed DDL.
            bootstrapped = False
            for name in user_tables:
                sql = table_sql.get(name)
                if not sql:
                    continue
                if not bootstrapped:
                    dest.bootstrap_admin(sql, [], sign(sql, []), cert_pem)
                    bootstrapped = True
                else:
                    dest.execute_signed(sql, [], sign(sql, []), cert_pem)
            if not bootstrapped:
                # Structure-less template (UI-only): bootstrap via app name.
                q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
                params = ["name", app_name]
                dest.bootstrap_admin(q, params, sign(q, params), cert_pem)

        # Triggers + indexes on user tables; skip anything schemaspec (or a
        # prior CREATE TABLE UNIQUE) already put on the dest.
        for name, _tbl, sql in trigger_ddl:
            if name in _existing_master_names(dest, "trigger"):
                continue
            dest.execute_signed(sql, [], sign(sql, []), cert_pem)

        for name, _tbl, sql in index_ddl:
            if name in _existing_master_names(dest, "index"):
                continue
            dest.execute_signed(sql, [], sign(sql, []), cert_pem)

        # Any user tables still missing (mixed / non-schema_spec extras).
        dest_tables = set(_user_table_names(dest))
        for name in user_tables:
            if name in dest_tables:
                continue
            sql = table_sql.get(name)
            if sql:
                dest.execute_signed(sql, [], sign(sql, []), cert_pem)

        _lift_rbac_rules(template, dest, sign, cert_pem)
        _lift_manifest(
            template, dest, sign, cert_pem, app_name, schema_already_set
        )

        # Assert no data rows were copied into user tables.
        for name in _user_table_names(dest):
            count = dest.conn.execute(
                f'SELECT COUNT(*) FROM "{name}"'
            ).fetchone()[0]
            if count:
                raise TemplateError(
                    f"Internal error: user table {name!r} has {count} rows after "
                    "instantiate (v1 must not copy app data)."
                )

        summary = {
            "dest_path": dest_path,
            "container_uid": dest.container_uid,
            "template_uid": template_uid,
            "app_name": app_name,
            "creator_cn": identity.cn,
            "tables": _user_table_names(dest),
        }
        dest.close()
        dest = None
        return summary
    except Exception:
        if dest is not None:
            try:
                dest.close()
            except Exception:
                pass
        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except OSError:
                pass
        raise
    finally:
        try:
            template.close()
        except Exception:
            pass


def safe_msf_filename(app_name):
    """Filesystem-safe ``.msf`` basename stem from an app name."""
    stem = re.sub(r"[^\w\-]+", "_", app_name.strip(), flags=re.UNICODE)
    stem = stem.strip("_") or "new_app"
    return f"{stem}.msf"
