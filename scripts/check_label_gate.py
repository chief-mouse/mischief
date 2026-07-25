#!/usr/bin/env python3
"""CI gate: raw toga.Label construction is forbidden outside mschf.widgets.

Scans ``src/mschf/**/*.py`` for:
  * ``toga.Label(...)`` attribute calls
  * ``Label(...)`` when Label was imported from toga

Exit 0 when clean; exit 1 listing offenders. Stdlib only.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path


def _is_widgets_module(path: Path) -> bool:
    return path.name == "widgets.py" and path.parent.name == "mschf"


def _label_imported_from_toga(tree: ast.AST) -> set[str]:
    """Names bound to Label via ``from toga import Label`` / ``from toga import X as Y``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module != "toga":
            continue
        for alias in node.names or []:
            if alias.name == "Label":
                names.add(alias.asname or "Label")
    return names


def find_offenders(path: Path, source: str) -> list[str]:
    """Return human-readable offender lines for one file."""
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        return [f"{path}: syntax error, cannot scan: {e}"]

    label_names = _label_imported_from_toga(tree)
    hits: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # toga.Label(...)
        if isinstance(func, ast.Attribute) and func.attr == "Label":
            if isinstance(func.value, ast.Name) and func.value.id == "toga":
                hits.append(f"{path}:{node.lineno}: toga.Label(...)")
                continue
        # Label(...) after from toga import Label
        if isinstance(func, ast.Name) and func.id in label_names:
            hits.append(f"{path}:{node.lineno}: {func.id}(...) imported from toga")

    return hits


def scan(root: Path) -> list[str]:
    offenders: list[str] = []
    if not root.is_dir():
        return [f"scan root missing: {root}"]
    for path in sorted(root.rglob("*.py")):
        if _is_widgets_module(path):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as e:
            offenders.append(f"{path}: read error: {e}")
            continue
        offenders.extend(find_offenders(path, source))
    return offenders


def _self_test() -> None:
    """One-line smoke: detect both call forms; allow widgets path."""
    bad = "import toga\nx = toga.Label('hi')\n"
    assert find_offenders(Path("fake.py"), bad), "should flag toga.Label"
    bad2 = "from toga import Label\nx = Label('hi')\n"
    assert find_offenders(Path("fake.py"), bad2), "should flag imported Label"
    good = "from mschf.widgets import label\n"
    assert not find_offenders(Path("fake.py"), good)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["--self-test"]:
        _self_test()
        print("check_label_gate self-test OK")
        return 0

    # Repo root = parent of scripts/
    here = Path(__file__).resolve().parent
    repo = here.parent
    root = repo / "src" / "mschf"
    offenders = scan(root)
    if offenders:
        print("Label factory gate FAILED — raw toga.Label outside widgets.py:")
        for line in offenders:
            print(f"  {line}")
        print("Use mschf.widgets.label(toga, text, ...) instead.")
        return 1
    print(f"Label factory gate OK ({root.as_posix()}: no raw toga.Label)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
