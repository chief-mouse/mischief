"""Headless tests for mschf.widgets (shared wrapping message widget).

Uses a stub toga namespace — no real GUI toolkit required. Ends by asserting
that the real ``toga`` package was never imported.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath("src"))

# --- stub toga (never the real package) ------------------------------------


class _Pack:
    def __init__(self, **kwargs):
        self.kwargs = dict(kwargs)
        for k, v in kwargs.items():
            setattr(self, k, v)


class _MultilineTextInput:
    def __init__(self, *args, readonly=False, value="", style=None, **kwargs):
        self.readonly = readonly
        self.value = value
        self.style = style
        self.kwargs = kwargs


class _Label:
    def __init__(self, text="", style=None, **kwargs):
        self.text = text
        self.style = style
        self.kwargs = kwargs


class _Box:
    def __init__(self, *args, style=None, children=None, **kwargs):
        self.style = style
        self.children = list(children) if children else []
        self.kwargs = kwargs

    def add(self, child):
        self.children.append(child)

    def remove(self, child):
        self.children.remove(child)

    def clear(self):
        self.children.clear()


class _StyleMod:
    Pack = _Pack


def _make_stub_toga():
    return SimpleNamespace(
        MultilineTextInput=_MultilineTextInput,
        Box=_Box,
        Label=_Label,
        style=_StyleMod,
        __name__="fake_toga_for_test_widgets",
    )


def _inner(w):
    """Return the MultilineTextInput child of a message container, or None."""
    children = getattr(w, "children", None) or []
    for c in children:
        if isinstance(c, _MultilineTextInput):
            return c
    return None


def _is_collapsed(w):
    """Empty message area: no input child and zero-height (or no reserved height)."""
    if _inner(w) is not None:
        return False
    height = getattr(w.style, "height", None)
    if height is None and hasattr(w.style, "kwargs"):
        height = w.style.kwargs.get("height")
    # Collapsed = height 0 (explicit) — primary acceptance for visually-absent.
    return height == 0


def test_import_without_toga():
    # Ensure clean slate for the real package name.
    sys.modules.pop("toga", None)
    import mschf.widgets as w  # noqa: F401

    assert "toga" not in sys.modules, "widgets.py must not import toga at module level"
    print("  [OK] mschf.widgets imports without toga")


def test_message_widget_constructs_readonly_multiline():
    from mschf.widgets import message_widget

    toga = _make_stub_toga()
    text = "Template contains pickled source_code; refuse instantiate."
    w = message_widget(toga, text, kind="error", min_height=72)

    assert isinstance(w, _Box)
    inp = _inner(w)
    assert inp is not None
    assert isinstance(inp, _MultilineTextInput)
    assert inp.readonly is True
    assert inp.value == text
    assert inp.style is not None
    # flex=1 on the horizontal axis so the widget fills width and wraps.
    assert getattr(inp.style, "flex", None) == 1 or inp.style.kwargs.get("flex") == 1
    assert getattr(inp.style, "height", None) == 72 or inp.style.kwargs.get("height") == 72
    # error kind tints (best-effort) on the *input*, not an empty shell
    color = getattr(inp.style, "color", None) or inp.style.kwargs.get("color")
    assert color is not None
    bg = getattr(inp.style, "background_color", None) or inp.style.kwargs.get(
        "background_color"
    )
    assert bg is not None
    print("  [OK] message_widget → Box + readonly MultilineTextInput with flex + height")


def test_message_widget_default_height_and_info_kind():
    from mschf.widgets import message_widget

    toga = _make_stub_toga()
    w = message_widget(toga, "hello")
    inp = _inner(w)
    assert inp is not None
    assert inp.value == "hello"
    assert inp.readonly is True
    height = getattr(inp.style, "height", None) or inp.style.kwargs.get("height")
    assert height == 60
    # info kind: no mandatory tint
    color = getattr(inp.style, "color", None) or (
        inp.style.kwargs.get("color") if hasattr(inp.style, "kwargs") else None
    )
    assert color is None
    print("  [OK] message_widget defaults (height=60, info)")


def test_message_widget_empty_starts_collapsed():
    """Empty/None initial text → no child, zero height, no error tint."""
    from mschf.widgets import message_widget

    toga = _make_stub_toga()
    for initial in ("", None):
        w = message_widget(toga, initial, kind="error", min_height=72)
        assert isinstance(w, _Box)
        assert _is_collapsed(w), f"expected collapsed for initial={initial!r}"
        assert _inner(w) is None
        # Container itself must not carry the error pink tint when empty.
        bg = getattr(w.style, "background_color", None)
        if bg is None and hasattr(w.style, "kwargs"):
            bg = w.style.kwargs.get("background_color")
        assert bg is None or bg in ("", None)
    print("  [OK] empty/None initial → collapsed (no child, height=0, no tint)")


def test_set_message_expand_collapse_roundtrip():
    """set_message expands with tint; empty collapses; round-trip stable."""
    from mschf.widgets import message_widget, set_message

    toga = _make_stub_toga()
    w = message_widget(toga, "", kind="error", min_height=72)
    assert _is_collapsed(w)

    set_message(w, "boom")
    assert not _is_collapsed(w)
    inp = _inner(w)
    assert inp is not None
    assert inp.value == "boom"
    color = getattr(inp.style, "color", None) or inp.style.kwargs.get("color")
    assert color is not None
    bg = getattr(inp.style, "background_color", None) or inp.style.kwargs.get(
        "background_color"
    )
    assert bg is not None

    set_message(w, "")
    assert _is_collapsed(w)
    assert _inner(w) is None

    # Round-trip again
    set_message(w, "again")
    assert _inner(w) is not None and _inner(w).value == "again"
    set_message(w, None)
    assert _is_collapsed(w)

    # Idempotent collapse / expand
    set_message(w, "")
    assert _is_collapsed(w)
    set_message(w, "stable")
    set_message(w, "stable")
    assert _inner(w) is not None and _inner(w).value == "stable"
    print("  [OK] set_message expand/collapse round-trip + idempotent")


def test_set_message_updates_value():
    from mschf.widgets import message_widget, set_message

    toga = _make_stub_toga()
    w = message_widget(toga, "initial")
    set_message(w, "updated long validation error\nline two")
    assert _inner(w).value == "updated long validation error\nline two"
    set_message(w, "")
    assert _is_collapsed(w)
    set_message(w, None)
    assert _is_collapsed(w)
    print("  [OK] set_message updates / clears value")


def test_truncate_for_label():
    from mschf.widgets import truncate_for_label

    assert truncate_for_label("short") == "short"
    assert truncate_for_label(None) == ""

    multi = "line one\nline two\r\nline three"
    out = truncate_for_label(multi, max_chars=200)
    assert "\n" not in out and "\r" not in out
    assert "line one" in out and "line two" in out

    long = "x" * 200
    trunc = truncate_for_label(long, max_chars=50)
    assert len(trunc) == 50
    assert trunc.endswith("…")
    assert "\n" not in trunc

    # Whitespace collapsed to single line
    assert truncate_for_label("  a   b  \n c ") == "a b c"

    # Tight max
    assert truncate_for_label("hello", max_chars=1) == "…"
    assert truncate_for_label("hello", max_chars=0) == ""
    print("  [OK] truncate_for_label single-line + ellipsis, never newlines")


def test_label_factory_decision_rule():
    """short → Label; long/newline → wrapping Box; force_single_line truncates."""
    from mschf.widgets import label, truncate_for_label

    toga = _make_stub_toga()

    short = label(toga, "Hello")
    assert isinstance(short, _Label), type(short)
    assert short.text == "Hello"

    exactly_80 = "x" * 80
    w80 = label(toga, exactly_80)
    assert isinstance(w80, _Label)
    assert w80.text == exactly_80

    long = "y" * 81
    wrapped = label(toga, long)
    assert isinstance(wrapped, _Box), type(wrapped)
    assert not isinstance(wrapped, _Label)
    inp = _inner(wrapped)
    assert inp is not None and isinstance(inp, _MultilineTextInput)
    assert inp.readonly is True
    assert inp.value == long
    # Content wrap: no error/warning tint
    color = getattr(inp.style, "color", None) or (
        inp.style.kwargs.get("color") if hasattr(inp.style, "kwargs") else None
    )
    assert color is None

    with_nl = label(toga, "line one\nline two")
    assert isinstance(with_nl, _Box)
    assert _inner(with_nl).value == "line one\nline two"

    # force_single_line always Label + truncate
    forced = label(toga, "a" * 200, force_single_line=True)
    assert isinstance(forced, _Label)
    assert forced.text == truncate_for_label("a" * 200)
    assert forced.text.endswith("…")

    forced_nl = label(toga, "one\ntwo\nthree", force_single_line=True)
    assert isinstance(forced_nl, _Label)
    assert "\n" not in forced_nl.text
    print("  [OK] label() decision rule (short/long/newline/force_single_line)")


def test_label_style_passthrough():
    from mschf.widgets import label

    toga = _make_stub_toga()
    style = _Pack(margin=8, font_weight="bold", font_size=14)

    short = label(toga, "caption", style=style)
    assert short.style is style

    long = label(toga, "z" * 100, style=style)
    assert isinstance(long, _Box)
    assert long.style is style
    print("  [OK] label() style passthrough (Label + wrapping)")


def main():
    print("=== test_widgets ===")
    test_import_without_toga()
    test_message_widget_constructs_readonly_multiline()
    test_message_widget_default_height_and_info_kind()
    test_message_widget_empty_starts_collapsed()
    test_set_message_expand_collapse_roundtrip()
    test_set_message_updates_value()
    test_truncate_for_label()
    test_label_factory_decision_rule()
    test_label_style_passthrough()

    assert "toga" not in sys.modules, (
        "test_widgets must stay headless — real toga was imported"
    )
    print("  [OK] toga not in sys.modules")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
