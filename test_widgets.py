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


class _StyleMod:
    Pack = _Pack


def _make_stub_toga():
    return SimpleNamespace(
        MultilineTextInput=_MultilineTextInput,
        style=_StyleMod,
        __name__="fake_toga_for_test_widgets",
    )


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

    assert isinstance(w, _MultilineTextInput)
    assert w.readonly is True
    assert w.value == text
    assert w.style is not None
    # flex=1 on the horizontal axis so the widget fills width and wraps.
    assert getattr(w.style, "flex", None) == 1 or w.style.kwargs.get("flex") == 1
    assert getattr(w.style, "height", None) == 72 or w.style.kwargs.get("height") == 72
    # error kind tints (best-effort)
    color = getattr(w.style, "color", None) or w.style.kwargs.get("color")
    assert color is not None
    print("  [OK] message_widget → readonly MultilineTextInput with flex + height")


def test_message_widget_default_height_and_info_kind():
    from mschf.widgets import message_widget

    toga = _make_stub_toga()
    w = message_widget(toga, "hello")
    assert w.value == "hello"
    assert w.readonly is True
    height = getattr(w.style, "height", None) or w.style.kwargs.get("height")
    assert height == 60
    # info kind: no mandatory tint
    print("  [OK] message_widget defaults (height=60, info)")


def test_set_message_updates_value():
    from mschf.widgets import message_widget, set_message

    toga = _make_stub_toga()
    w = message_widget(toga, "initial")
    set_message(w, "updated long validation error\nline two")
    assert w.value == "updated long validation error\nline two"
    set_message(w, "")
    assert w.value == ""
    set_message(w, None)
    assert w.value == ""
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


def main():
    print("=== test_widgets ===")
    test_import_without_toga()
    test_message_widget_constructs_readonly_multiline()
    test_message_widget_default_height_and_info_kind()
    test_set_message_updates_value()
    test_truncate_for_label()

    assert "toga" not in sys.modules, (
        "test_widgets must stay headless — real toga was imported"
    )
    print("  [OK] toga not in sys.modules")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
