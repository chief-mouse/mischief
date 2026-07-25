"""Shared GUI widgets that stay usable without importing toga at module level.

``toga`` is always passed as the first argument (same pattern as
``declarative.py``) so headless tests and CI can import this module without
the GUI toolkit installed.
"""
from __future__ import annotations

import importlib


def _pack_cls(toga):
    """Resolve ``Pack`` from a passed-in toga module (lazy style submodule)."""
    style_mod = getattr(toga, "style", None)
    if style_mod is None:
        style_mod = importlib.import_module(f"{toga.__name__}.style")
    return style_mod.Pack


def message_widget(toga, text, *, kind="info", min_height=None):
    """Display potentially-long text without stretching the parent horizontally.

    Uses a read-only ``MultilineTextInput`` with ``flex=1`` so the widget fills
    available width and wraps internally. Height is a modest fixed few-line
    size (scrollable beyond that); pass ``min_height`` to override.

    ``kind`` may tint text/background best-effort ('error' → red-ish). Wrapping
    is the requirement; cosmetic styling is platform-tolerant.
    """
    Pack = _pack_cls(toga)
    height = int(min_height) if min_height is not None else 60
    style_kw = {
        "flex": 1,
        "height": height,
        "margin": 4,
    }
    if kind == "error":
        style_kw["color"] = "#b91c1c"
        style_kw["background_color"] = "#fef2f2"
    elif kind == "warning":
        style_kw["color"] = "#92400e"
        style_kw["background_color"] = "#fffbeb"
    # else info / default: no tint

    widget = toga.MultilineTextInput(
        readonly=True,
        style=Pack(**style_kw),
    )
    widget.value = "" if text is None else str(text)
    return widget


def set_message(widget, text):
    """Update a ``message_widget`` value in place (empty string is fine)."""
    widget.value = "" if text is None else str(text)


def truncate_for_label(text, max_chars=120):
    """Single-line, ellipsized text for genuine one-line Labels.

    Collapses newlines/whitespace, never emits a newline. Use when a Label is
    the right control but the input length is unbounded (status lines, etc.).
    """
    if text is None:
        s = ""
    else:
        s = str(text)
    # Single line: newlines → spaces, then collapse runs of whitespace.
    s = " ".join(s.split())
    try:
        n = int(max_chars)
    except (TypeError, ValueError):
        n = 120
    if n < 1:
        return ""
    if len(s) <= n:
        return s
    if n == 1:
        return "…"
    return s[: n - 1] + "…"
