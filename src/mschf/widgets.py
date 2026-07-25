"""Shared GUI widgets that stay usable without importing toga at module level.

``toga`` is always passed as the first argument (same pattern as
``declarative.py``) so headless tests and CI can import this module without
the GUI toolkit installed.
"""
from __future__ import annotations

import importlib

# Private marker stashed on the container returned by message_widget.
_MSG_META = "_mschf_message_meta"

# Private marker stashed on the container returned by prose_area.
_PROSE_META = "_mschf_prose_meta"

# Single-line Label ceiling for :func:`label` (chars, inclusive).
_LABEL_SINGLE_LINE_MAX = 80


def _pack_cls(toga):
    """Resolve ``Pack`` from a passed-in toga module (lazy style submodule)."""
    style_mod = getattr(toga, "style", None)
    if style_mod is None:
        style_mod = importlib.import_module(f"{toga.__name__}.style")
    return style_mod.Pack


def _input_style_kw(kind, height):
    """Style kwargs for the inner MultilineTextInput (tint only when expanded)."""
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
    return style_kw


def _make_readonly_input(toga, text, *, height, kind=None):
    """Shared inner read-only MultilineTextInput (no tint when kind is None/info)."""
    Pack = _pack_cls(toga)
    style_kw = _input_style_kw(kind if kind else "info", height)
    inp = toga.MultilineTextInput(
        readonly=True,
        style=Pack(**style_kw),
    )
    inp.value = "" if text is None else str(text)
    return inp


def _collapse_container(container):
    """Make the message area occupy no visual space (no reserved height)."""
    style = getattr(container, "style", None)
    if style is None:
        return
    for prop, val in (("height", 0), ("flex", 0), ("margin", 0)):
        try:
            setattr(style, prop, val)
        except Exception:
            pass


def _expand_container(container):
    """Let the container grow with its child input."""
    style = getattr(container, "style", None)
    if style is None:
        return
    # 'none' is Travertino's unset height — child dictates natural size.
    for prop, val in (("height", "none"), ("flex", 1), ("margin", 0)):
        try:
            setattr(style, prop, val)
        except Exception:
            pass


def _remove_child(container, child):
    """Best-effort remove of the inner input (toga Box.remove / clear)."""
    if child is None:
        return
    try:
        container.remove(child)
        return
    except Exception:
        pass
    try:
        container.clear()
    except Exception:
        pass


def _enable_native_wrap(widget, max_width_px=900):
    """Best-effort platform-native text wrap on a real ``toga.Label``.

    **WinForms (primary target):** via the widget's native handle
    (``widget._impl.native``), set ``AutoSize = True`` and
    ``MaximumSize = System.Drawing.Size(max_width_px, 0)`` so the native
    Label wraps at the width cap and grows vertically.

    The native handle may not exist until the widget is realized. This helper
    attempts once at construction (same pattern as ``app.py`` WinForms
    tweaks); if ``_impl`` / ``native`` is absent the call is a silent no-op.
    There is no cheap cross-backend "on realize" hook worth attaching here.

    Secondary backends (GTK/Cocoa/dummy/stub toga in tests): any missing
    attribute or import fails closed into the broad ``except`` — caller keeps
    an unwrapped-but-styled Label. Never raises; never falls back to an input.
    """
    try:
        impl = getattr(widget, "_impl", None)
        if impl is None:
            return
        native = getattr(impl, "native", None)
        if native is None:
            return
        max_w = int(max_width_px)
        # Import/System.Drawing only inside the guarded block (pythonnet/WinForms).
        from System.Drawing import Size

        native.AutoSize = True
        native.MaximumSize = Size(max_w, 0)
    except Exception:
        pass


def message_widget(toga, text, *, kind="info", min_height=None):
    """Display potentially-long text without stretching the parent horizontally.

    Returns a thin container ``Box``. When *text* is empty/None the box is
    **collapsed** (no child, height 0, no tint) so it occupies no visual space
    — critical on WinForms where an empty MultilineTextInput still paints its
    background. When a message is present, a read-only ``MultilineTextInput``
    child is added with ``flex=1`` so it fills available width and wraps.

    Height is a modest fixed few-line size (scrollable beyond that); pass
    ``min_height`` to override.

    ``kind`` may tint text/background best-effort ('error' → red-ish) **only
    while a message is shown**. Wrapping is the requirement; cosmetic styling
    is platform-tolerant.
    """
    Pack = _pack_cls(toga)
    height = int(min_height) if min_height is not None else 60

    # Start collapsed: zero height, no children, no tint on the container.
    container = toga.Box(
        style=Pack(direction="column", height=0, flex=0, margin=0),
    )
    setattr(
        container,
        _MSG_META,
        {
            "toga": toga,
            "kind": kind,
            "height": height,
            "input": None,
        },
    )
    set_message(container, text)
    return container


def set_message(widget, text):
    """Update a ``message_widget`` in place.

    Non-empty *text* expands the area (adds the inner input if needed) and
    applies the widget's ``kind`` tint. Empty/None fully collapses it (removes
    the child, height 0, no tint). Idempotent either direction.
    """
    meta = getattr(widget, _MSG_META, None)
    if meta is None:
        # Not a message_widget container — best-effort value write for tests /
        # accidental direct use of a MultilineTextInput.
        if hasattr(widget, "value"):
            widget.value = "" if text is None else str(text)
        return

    text_s = "" if text is None else str(text)
    toga = meta["toga"]
    kind = meta["kind"]
    height = meta["height"]
    inp = meta["input"]

    if not text_s:
        if inp is not None:
            _remove_child(widget, inp)
            meta["input"] = None
        _collapse_container(widget)
        return

    if inp is None:
        inp = _make_readonly_input(toga, text_s, height=height, kind=kind)
        meta["input"] = inp
        widget.add(inp)
    else:
        inp.value = text_s
    _expand_container(widget)


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


def prose_area(toga):
    """Thin container ``Box`` for static informational prose (wrapping labels).

    Unlike :func:`message_widget` this never uses a MultilineTextInput and
    never applies a tint — pure label text. Start empty (no child, no reserved
    space); populate with :func:`set_prose`.
    """
    Pack = _pack_cls(toga)
    container = toga.Box(
        style=Pack(direction="column", margin=0),
    )
    setattr(container, _PROSE_META, {"child": None})
    return container


def set_prose(area, toga, text):
    """Update a :func:`prose_area` in place.

    Non-empty *text* rebuilds the area's single child via :func:`label`
    (long / multi-line text gets native wrap). Empty/None removes the child
    entirely so the area occupies no visual space. Never tints. Idempotent
    either direction.
    """
    meta = getattr(area, _PROSE_META, None)
    text_s = "" if text is None else str(text)

    child = None
    if meta is not None:
        child = meta.get("child")
    if child is None:
        children = getattr(area, "children", None) or []
        if children:
            child = children[0]

    if not text_s:
        if child is not None:
            _remove_child(area, child)
        if meta is not None:
            meta["child"] = None
        return

    # Always rebuild so long-text wrap path re-runs and text is current.
    if child is not None:
        _remove_child(area, child)
    new_child = label(toga, text_s)
    area.add(new_child)
    if meta is not None:
        meta["child"] = new_child


def label(toga, text, *, style=None, force_single_line=False, max_width=900):
    """THE way to make a text label anywhere in this codebase.

    Decision rule:

    - ``force_single_line=True`` → real ``toga.Label`` with
      :func:`truncate_for_label` applied to *text*.
    - else text ≤ 80 chars AND no newline → real ``toga.Label`` verbatim.
    - else → real ``toga.Label`` with *style* applied verbatim (bold /
      font_size / color work), plus a best-effort platform-native wrap
      constraint via :func:`_enable_native_wrap` (WinForms
      ``MaximumSize`` + ``AutoSize``; silent no-op elsewhere).

    *style* passes through to the Label. *max_width* (px, default 900) is the
    native wrap cap when the long-text branch runs. Returns the widget.
    ``toga`` is passed in so this stays import-safe headless.
    """
    Pack = _pack_cls(toga)
    text_s = "" if text is None else str(text)
    if style is None:
        style = Pack()

    if force_single_line:
        return toga.Label(truncate_for_label(text_s), style=style)

    has_newline = ("\n" in text_s) or ("\r" in text_s)
    if len(text_s) <= _LABEL_SINGLE_LINE_MAX and not has_newline:
        return toga.Label(text_s, style=style)

    # Long / multi-line prose: real Label (keeps Pack styling) + native wrap.
    widget = toga.Label(text_s, style=style)
    _enable_native_wrap(widget, max_width)
    return widget
