"""Authoring for the "Widget Gallery" demo micro-app.

Builds a signed ``.msf`` whose UI demonstrates every Toga widget available on
this platform, grouped into tabs. Useful as a live reference for the
declarative-UI work: it's the visual catalogue of the widget vocabulary a
manifest-driven micro-app could draw from.

Like ``starter.py``, the UI source lives in ``GALLERY_SOURCE`` and is exec'd
into a non-importable namespace before pickling, so dill serializes it BY
VALUE and the container carries its own code. The module imports no toga at
top level, so authoring/auditing stays CI-safe (toga is only needed at
sandbox render time).
"""
import json
import base64
import os

import dill

from mschf.storage import MSFStorage

# Note (Tree data format, learned the hard way): TreeSource wants a list of
# (data, children) tuples — a list of dicts makes it do dict[0] -> KeyError: 0.

# ImageView needs a real image; embed the committed brand PNG at author time
# (base64 into the code blob) so the container is self-contained. Fall back to
# a 1x1 transparent pixel if the asset is somehow missing.
def _load_logo_b64():
    try:
        res = os.path.join(os.path.dirname(__file__), "resources", "mschf.png")
        with open(res, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
                "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")


GALLERY_SOURCE = '''
def gallery_app(toga, host_api):
    import base64
    import datetime
    from toga.style import Pack as P

    LOGO_B64 = "__LOGO_B64__"

    def heading(text):
        return toga.Label(text, style=P(font_size=13, font_weight="bold", margin_top=12, margin_bottom=2))

    def note(text):
        return toga.Label(text, style=P(font_size=9, color="#666666", margin_bottom=4))

    def tab(*widgets):
        col = toga.Box(style=P(direction="column", margin=12))
        for w in widgets:
            col.add(w)
        return toga.ScrollContainer(horizontal=False, content=col, style=P(flex=1))

    # ----- Text & inputs -----
    inputs = tab(
        heading("Label"), toga.Label("A static text label."),
        heading("TextInput"), toga.TextInput(placeholder="Single-line text", value="editable"),
        heading("MultilineTextInput"),
        toga.MultilineTextInput(value="Multi-line,\\nwrapping,\\nscrollable text.", style=P(height=70)),
        heading("PasswordInput"), toga.PasswordInput(placeholder="hidden characters", value="secret"),
        heading("NumberInput"), toga.NumberInput(min=0, max=100, step=1, value=42),
        heading("Slider"), toga.Slider(min=0, max=100, value=30),
        heading("Switch"), toga.Switch("Toggle me", value=True),
        heading("Selection"), toga.Selection(items=["Alpha", "Bravo", "Charlie"]),
        heading("DateInput"), toga.DateInput(value=datetime.date.today()),
        heading("TimeInput"), toga.TimeInput(value=datetime.time(9, 30)),
    )

    # ----- Buttons, progress, dividers -----
    prog = toga.ProgressBar(max=100, value=60)
    spinner = toga.ActivityIndicator()
    try:
        spinner.start()
    except Exception:
        pass
    controls = tab(
        heading("Button"), toga.Button("Press me", on_press=lambda w: None),
        heading("ProgressBar"), note("determinate, 60%"), prog,
        heading("ActivityIndicator"), note("indeterminate spinner"), spinner,
        heading("Divider"),
        toga.Divider(),
        note("(horizontal rule above)"),
    )

    # ----- Collections -----
    table = toga.Table(
        headings=["Widget", "Category"],
        accessors=("widget", "category"),
        data=[("Button", "control"), ("Table", "collection"), ("Canvas", "graphics")],
        style=P(flex=1, height=140),
    )
    dlist = toga.DetailedList(
        data=[
            {"title": "Signed transaction", "subtitle": "committed to the ledger"},
            {"title": "RBAC rule", "subtitle": "object-level, support role"},
            {"title": "Audit trigger", "subtitle": "stamps current_signer()"},
        ],
        style=P(flex=1, height=140),
    )
    # TreeSource wants a list of (data, children) tuples; children None for leaves.
    tree = toga.Tree(
        columns=["Name", "Kind"],
        data=[
            ({"name": "Inputs", "kind": "group"}, [
                ({"name": "TextInput", "kind": "widget"}, None),
                ({"name": "Slider", "kind": "widget"}, None),
            ]),
            ({"name": "Collections", "kind": "group"}, [
                ({"name": "Table", "kind": "widget"}, None),
                ({"name": "Tree", "kind": "widget"}, None),
            ]),
        ],
        style=P(flex=1, height=160),
    )
    collections = tab(
        heading("Table"), table,
        heading("DetailedList"), dlist,
        heading("Tree"), tree,
    )

    # ----- Graphics -----
    graphics_widgets = [heading("ImageView")]
    try:
        img = toga.Image(data=base64.b64decode(LOGO_B64))
        graphics_widgets.append(toga.ImageView(img, style=P(width=72, height=72)))
    except Exception as e:
        graphics_widgets.append(note("ImageView unavailable: " + str(e)))

    graphics_widgets.append(heading("Canvas"))
    graphics_widgets.append(note("2D drawing: filled rect, ellipse, stroked line"))
    try:
        canvas = toga.Canvas(style=P(width=280, height=120))
        with canvas.Fill(color="#F5821F") as f:
            f.rect(12, 14, 96, 92)
        with canvas.Fill(color="#0d0712") as f:
            f.ellipse(190, 60, 44, 44)
        with canvas.Stroke(color="#888888", line_width=2) as s:
            s.move_to(12, 116)
            s.line_to(268, 116)
        graphics_widgets.append(canvas)
    except Exception as e:
        graphics_widgets.append(note("Canvas unavailable: " + str(e)))
    graphics = tab(*graphics_widgets)

    # ----- Web & Map (Edge WebView2; MapView also needs network) -----
    web_widgets = [heading("WebView"), note("renders HTML via Edge WebView2")]
    try:
        web = toga.WebView(style=P(flex=1, height=180))
        web.set_content("about:blank",
                        "<html><body style='font-family:sans-serif;padding:12px'>"
                        "<h2>WebView</h2><p>Arbitrary HTML, rendered by Edge WebView2.</p>"
                        "</body></html>")
        web_widgets.append(web)
    except Exception as e:
        web_widgets.append(note("WebView unavailable: " + str(e)))

    web_widgets.append(heading("MapView"))
    web_widgets.append(note("OpenStreetMap via Leaflet — needs internet"))
    try:
        mapview = toga.MapView(style=P(flex=1, height=220))
        mapview.location = (40.7128, -74.0060)
        mapview.zoom = 11
        mapview.add_pin(toga.MapPin((40.7128, -74.0060), title="Mischief", subtitle="WebView2 + Leaflet"))
        web_widgets.append(mapview)
    except Exception as e:
        web_widgets.append(note("MapView unavailable: " + str(e)))
    webmap = tab(*web_widgets)

    # ----- Containers -----
    left = toga.Box(style=P(direction="column", margin=8))
    left.add(toga.Label("Left pane"))
    right = toga.Box(style=P(direction="column", margin=8))
    right.add(toga.Label("Right pane"))
    split = toga.SplitContainer(content=[left, right], style=P(height=140))

    tall = toga.Box(style=P(direction="column", margin=8))
    for i in range(20):
        tall.add(toga.Label("Scrollable row " + str(i + 1)))
    scroller = toga.ScrollContainer(content=tall, style=P(height=140))

    containers = tab(
        heading("SplitContainer"), split,
        heading("ScrollContainer"), note("20 rows in a fixed-height scroll region"), scroller,
        heading("Box + OptionContainer"),
        note("demonstrated by this window's own layout and the tabs above"),
    )

    # ----- Assemble -----
    tabs = toga.OptionContainer(
        content=[
            ("Inputs", inputs),
            ("Controls", controls),
            ("Collections", collections),
            ("Graphics", graphics),
            ("Web & Map", webmap),
            ("Containers", containers),
        ],
        style=P(flex=1),
    )

    root = toga.Box(id="widget_gallery", style=P(direction="column", margin=10))
    root.add(toga.Label("Toga Widget Gallery", style=P(font_size=18, font_weight="bold")))
    root.add(toga.Label("Every widget available on this platform, grouped by role.",
                        style=P(font_style="italic", font_size=10, color="#666666", margin_bottom=8)))
    root.add(tabs)
    return root
'''


def _gallery_callable():
    # Token replace (not str.format) — the source is full of {..} dict literals.
    # The base64 is plain [A-Za-z0-9+/=], safe to inject into the string literal.
    ns = {}
    exec(GALLERY_SOURCE.replace("__LOGO_B64__", _load_logo_b64()), ns)
    return ns['gallery_app']


def create_gallery_container(dest_path, identity, ca_cert_path):
    """Author the widget-gallery .msf at dest_path, signed by ``identity``.

    Minimal valid container: bootstrap admin (so the creating identity may open
    it), signed code blob, manifest. No custom tables/RBAC — the gallery is a
    pure widget demo. Passes replay_audit.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(identity.key_path, 'rb') as f:
        key_pem = f.read()
    password = identity.key_passphrase.encode('utf-8') if identity.key_passphrase else None
    private_key = load_pem_private_key(key_pem, password=password)
    cert_pem = identity.cert_pem

    def _mjs(obj):
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
        elif isinstance(obj, (list, tuple)):
            return [_mjs(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: _mjs(v) for k, v in obj.items()}
        return obj

    def sign(query, params):
        payload = json.dumps({"query": query, "params": _mjs(params)}, sort_keys=True).encode('utf-8')
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    if os.path.exists(dest_path):
        raise FileExistsError(f"{dest_path} already exists — not overwriting.")

    db = MSFStorage(dest_path, ca_cert_path=ca_cert_path)
    try:
        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        db.bootstrap_admin(q, ['entry_point', 'main_app'], sign(q, ['entry_point', 'main_app']), cert_pem)

        code_func = _gallery_callable()
        pickled = dill.dumps(code_func)
        q = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
        db.store_code('main_app', code_func, sign(q, ['main_app', pickled]), cert_pem)

        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        for key, value in (('name', 'Widget Gallery'),
                           ('version', '1.0'),
                           ('description', 'Demonstrates every Toga widget available on this platform.')):
            db.set_manifest_item(key, value, sign(q, [key, value]), cert_pem)
    finally:
        db.close()
    return dest_path
