"""kiyoo-range — the interactive front door onto every lab: one app, one
page per category (all 23 kiyooo ships), each with a live-proxied view of
the real decoy plus a "fetch live evidence" button that hits it server-side
and renders the raw response. Not a link list — click through it like a
vulnerable machine.

Standalone on purpose, like the other labs: no import of the `kiyooo`
package, just fastapi/uvicorn/httpx.
"""

from __future__ import annotations

import html

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .catalog import BY_SLUG, CATEGORIES, SECTIONS, Category
from .evidence import fetch
from .proxy import proxy as proxy_request

app = FastAPI(title="kiyoo-range", docs_url=None, redoc_url=None)

_LAB_NOTICE = (
    "kiyoo-range is the interactive index for every kiyooo demo lab — all "
    "content it links to or serves directly is synthetic, decoy-grade, "
    "never exploit-grade. See each lab's own README for detail."
)

_SEVERITY_COLOR = {
    "critical": "#fb4f6d",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low"]

_CSS = """
:root {
  color-scheme: dark;
  --bg: #0a0d14;
  --surface: #11151f;
  --surface-2: #161b28;
  --border: #232a3a;
  --text: #e7eaf2;
  --text-2: #99a2b8;
  --text-3: #626b82;
  --accent: #5b8cff;
  --accent-soft: rgba(91, 140, 255, 0.12);
  --mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  --sans: -apple-system, "Segoe UI", system-ui, sans-serif;
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0; font-family: var(--sans); background: var(--bg); color: var(--text);
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; }
code {
  font-family: var(--mono); background: var(--surface-2); border: 1px solid var(--border);
  border-radius: 4px; padding: 0.1em 0.4em; font-size: 0.9em; color: #c7d0e8;
}

.topbar {
  height: 58px; display: flex; align-items: center; justify-content: space-between;
  padding: 0 1.5em; border-bottom: 1px solid var(--border); background: var(--surface);
  position: sticky; top: 0; z-index: 20;
}
.brand { display: flex; align-items: center; gap: 0.6em; text-decoration: none; }
.brand-mark {
  width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center;
  justify-content: center; font-weight: 800; font-size: 0.95em; color: #0a0d14;
  background: linear-gradient(135deg, #7fa8ff, var(--accent));
}
.brand-text { font-weight: 700; font-size: 1.05em; letter-spacing: -0.01em; }
.brand-text .accent { color: var(--accent); }
.topbar-meta { display: flex; align-items: center; gap: 0.5em; }
.pill {
  font-family: var(--mono); font-size: 0.72em; padding: 0.35em 0.7em; border-radius: 999px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--text-2);
}
.pill-live { color: #6ee7a8; border-color: rgba(110, 231, 168, 0.35); }
.pill-live::before {
  content: ""; display: inline-block; width: 6px; height: 6px; border-radius: 50%;
  background: #6ee7a8; margin-right: 0.5em; box-shadow: 0 0 6px #6ee7a8;
}

.layout { display: flex; align-items: flex-start; }
nav {
  width: 268px; flex-shrink: 0; padding: 1.1em 0.8em 2em;
  border-right: 1px solid var(--border); position: sticky; top: 58px;
  height: calc(100vh - 58px); overflow-y: auto;
}
nav .section-label {
  font-size: 0.7em; text-transform: uppercase; letter-spacing: 0.07em;
  color: var(--text-3); margin: 1.3em 0.6em 0.4em; font-weight: 700;
}
nav .section-label:first-child { margin-top: 0.3em; }
nav a {
  display: flex; align-items: center; gap: 0.55em; color: var(--text-2); text-decoration: none;
  padding: 0.4em 0.6em; border-radius: 6px; font-size: 0.88em; line-height: 1.3;
}
nav a .dot {
  width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
  background: var(--sev, var(--text-3));
}
nav a:hover { background: var(--surface-2); color: var(--text); }
nav a.active { background: var(--accent-soft); color: #cddcff; font-weight: 600; }

main { flex: 1; min-width: 0; padding: 2.2em 2.6em 4em; max-width: 1080px; }

.hero h1 { margin: 0 0 0.25em; font-size: 1.85em; letter-spacing: -0.02em; }
.hero .lede { color: var(--text-2); max-width: 640px; line-height: 1.6; margin: 0 0 1.4em; }
.stats { display: flex; gap: 0.7em; flex-wrap: wrap; margin-bottom: 2em; }
.stat {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 0.75em 1.1em; min-width: 104px;
}
.stat .n {
  font-size: 1.5em; font-weight: 700; font-variant-numeric: tabular-nums;
  color: var(--sev, var(--text));
}
.stat .l {
  font-size: 0.7em; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-3);
}

h2.section-title {
  font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-2);
  margin: 2.2em 0 0.8em; padding-bottom: 0.5em; border-bottom: 1px solid var(--border);
}
h2.section-title .count {
  color: var(--text-3); font-weight: 400; text-transform: none; letter-spacing: 0;
}

.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(258px, 1fr)); gap: 0.85em; }
.card {
  position: relative; background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 1em 1.1em 1em 1.3em; text-decoration: none; color: inherit;
  display: block; transition: transform 0.12s ease, border-color 0.12s ease, box-shadow 0.12s ease;
  overflow: hidden;
}
.card::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--sev);
}
.card:hover {
  transform: translateY(-2px); border-color: var(--sev);
  box-shadow: 0 8px 24px -12px var(--sev), 0 0 0 1px var(--sev) inset;
}
.card h3 { margin: 0.5em 0 0.35em; font-size: 1em; letter-spacing: -0.005em; }
.card p { margin: 0; color: var(--text-2); font-size: 0.85em; line-height: 1.5; }

.sev {
  display: inline-flex; align-items: center; gap: 0.45em; font-size: 0.72em; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.05em; color: var(--sev);
}
.sev::before {
  content: ""; width: 7px; height: 7px; border-radius: 50%; background: var(--sev);
  box-shadow: 0 0 7px var(--sev);
}

.crumb { font-size: 0.85em; color: var(--text-3); text-decoration: none; }
.crumb:hover { color: var(--text-2); }
.detail-head {
  display: flex; align-items: center; gap: 0.8em; margin: 0.6em 0 0.3em; flex-wrap: wrap;
}
.detail-head h1 { margin: 0; font-size: 1.5em; letter-spacing: -0.015em; }
.summary {
  color: var(--text-2); font-size: 1em; line-height: 1.6; max-width: 640px; margin: 0.4em 0 0;
}
.source-line {
  margin: 0.9em 0 0; font-size: 0.85em; color: var(--text-3);
  display: flex; gap: 0.5em; align-items: baseline;
}
.source-line b { color: var(--text-2); font-weight: 600; }

.note {
  background: var(--accent-soft); border: 1px solid rgba(91, 140, 255, 0.3); color: #b9cdff;
  padding: 0.75em 1em; margin: 1.1em 0; border-radius: 8px; font-size: 0.88em; line-height: 1.5;
}

h2.block-title {
  font-size: 0.95em; color: var(--text-2); margin: 2em 0 0.5em; letter-spacing: 0.01em;
}

.browser-frame {
  border: 1px solid var(--border); border-radius: 10px; overflow: hidden; background: #fff;
}
.browser-frame .bar {
  background: var(--surface-2); padding: 0.55em 0.8em; display: flex; align-items: center;
  gap: 0.6em; border-bottom: 1px solid var(--border);
}
.browser-frame .dots { display: flex; gap: 0.32em; }
.browser-frame .dots span { width: 9px; height: 9px; border-radius: 50%; display: block; }
.browser-frame .url {
  flex: 1; font-family: var(--mono); font-size: 0.76em; color: var(--text-2);
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 0.3em 0.7em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
iframe.live-view { display: block; width: 100%; height: 520px; border: 0; background: #fff; }

.terminal {
  background: #05070a; border: 1px solid var(--border); border-radius: 10px; overflow: hidden;
}
.terminal .bar {
  display: flex; align-items: center; justify-content: space-between; padding: 0.55em 0.9em;
  background: var(--surface); border-bottom: 1px solid var(--border);
}
.terminal .bar .label { font-family: var(--mono); font-size: 0.75em; color: var(--text-3); }
.terminal pre {
  margin: 0; padding: 1.1em; font-family: var(--mono); font-size: 0.82em; line-height: 1.55;
  overflow-x: auto; white-space: pre-wrap; word-break: break-word; color: #d6dcec;
}
.terminal .err { color: #ff8397; }

button {
  background: var(--accent); color: #06101f; border: none; padding: 0.5em 1.05em;
  border-radius: 7px; cursor: pointer; font-size: 0.85em; font-weight: 600;
  transition: background 0.12s ease, transform 0.05s ease;
}
button:hover { background: #7ba0ff; }
button:active { transform: translateY(1px); }

footer.lab-footer {
  margin-top: 3em; padding-top: 1.2em; border-top: 1px solid var(--border);
  color: var(--text-3); font-size: 0.78em; line-height: 1.6;
}

@media (max-width: 860px) {
  .layout { flex-direction: column; }
  nav {
    width: 100%; height: auto; position: static;
    border-right: none; border-bottom: 1px solid var(--border);
  }
  main { padding: 1.6em 1.2em 3em; }
}
"""


def _sev_badge(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev, "#9ca3af")
    return f'<span class="sev" style="--sev:{color}">{html.escape(sev)}</span>'


def _nav_link(cat: Category, current: str) -> str:
    color = _SEVERITY_COLOR.get(cat.severity, "#9ca3af")
    active = " active" if cat.slug == current else ""
    return (
        f'<a class="nav-link{active}" style="--sev:{color}" href="/category/{cat.slug}">'
        f'<span class="dot"></span>{html.escape(cat.name)}</a>'
    )


def _nav(current: str = "") -> str:
    parts = []
    for section in SECTIONS:
        cats = [c for c in CATEGORIES if c.section == section]
        parts.append(f'<div class="section-label">{html.escape(section)}</div>')
        parts.extend(_nav_link(c, current) for c in cats)
    return "\n".join(parts)


def _shell(body: str, current: str = "") -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kiyoo-range</title>
<style>{_CSS}</style></head>
<body>
<header class="topbar">
  <a class="brand" href="/">
    <span class="brand-mark">K</span>
    <span class="brand-text">kiyoo<span class="accent">range</span></span>
  </a>
  <div class="topbar-meta">
    <span class="pill">{len(CATEGORIES)} categories &middot; 2 labs, 1 port</span>
    <span class="pill pill-live">live</span>
  </div>
</header>
<div class="layout"><nav>{_nav(current)}</nav><main>{body}</main></div>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    counts = {sev: sum(1 for c in CATEGORIES if c.severity == sev) for sev in _SEVERITY_ORDER}
    stats_html = "".join(
        f'<div class="stat" style="--sev:{_SEVERITY_COLOR[sev]}">'
        f'<div class="n">{counts[sev]}</div><div class="l">{sev}</div></div>'
        for sev in _SEVERITY_ORDER
        if counts[sev]
    )

    sections_html = []
    for section in SECTIONS:
        cards = [c for c in CATEGORIES if c.section == section]
        cards_html = "\n".join(
            f'<a class="card" style="--sev:{_SEVERITY_COLOR.get(c.severity, "#9ca3af")}" '
            f'href="/category/{c.slug}">{_sev_badge(c.severity)}'
            f"<h3>{html.escape(c.name)}</h3><p>{html.escape(c.summary)}</p></a>"
            for c in cards
        )
        sections_html.append(
            f'<h2 class="section-title">{html.escape(section)} '
            f'<span class="count">&middot; {len(cards)}</span></h2>'
            f'<div class="grid">{cards_html}</div>'
        )

    body = f"""
<div class="hero">
  <h1>Every lab, one place</h1>
  <p class="lede">{html.escape(_LAB_NOTICE)}</p>
  <div class="stats">{stats_html}</div>
</div>
{"".join(sections_html)}
<footer class="lab-footer">
  Backed by <code>labs/kiyoo-ai</code> and <code>labs/acmecorp</code>, reverse-proxied
  through this one origin — no other port to go find. <code>kiyoo-labs stop</code> to tear
  everything down.
</footer>
"""
    return _shell(body)


@app.get("/category/{slug}", response_class=HTMLResponse)
async def category_page(slug: str) -> HTMLResponse:
    cat = BY_SLUG.get(slug)
    if cat is None:
        return HTMLResponse(_shell("<h1>404</h1><p>No such category.</p>"), status_code=404)

    needs_note = (
        f'<div class="note">Needs <code>{html.escape(cat.demo.needs)}</code> running '
        f"(<code>kiyoo-labs {html.escape(cat.demo.needs)}</code>) for a live fetch"
        + (
            " — not running it right now just shows a captured offline preview "
            "below instead, clearly labeled as one."
            if cat.demo.offline_example
            else ". Not running it will show a connection error, which is "
            "itself an honest result."
        )
        + "</div>"
        if cat.demo.needs
        else ""
    )

    live_view = ""
    if cat.demo.kind in ("http", "http_post"):
        live_view = f"""
<h2 class="block-title">Live view — proxied through this origin, no other port</h2>
<div class="browser-frame">
  <div class="bar">
    <div class="dots">
      <span style="background:#ff6159"></span>
      <span style="background:#ffbd2e"></span>
      <span style="background:#27c93f"></span>
    </div>
    <div class="url">{html.escape(cat.demo.url)}</div>
  </div>
  <iframe class="live-view" src="/proxy/{slug}/"></iframe>
</div>
"""

    body = f"""
<a class="crumb" href="/">&larr; all categories</a>
<div class="detail-head"><h1>{html.escape(cat.name)}</h1>{_sev_badge(cat.severity)}</div>
<p class="summary">{html.escape(cat.summary)}</p>
<p class="source-line"><b>Live in</b> {html.escape(cat.source_note)}</p>
{needs_note}
{live_view}
<h2 class="block-title">Raw evidence</h2>
<div class="terminal">
  <div class="bar">
    <span class="label">GET /api/evidence/{slug}</span>
    <button onclick="go()">Fetch live evidence</button>
  </div>
  <pre id="out">click the button — kiyoo-range's own backend
makes the real request server-side</pre>
</div>
<script>
async function go() {{
  const out = document.getElementById('out');
  out.textContent = 'fetching...';
  const res = await fetch('/api/evidence/{slug}');
  const data = await res.json();
  if (!data.ok) {{
    out.innerHTML = '<span class="err">' + data.error + '</span>';
    return;
  }}
  let text = '';
  if (data.offline) {{
    text += 'OFFLINE PREVIEW — the lab this needs isn\\'t running right now, '
      + 'so this is a captured example, not a live fetch. Start it (see the '
      + 'note above) for the real thing.\\n\\n';
  }} else {{
    text += 'status: ' + (data.status ?? '(tcp, no HTTP status)') + '\\n\\n';
    if (Object.keys(data.headers).length) {{
      text += 'headers:\\n' + JSON.stringify(data.headers, null, 2) + '\\n\\n';
    }}
    text += 'body:\\n';
  }}
  text += data.body;
  out.textContent = text;
}}
</script>
"""
    return HTMLResponse(_shell(body, current=slug))


@app.api_route(
    "/proxy/{slug}/{subpath:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_route(slug: str, subpath: str, request: Request) -> Response:
    cat = BY_SLUG.get(slug)
    if cat is None:
        return Response("unknown category", status_code=404, media_type="text/plain")
    return await proxy_request(cat, subpath, request)


@app.get("/api/evidence/{slug}")
async def api_evidence(slug: str) -> JSONResponse:
    cat = BY_SLUG.get(slug)
    if cat is None:
        return JSONResponse({"ok": False, "error": "unknown category"}, status_code=404)
    result = await fetch(cat)
    return JSONResponse(
        {
            "ok": result.ok,
            "status": result.status,
            "headers": result.headers,
            "body": result.body,
            "error": result.error,
            "offline": result.offline,
        }
    )


@app.get("/_lab/notice", response_class=PlainTextResponse)
async def lab_notice() -> str:
    return _LAB_NOTICE


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"ok": True, "categories": len(CATEGORIES)})
