"""
HTML report generation for Warden scan results.

Self-contained single-file HTML output (no external assets): report header
with scan metadata, executive summary with severity distribution, a compact
findings index, detailed findings (searchable / filterable / expandable,
copyable evidence and PoC blocks), scan notes, and a reverse-engineering
inventory appendix. Presentation only: all content comes from
ScanResult.to_dict(), so the JSON export and this report always agree.
"""
from __future__ import annotations

import base64
import html
import re
import urllib.parse
from datetime import datetime
from pathlib import Path

from core.path_utils import normalize_target_path
from core.scanner import ScanResult

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

MODULE_LABELS = {
    "secrets": "Secrets & Configuration",
    "dll_hijack": "DLL Hijacking",
    "signature": "Code Signing & Integrity",
    "re_exposure": "Binary Hardening & RE Exposure",
    "linux": "Linux Thick Client",
    "macos": "macOS Thick Client",
    "reputation": "Reputation (VirusTotal)",
}

MITRE_BY_TAG = {
    "credential": "T1552 Unsecured Credentials",
    "jwt": "T1552 Unsecured Credentials",
    "database": "T1005 Data from Local System",
    "dll": "T1574 Hijack Execution Flow",
    "signature": "T1553 Subvert Trust Controls",
    "auto-update": "T1195 Supply Chain Compromise",
    "anti-debug": "T1497 Virtualization/Sandbox Evasion",
    "registry-key": "T1112 Modify Registry",
    "named-pipe": "T1559 Inter-Process Communication",
    "fuse": "T1218 System Binary Proxy Execution",
}

CWE_BY_TAG = {
    "credential": "CWE-798 Hard-coded Credentials",
    "jwt": "CWE-522 Insufficiently Protected Credentials",
    "database": "CWE-200 Exposure of Sensitive Information",
    "weak-crypto": "CWE-327 Broken/Risky Cryptographic Algorithm",
    "permissions": "CWE-732 Incorrect Permission Assignment",
    "signature": "CWE-347 Improper Verification of Cryptographic Signature",
    "debug-setting": "CWE-489 Active Debug Code",
    "tls-setting": "CWE-295 Improper Certificate Validation",
    "tls": "CWE-295 Improper Certificate Validation",
    "outdated-component": "CWE-1104 Use of Unmaintained Third-Party Components",
    "webpreferences": "CWE-1188 Insecure Default Initialization",
    "navigation": "CWE-601 Open Redirect / Untrusted Navigation",
    "transport": "CWE-319 Cleartext Transmission of Sensitive Information",
    "environment": "CWE-489 Active Debug Code",
}

RISK_TEXT = {
    "Critical": "Critical findings were identified that require immediate remediation before release.",
    "High": "High-severity findings were identified and should be remediated before release.",
    "Medium": "Medium-severity findings were identified; remediation is recommended in the next release cycle.",
    "Low": "Only low-severity findings were identified; address them as part of normal hardening.",
    "None": "No findings above informational severity were identified by the modules run in this scan.",
}


def _load_brand_logo_tag() -> str:
    """Embed the Warden logo as a data URI so the report stays one file."""
    logo_path = Path(__file__).resolve().parent.parent / "assets" / "logo_report.png"
    try:
        data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        return f'<img class="brand-logo" src="data:image/png;base64,{data}" alt="Warden">'
    except Exception:
        return ""


_BRAND_LOGO = _load_brand_logo_tag()

_STYLE = """
:root {
  --bg: #f6f7f9; --surface: #ffffff; --surface-2: #f9fafb; --code-bg: #f4f5f7;
  --border: #e3e6ea; --border-strong: #cfd4da;
  --text: #16191d; --text-2: #3d4450; --muted: #6b7280;
  --link: #2451b7; --focus: #2451b7;
  --crit: #b42318; --high: #c4320a; --med: #a15c07; --low: #1d5bbf; --info: #5b6472;
  --crit-bg: #fef3f2; --high-bg: #fff4ed; --med-bg: #fffaeb; --low-bg: #eff4ff; --info-bg: #f2f4f7;
  --mono: "Cascadia Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
  --sans: Inter, "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", Arial, sans-serif;
}
:root[data-theme="dark"] {
  --bg: #0f1114; --surface: #16191d; --surface-2: #1b1f24; --code-bg: #111418;
  --border: #2a2f36; --border-strong: #3a414a;
  --text: #e7e9ec; --text-2: #b9bfc8; --muted: #8a919c;
  --link: #8fb0f5; --focus: #8fb0f5;
  --crit: #f97066; --high: #f38744; --med: #e8b339; --low: #7aa6f5; --info: #98a2b3;
  --crit-bg: #2a1716; --high-bg: #2a1c12; --med-bg: #2a2312; --low-bg: #142034; --info-bg: #1f242b;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.55 var(--sans); }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.page { max-width: 1180px; margin: 0 auto; padding: 0 28px 64px; }

/* Header */
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 18px 0; border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700; letter-spacing: .08em; font-size: 13px; }
.brand-logo { width: 26px; height: 26px; object-fit: contain; }
.brand small { font-weight: 500; letter-spacing: 0; color: var(--muted); font-size: 12px; margin-left: 6px; }
.actions { display: flex; gap: 8px; }
.btn { font: 500 12px var(--sans); color: var(--text-2); background: var(--surface); border: 1px solid var(--border-strong);
  border-radius: 4px; padding: 6px 12px; cursor: pointer; }
.btn:hover { border-color: var(--text-2); color: var(--text); }
.btn.copied { color: var(--low); border-color: var(--low); }
.report-title { padding: 28px 0 8px; }
.report-title .kicker { font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); font-weight: 600; }
.report-title h1 { margin: 6px 0 0; font-size: 24px; font-weight: 650; letter-spacing: -.01em; word-break: break-word; }
.meta { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 20px 0 0;
  border: 1px solid var(--border); border-radius: 6px; background: var(--surface); }
.meta div { padding: 10px 14px; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); min-width: 0; }
.meta div:nth-child(4n) { border-right: 0; }
.meta dt { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; font-weight: 600; }
.meta dd { margin: 3px 0 0; font-size: 13px; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.meta dd.mono { font-family: var(--mono); font-size: 12.5px; }
.meta .wide { grid-column: span 4; border-right: 0; }

/* Sections */
section { margin-top: 36px; }
h2 { font-size: 15px; font-weight: 650; margin: 0 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border);
  display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
h2 .count { font-size: 12px; font-weight: 500; color: var(--muted); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }

/* Executive summary */
.exec { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr); gap: 16px; }
.exec .panel { padding: 16px 18px; }
.rating { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 650; }
.rating .sq { width: 12px; height: 12px; border-radius: 2px; background: var(--info); }
.exec p { margin: 10px 0 0; color: var(--text-2); }
.exec ul { margin: 10px 0 0; padding-left: 18px; color: var(--text-2); }
.distbar { display: flex; height: 8px; border-radius: 2px; overflow: hidden; background: var(--info-bg); margin: 4px 0 14px; }
.distbar span { display: block; height: 100%; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
  font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--border-strong); white-space: nowrap; }
td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.sev-row { cursor: pointer; }
tr.sev-row:hover td, tr.sev-row.active td { background: var(--surface-2); }
tr.sev-row.active td:first-child { box-shadow: inset 3px 0 0 var(--focus); }

/* Severity label */
.sev { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 650; white-space: nowrap;
  padding: 2px 8px; border-radius: 3px; border: 1px solid currentColor; line-height: 1.5; }
.sev::before { content: ""; width: 7px; height: 7px; border-radius: 1px; background: currentColor; }
.sev.Critical { color: var(--crit); background: var(--crit-bg); }
.sev.High { color: var(--high); background: var(--high-bg); }
.sev.Medium { color: var(--med); background: var(--med-bg); }
.sev.Low { color: var(--low); background: var(--low-bg); }
.sev.Info { color: var(--info); background: var(--info-bg); }
.c-Critical { background: var(--crit); } .c-High { background: var(--high); } .c-Medium { background: var(--med); }
.c-Low { background: var(--low); } .c-Info { background: var(--info); }

/* Index table */
.index-table td.title a { color: var(--text); font-weight: 550; }
.index-table td.title a:hover { color: var(--link); }
.index-table .id, .finding .id { font-family: var(--mono); font-size: 12px; color: var(--muted); white-space: nowrap; }
.index-wrap { overflow-x: auto; }

/* Toolbar */
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 12px; }
.toolbar input[type=search], .toolbar select { font: 13px var(--sans); color: var(--text); background: var(--surface);
  border: 1px solid var(--border-strong); border-radius: 4px; padding: 7px 10px; }
.toolbar input[type=search] { flex: 1 1 280px; min-width: 200px; }
.chips { display: flex; gap: 4px; flex-wrap: wrap; }
.chip { font: 500 12px var(--sans); padding: 6px 10px; border: 1px solid var(--border-strong); background: var(--surface);
  color: var(--text-2); border-radius: 4px; cursor: pointer; }
.chip[aria-pressed="true"] { background: var(--text); color: var(--surface); border-color: var(--text); }
.toolbar .visible { margin-left: auto; color: var(--muted); font-size: 12px; white-space: nowrap; }

/* Finding */
.finding { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; }
.finding > summary { list-style: none; cursor: pointer; display: grid; grid-template-columns: auto auto minmax(0, 1fr) auto auto;
  align-items: center; gap: 12px; padding: 11px 14px; }
.finding > summary::-webkit-details-marker { display: none; }
.finding > summary::after { content: ""; width: 7px; height: 7px; border-right: 1.5px solid var(--muted);
  border-bottom: 1.5px solid var(--muted); transform: rotate(-45deg); margin-right: 4px; }
.finding[open] > summary::after { transform: rotate(45deg); }
.finding[open] > summary { border-bottom: 1px solid var(--border); }
.finding .ftitle { font-weight: 600; overflow-wrap: anywhere; }
.finding .affected { font-size: 12px; color: var(--muted); white-space: nowrap; }
.finding.low-confidence .ftitle::after { content: "low confidence"; margin-left: 8px; font-size: 11px; font-weight: 500;
  color: var(--muted); border: 1px solid var(--border-strong); border-radius: 3px; padding: 0 5px; }
.fbody { padding: 4px 18px 18px; }
.attrs { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0; margin: 12px 0 4px;
  border: 1px solid var(--border); border-radius: 4px; }
.attrs div { padding: 8px 12px; border-right: 1px solid var(--border); min-width: 0; }
.attrs div:nth-child(4) { border-right: 0; }
.attrs div.wide { grid-column: 1 / -1; border-right: 0; border-top: 1px solid var(--border); }
.attrs dt { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; font-weight: 600; }
.attrs dd { margin: 2px 0 0; font-size: 12.5px; overflow-wrap: anywhere; }
.attrs dd.mono { font-family: var(--mono); }
.block { margin-top: 18px; }
.block > h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); font-weight: 650;
  margin: 0 0 6px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.block p { margin: 0; color: var(--text-2); max-width: 90ch; white-space: pre-line; }
.tags { margin-top: 16px; font-family: var(--mono); font-size: 11.5px; color: var(--muted); }
.tags span + span::before { content: " \\00B7  "; }

/* Code / evidence */
pre, code { font-family: var(--mono); }
pre.code { margin: 0; background: var(--code-bg); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px;
  font-size: 12.5px; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 460px; overflow: auto; color: var(--text); }
pre.code .step { font-weight: 650; color: var(--text); }
pre.code .cmt { color: var(--muted); }
pre.code .cmd { color: var(--link); }
.path { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.path .seg { color: var(--muted); }
.occ-table { border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
.occ-scroll { max-height: 340px; overflow: auto; border: 1px solid var(--border); border-radius: 4px; }
.occ-scroll table th { position: sticky; top: 0; background: var(--surface); }
.occ-table td.ev, .occ-scroll td.ev { font-family: var(--mono); font-size: 12px; color: var(--text-2); overflow-wrap: anywhere; }
details.sub { margin-top: 18px; border: 1px solid var(--border); border-radius: 4px; }
details.sub > summary { cursor: pointer; padding: 8px 12px; font-size: 12.5px; font-weight: 600; color: var(--text-2); }
details.sub > div { padding: 0 12px 12px; }
details.sub .occ { padding-top: 12px; border-top: 1px solid var(--border); margin-top: 12px; }
details.sub .occ:first-child { border-top: 0; margin-top: 0; }
details.sub .occ .path { font-weight: 600; display: block; margin-bottom: 6px; }
details.sub .occ pre.code + pre.code { margin-top: 6px; }

.empty { padding: 28px; text-align: center; color: var(--muted); border: 1px dashed var(--border-strong); border-radius: 6px; background: var(--surface); }
.notes li { margin: 4px 0; color: var(--text-2); font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
details.appendix > summary { cursor: pointer; font-size: 15px; font-weight: 650; padding: 0 0 8px; border-bottom: 1px solid var(--border); list-style: none; }
details.appendix > summary::-webkit-details-marker { display: none; }
details.appendix > summary::before { content: "+ "; color: var(--muted); }
details.appendix[open] > summary::before { content: "\\2212  "; }
details.appendix > summary .count { font-size: 12px; font-weight: 500; color: var(--muted); margin-left: 8px; }
.appendix-note { color: var(--muted); font-size: 12.5px; margin: 10px 0 12px; }
footer { margin-top: 48px; padding-top: 14px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px;
  display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; }

@media (max-width: 860px) {
  .page { padding: 0 16px 48px; }
  .meta, .attrs { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .meta div:nth-child(4n) { border-right: 1px solid var(--border); }
  .meta div:nth-child(2n) { border-right: 0; }
  .meta .wide { grid-column: span 2; }
  .attrs div { border-bottom: 1px solid var(--border); }
  .exec { grid-template-columns: 1fr; }
  .finding > summary { grid-template-columns: auto minmax(0, 1fr) auto; }
  .finding > summary .id, .finding > summary .affected { display: none; }
  .index-table .hide-sm { display: none; }
}

@media print {
  :root, :root[data-theme="dark"] {
    --bg: #fff; --surface: #fff; --surface-2: #fff; --code-bg: #f6f7f8; --border: #d9dce1; --border-strong: #c3c8cf;
    --text: #000; --text-2: #222; --muted: #555; --link: #000;
    --crit: #a1170f; --high: #b02c08; --med: #8a4e06; --low: #1a4fa8; --info: #4b5361;
    --crit-bg: #fff; --high-bg: #fff; --med-bg: #fff; --low-bg: #fff; --info-bg: #fff;
  }
  @page { size: A4; margin: 16mm 14mm 18mm; }
  body { font-size: 11pt; }
  .page { max-width: none; padding: 0; }
  .actions, .toolbar, .btn { display: none !important; }
  .finding, .panel, .meta, tr, pre.code { break-inside: avoid; }
  .finding > summary::after, details.appendix > summary::before { display: none; }
  pre.code, .occ-scroll { max-height: none; overflow: visible; }
  section.findings-detail { break-before: page; }
  a { text-decoration: none; }
}
"""

_SCRIPT = """
(function () {
  var state = { sev: null, module: '', q: '' };
  function $(s, r) { return (r || document).querySelector(s); }
  function $$(s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); }

  function applyFilters() {
    var shown = 0;
    $$('#findings .finding').forEach(function (f) {
      var ok = (!state.sev || f.dataset.severity === state.sev)
        && (!state.module || f.dataset.module === state.module)
        && (!state.q || f.dataset.search.indexOf(state.q) !== -1);
      f.hidden = !ok;
      if (ok) shown++;
    });
    $$('#index tbody tr[data-ref]').forEach(function (r) {
      var f = document.getElementById(r.dataset.ref);
      r.hidden = f ? f.hidden : false;
    });
    var v = $('#visibleCount'); if (v) v.textContent = shown;
    var e = $('#noMatch'); if (e) e.hidden = shown !== 0 || $$('#findings .finding').length === 0;
    $$('.chip[data-sev]').forEach(function (c) { c.setAttribute('aria-pressed', String((c.dataset.sev || null) === state.sev)); });
    $$('tr.sev-row').forEach(function (r) { r.classList.toggle('active', r.dataset.sev === state.sev); });
  }
  window.filterBySeverity = function (sev) {
    state.sev = (state.sev === sev || !sev) ? null : sev;
    applyFilters();
    var d = $('#findings'); if (d && sev) d.scrollIntoView({ block: 'start' });
  };
  window.setAll = function (open) { $$('#findings .finding').forEach(function (f) { if (!f.hidden) f.open = open; }); };
  window.openFinding = function (id) { var f = document.getElementById(id); if (f) { f.open = true; } };

  function copyText(btn, text) {
    var done = function () {
      var t = btn.textContent; btn.textContent = 'Copied'; btn.classList.add('copied');
      setTimeout(function () { btn.textContent = t; btn.classList.remove('copied'); }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }
  window.copyPoc = function (btn, encoded) { copyText(btn, decodeURIComponent(encoded)); };

  function applyTheme(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    var b = $('#themeToggle'); if (b) b.textContent = mode === 'dark' ? 'Light theme' : 'Dark theme';
  }
  window.toggleTheme = function () {
    var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next); try { localStorage.setItem('warden-report-theme', next); } catch (e) {}
  };

  var printOpen = [];
  window.addEventListener('beforeprint', function () {
    printOpen = $$('details:not([open])'); printOpen.forEach(function (d) { d.open = true; });
  });
  window.addEventListener('afterprint', function () { printOpen.forEach(function (d) { d.open = false; }); });

  document.addEventListener('DOMContentLoaded', function () {
    var saved = null;
    try { saved = localStorage.getItem('warden-report-theme'); } catch (e) {}
    if (!saved) saved = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    applyTheme(saved);
    var box = $('#searchBox');
    if (box) box.addEventListener('input', function () { state.q = box.value.trim().toLowerCase(); applyFilters(); });
    var mod = $('#moduleFilter');
    if (mod) mod.addEventListener('change', function () { state.module = mod.value; applyFilters(); });
    if (location.hash) window.openFinding(location.hash.slice(1));
    applyFilters();
  });
})();
"""


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _format_timestamp(value: str | None) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    display = parsed.strftime("%d %b %Y, %H:%M:%S")
    timezone_name = parsed.tzname()
    return f"{display} {timezone_name}" if timezone_name else display


def _duration(start: str | None, end: str | None) -> str:
    try:
        seconds = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    except (TypeError, ValueError):
        return "—"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs:02d}s" if minutes else f"{seconds:.1f}s"


def _mapped_values(f: dict, mapping: dict[str, str]) -> list[str]:
    tags = set(f.get("tags", []))
    return sorted({v for tag, v in mapping.items() if tag in tags})


def _module_label(module: str) -> str:
    return MODULE_LABELS.get(module, module.replace("_", " ").title())


def _sev(sev: str) -> str:
    return f'<span class="sev {_esc(sev)}">{_esc(sev)}</span>'


def _path_html(path: str) -> str:
    """Archive chains ("setup.exe > app.7z > app.exe") with muted separators."""
    parts = [_esc(p) for p in str(path).split(" > ")]
    return '<span class="path">' + '<span class="seg"> &rsaquo; </span>'.join(parts) + "</span>"


_STEP_RE = re.compile(r"^(\s*)(\d+\.)(\s.*)?$")
_CMD_RE = re.compile(
    r"^(\s+)((?:\$f|\$b|Get-|Select-String|dumpbin|signtool|osslsigncode|strings64|icacls|mt\.exe|7z |npx |python|xxd|grep|"
    r"sc |reg |icacls|Import-Module|codesign|otool|readelf|file |objdump|spctl|plutil|stat |find |ls ).*)$"
)


def _code(text: str) -> str:
    """Escaped code block with light, safe highlighting: numbered steps bold,
    command lines tinted, parenthesised notes muted."""
    out = []
    for line in str(text).split("\n"):
        m = _STEP_RE.match(line)
        if m:
            out.append(f'{_esc(m.group(1))}<span class="step">{_esc(m.group(2))}</span>{_esc(m.group(3) or "")}')
            continue
        m = _CMD_RE.match(line)
        if m:
            out.append(f'{_esc(m.group(1))}<span class="cmd">{_esc(m.group(2))}</span>')
            continue
        if line.strip().startswith("(") and line.strip().endswith(")"):
            out.append(f'<span class="cmt">{_esc(line)}</span>')
            continue
        out.append(_esc(line))
    return '<pre class="code">' + "\n".join(out) + "</pre>"


def _copy_btn(text: str, label: str = "Copy") -> str:
    return f"<button class=\"btn\" type=\"button\" onclick=\"copyPoc(this, '{urllib.parse.quote(str(text))}')\">{label}</button>"


def _highest(counts: dict) -> str:
    instances = counts.get("instances", {})
    return next((s for s in SEVERITY_ORDER if s != "Info" and instances.get(s, 0) > 0), "None")


def _render_header(meta, report_data: dict, findings: list[dict]) -> str:
    target = normalize_target_path(meta.target_path)
    m = report_data["metadata"]
    modules = ", ".join(
        f"{_module_label(name)} ({count})" for name, count in sorted(meta.module_execution_counts.items())
    ) or "—"
    instances = sum(len(f.get("occurrences") or []) for f in findings)
    rows = [
        ("Target", f'<dd class="mono">{_esc(target)}</dd>', False),
        ("Scan started", f'<dd><time datetime="{_esc(meta.started_at)}">{_esc(_format_timestamp(meta.started_at))}</time></dd>', False),
        ("Scan finished", f'<dd><time datetime="{_esc(meta.finished_at)}">{_esc(_format_timestamp(meta.finished_at))}</time></dd>', False),
        ("Duration", f"<dd>{_esc(_duration(meta.started_at, meta.finished_at))}</dd>", False),
        ("Files scanned", f"<dd>{_esc(m['files_scanned'])} <span style='color:var(--muted)'>({_esc(m['input_files_scanned'])} input, {_esc(m['extracted_files_scanned'])} extracted)</span></dd>", False),
        ("Issues", f"<dd>{len(findings)} <span style='color:var(--muted)'>({instances} instances)</span></dd>", False),
        ("Inventory items", f"<dd>{len(report_data.get('inventory') or [])}</dd>", False),
        ("Tool version", f'<dd class="mono">Warden {_esc(meta.tool_version)}</dd>', False),
        ("Module executions", f"<dd>{_esc(modules)}</dd>", True),
    ]
    meta_html = "".join(
        f'<div class="{"wide" if wide else ""}"><dt>{label}</dt>{value}</div>' for label, value, wide in rows
    )
    return f"""<div class="topbar">
  <div class="brand">{_BRAND_LOGO}WARDEN<small>Static Security Assessment</small></div>
  <div class="actions">
    <button class="btn" type="button" onclick="window.print()">Print / PDF</button>
    <button class="btn" type="button" id="themeToggle" onclick="toggleTheme()">Dark theme</button>
  </div>
</div>
<div class="report-title">
  <div class="kicker">Security Assessment Report</div>
  <h1>{_esc(target)}</h1>
  <dl class="meta">{meta_html}</dl>
</div>"""


def _render_executive(findings: list[dict], counts: dict) -> str:
    unique, instances = counts.get("unique", {}), counts.get("instances", {})
    info_u = sum(counts.get("info_unique", {}).values())
    info_i = sum(counts.get("info_instances", {}).values())
    highest = _highest(counts)
    total_vuln = sum(unique.values())
    rating = {"None": "No significant risk"}.get(highest, f"{highest} risk")

    total_inst = sum(instances.values()) + info_i
    bar = "".join(
        f'<span class="c-{s}" style="width:{(instances.get(s, 0) if s != "Info" else info_i) / total_inst * 100:.2f}%" '
        f'title="{s}: {instances.get(s, 0) if s != "Info" else info_i}"></span>'
        for s in SEVERITY_ORDER if (instances.get(s, 0) if s != "Info" else info_i)
    ) if total_inst else ""
    rows = "".join(
        f'<tr class="sev-row" data-sev="{s}" onclick="filterBySeverity(\'{s}\')" tabindex="0" '
        f'onkeydown="if(event.key===\'Enter\')filterBySeverity(\'{s}\')">'
        f"<td>{_sev(s)}</td>"
        f'<td class="num">{unique.get(s, 0) if s != "Info" else info_u}</td>'
        f'<td class="num">{instances.get(s, 0) if s != "Info" else info_i}</td></tr>'
        for s in SEVERITY_ORDER
    )

    by_module: dict[str, int] = {}
    for f in findings:
        if f["severity"] != "Info":
            by_module[f["module"]] = by_module.get(f["module"], 0) + 1
    top = [f for f in findings if f["severity"] in ("Critical", "High")][:5] or \
          [f for f in findings if f["severity"] == "Medium"][:5]
    top_html = "".join(
        f'<li><a href="#{_esc(f["_ref"])}" onclick="openFinding(\'{_esc(f["_ref"])}\')">{_esc(f["title"])}</a> '
        f'<span style="color:var(--muted)">({_esc(f["severity"])}, {len(f.get("occurrences") or []) or 1} affected)</span></li>'
        for f in top
    )
    areas = ", ".join(f"{_module_label(m)} ({n})" for m, n in sorted(by_module.items(), key=lambda kv: -kv[1]))
    summary = (
        f"{total_vuln} distinct security issue{'s' if total_vuln != 1 else ''} "
        f"({sum(instances.values())} affected instance{'s' if sum(instances.values()) != 1 else ''}) "
        f"and {info_u} informational observation{'s' if info_u != 1 else ''} were identified."
    )
    sev_var = {"Critical": "--crit", "High": "--high", "Medium": "--med", "Low": "--low"}.get(highest, "--info")
    sq = f'<span class="sq" style="background:var({sev_var})"></span>'
    return f"""<section id="summary">
  <h2>Executive summary</h2>
  <div class="exec">
    <div class="panel">
      <div class="rating">{sq}{_esc(rating)}</div>
      <p>{_esc(RISK_TEXT.get(highest, RISK_TEXT['None']))}</p>
      <p>{_esc(summary)}{(' Affected areas: ' + _esc(areas) + '.') if areas else ''}</p>
      {('<p style="margin-top:14px;font-weight:600;color:var(--text)">Priority issues</p><ul>' + top_html + '</ul>') if top_html else ''}
    </div>
    <div class="panel">
      <div style="font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em">Risk distribution (instances)</div>
      <div class="distbar">{bar}</div>
      <table>
        <thead><tr><th>Severity</th><th class="num">Issues</th><th class="num">Instances</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <div style="font-size:12px;color:var(--muted);margin-top:8px">Select a severity to filter the findings below.</div>
    </div>
  </div>
</section>"""


def _render_index(findings: list[dict]) -> str:
    if not findings:
        return """<section id="index"><h2>Findings index</h2><div class="empty">No findings were identified by the modules run in this scan.</div></section>"""
    rows = "".join(
        f'<tr data-ref="{_esc(f["_ref"])}"><td class="id">{_esc(f["_id"])}</td><td>{_sev(f["severity"])}</td>'
        f'<td class="title"><a href="#{_esc(f["_ref"])}" onclick="openFinding(\'{_esc(f["_ref"])}\')">{_esc(f["title"])}</a></td>'
        f'<td class="hide-sm">{_esc(_module_label(f["module"]))}</td>'
        f'<td class="num">{len(f.get("occurrences") or []) or 1}</td></tr>'
        for f in findings
    )
    return f"""<section id="index">
  <h2>Findings index <span class="count">{len(findings)} issue{'s' if len(findings) != 1 else ''}</span></h2>
  <div class="panel index-wrap"><table class="index-table">
    <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th class="hide-sm">Area</th><th class="num">Affected</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</section>"""


def _render_finding(f: dict) -> str:
    occurrences = f.get("occurrences") or []
    locations = f.get("locations") or [f.get("file_path", "")]
    contexts = f.get("contexts") or []
    affected = len(occurrences) or len(locations)
    cwe = ", ".join(_mapped_values(f, CWE_BY_TAG))
    mitre = ", ".join(_mapped_values(f, MITRE_BY_TAG))

    attrs = [("Rule", f'<dd class="mono">{_esc(f["rule_id"])}</dd>'),
             ("Area", f"<dd>{_esc(_module_label(f['module']))}</dd>"),
             ("Confidence", f"<dd>{_esc(f.get('confidence', ''))}</dd>"),
             ("Affected", f"<dd>{affected} location{'s' if affected != 1 else ''}</dd>")]
    if cwe or mitre:
        attrs.append(("Classification", f"<dd>{_esc('; '.join(x for x in (cwe, mitre) if x))}</dd>"))
    attrs_html = "".join(
        f'<div{" class=wide" if k == "Classification" else ""}><dt>{k}</dt>{v}</div>' for k, v in attrs
    )

    # Affected locations with each occurrence's own evidence.
    if occurrences:
        occ_rows = "".join(
            f"<tr><td class='num'>{i}</td><td>{_path_html(o.get('location') or o.get('file_path', ''))}</td>"
            f"<td class='ev'>{_esc(o.get('evidence', ''))}</td></tr>"
            for i, o in enumerate(occurrences, 1)
        )
        head = "<thead><tr><th class='num'>#</th><th>Location</th><th>Evidence</th></tr></thead>"
    else:
        occ_rows = "".join(f"<tr><td class='num'>{i}</td><td>{_path_html(loc)}</td></tr>" for i, loc in enumerate(locations, 1))
        head = "<thead><tr><th class='num'>#</th><th>Location</th></tr></thead>"
    occ_cls = "occ-scroll" if affected > 8 else "occ-table"
    occ_html = f'<div class="{occ_cls}"><table>{head}<tbody>{occ_rows}</tbody></table></div>'

    context_entries = [
        (o.get("location", ""), o.get("context")) for o in occurrences if o.get("context")
    ] if occurrences else [(loc, ctx) for loc, ctx in zip(locations, contexts) if ctx]
    context_html = ""
    if context_entries:
        loc, ctx = context_entries[0]
        more = (f'<p style="margin-top:6px;color:var(--muted);font-size:12px">Context for {len(context_entries) - 1} more '
                f'location(s) is under "Per-location detail" below.</p>') if len(context_entries) > 1 else ""
        context_html = (f'<div class="block"><h3>Code context <span style="text-transform:none;letter-spacing:0;font-weight:500">'
                        f'{_path_html(loc)}</span></h3>{_code(ctx)}{more}</div>')

    poc_html = ""
    if f.get("poc"):
        note = " (first location; repeat for each location listed)" if affected > 1 else ""
        poc_html = (f'<div class="block"><h3>Proof of concept / reproduction{_esc(note)} {_copy_btn(f["poc"])}</h3>'
                    f'{_code(f["poc"])}</div>')

    detail_html = ""
    if len(occurrences) > 1:
        items = []
        for o in occurrences:
            parts = [_path_html(o.get("location") or o.get("file_path", "")).replace('class="path"', 'class="path" style="font-weight:600;display:block;margin-bottom:6px"', 1)]
            parts.append(_code(o.get("evidence", "")))
            if o.get("context"):
                parts.append(_code(o["context"]))
            if o.get("poc"):
                parts.append(f'<div style="display:flex;justify-content:flex-end;margin:8px 0 4px">{_copy_btn(o["poc"], "Copy PoC")}</div>' + _code(o["poc"]))
            items.append('<div class="occ">' + "".join(parts) + "</div>")
        detail_html = (f'<details class="sub"><summary>Per-location detail ({len(occurrences)})</summary>'
                       f'<div>{"".join(items)}</div></details>')

    searchable = [f["title"], f["rule_id"], f["module"], _module_label(f["module"]), str(f.get("evidence", "")),
                  str(f.get("description", "")), str(f.get("poc", ""))] + [str(x) for x in locations[:200]]
    for o in occurrences:
        searchable += [str(o.get("evidence", "")), str(o.get("context", ""))]
    search_blob = _esc(" ".join(searchable).lower())
    tags_html = "".join(f"<span>{_esc(t)}</span>" for t in f.get("tags", []))
    low_conf = " low-confidence" if f.get("confidence") == "Low" else ""
    evidence = str(f.get("evidence", ""))

    return f"""<details class="finding{low_conf}" id="{_esc(f['_ref'])}" data-severity="{_esc(f['severity'])}" data-module="{_esc(f['module'])}" data-search="{search_blob}">
  <summary><span class="id">{_esc(f['_id'])}</span>{_sev(f['severity'])}<span class="ftitle">{_esc(f['title'])}</span><span class="affected">{affected} affected</span></summary>
  <div class="fbody">
    <dl class="attrs">{attrs_html}</dl>
    <div class="block"><h3>Description</h3><p>{_esc(f.get('description') or '—')}</p></div>
    <div class="block"><h3>Evidence {_copy_btn(evidence)}</h3>{_code(evidence)}</div>
    <div class="block"><h3>Affected locations</h3>{occ_html}</div>
    {context_html}
    <div class="block"><h3>Remediation</h3><p>{_esc(f.get('remediation') or '—')}</p></div>
    {poc_html}
    {detail_html}
    <div class="tags">{tags_html}</div>
  </div>
</details>"""


def _render_findings(findings: list[dict]) -> str:
    modules = sorted({f["module"] for f in findings}, key=_module_label)
    options = "".join(f'<option value="{_esc(m)}">{_esc(_module_label(m))}</option>' for m in modules)
    chips = '<button class="chip" type="button" data-sev="" onclick="filterBySeverity(null)">All</button>' + "".join(
        f'<button class="chip" type="button" data-sev="{s}" onclick="filterBySeverity(\'{s}\')">{s}</button>'
        for s in SEVERITY_ORDER if any(f["severity"] == s for f in findings)
    )
    body = "".join(_render_finding(f) for f in findings) or \
        '<div class="empty">No findings were identified by the modules run in this scan.</div>'
    return f"""<section class="findings-detail">
  <h2>Detailed findings <span class="count">{len(findings)} issue{'s' if len(findings) != 1 else ''}</span></h2>
  <div class="toolbar">
    <input type="search" id="searchBox" placeholder="Search title, rule, file path, evidence…" aria-label="Search findings">
    <select id="moduleFilter" aria-label="Filter by area"><option value="">All areas</option>{options}</select>
    <div class="chips">{chips}</div>
    <button class="btn" type="button" onclick="setAll(true)">Expand all</button>
    <button class="btn" type="button" onclick="setAll(false)">Collapse all</button>
    <span class="visible">Showing <span id="visibleCount">{len(findings)}</span> of {len(findings)}</span>
  </div>
  <div id="findings">{body}<div class="empty" id="noMatch" hidden>No findings match the current filters.</div></div>
</section>"""


def _render_inventory(inventory: list[dict]) -> str:
    if not inventory:
        return ""
    body = "".join(_render_finding(f) for f in inventory)
    return f"""<section id="inventory">
  <details class="appendix"><summary>Appendix: reverse-engineering inventory<span class="count">{len(inventory)} item{'s' if len(inventory) != 1 else ''}</span></summary>
    <p class="appendix-note">Context collected for manual review (endpoints, dependencies, frameworks, verified hardening controls).
    These are not vulnerabilities and are excluded from all counts above.</p>
    {body}
  </details>
</section>"""


def _render_notes(errors: list[str]) -> str:
    if not errors:
        return ""
    items = "".join(f"<li>{_esc(e)}</li>" for e in errors)
    return f"""<section id="notes"><h2>Scan notes <span class="count">{len(errors)}</span></h2>
  <div class="panel" style="padding:8px 18px"><ul class="notes">{items}</ul></div>
  <p style="color:var(--muted);font-size:12px">Non-fatal issues during the scan (skipped files, extraction limits). Review them when assessing coverage.</p></section>"""


def generate_html_report(
    result: ScanResult,
    output_path: str | Path,
) -> Path:
    """Render a self-contained report with complete local scan evidence."""
    report_data = result.to_dict()
    findings = report_data["findings"]
    inventory = report_data.get("inventory") or []
    counts = report_data["summary"]
    meta = result.metadata

    # Severity first, then most affected; stable IDs W-001.. for cross-references.
    findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99,
                       -(len(f.get("occurrences") or []))),
    )
    for i, f in enumerate(findings, 1):
        f["_id"], f["_ref"] = f"W-{i:03d}", f"finding-{i}"
    for i, f in enumerate(inventory, 1):
        f["_id"], f["_ref"] = f"INV-{i:03d}", f"inventory-{i}"

    target = normalize_target_path(meta.target_path)
    doc = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warden Security Assessment &mdash; {_esc(target)}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="page">
{_render_header(meta, report_data, findings)}
{_render_executive(findings, counts)}
{_render_index(findings)}
{_render_findings(findings)}
{_render_notes(report_data.get("module_errors") or [])}
{_render_inventory(inventory)}
<footer>
  <span>Generated by Warden {_esc(meta.tool_version)} &middot; {_esc(_format_timestamp(meta.finished_at))}</span>
  <span>Static analysis only, for authorized assessments of owned or client-consented applications.</span>
</footer>
</div>
<script>{_SCRIPT}</script>
</body>
</html>
"""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(doc, encoding="utf-8")
    return output_path
