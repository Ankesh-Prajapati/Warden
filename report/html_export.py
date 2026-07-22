"""
HTML report generation for Warden scan results.

Self-contained single-file HTML output (no external assets). Findings are
grouped by module into collapsible sections, with a top-level risk summary
banner, severity filter bar, search, and copy-to-clipboard PoC blocks.
"""
from __future__ import annotations

import base64
import html
from pathlib import Path

from core.finding_grouping import group_finding_dicts
from core.scanner import ScanResult

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_COLORS = {
    "Critical": "#e0645c",
    "High": "#d9944f",
    "Medium": "#d0b352",
    "Low": "#6f9bd8",
    "Info": "#8b8f96",
}

# Presentational-only: two-stop gradients derived from the same severity
# colors above, used purely for premium-looking badges/cards/heatmap cells.
# Carries no data and does not affect severity logic or JSON output.
SEVERITY_GRADIENTS = {
    "Critical": ("#ff7a70", "#c23b39"),
    "High": ("#ffab6b", "#c2660f"),
    "Medium": ("#f3d16a", "#b8860b"),
    "Low": ("#8db6ff", "#3f68d6"),
    "Info": ("#b0b6c2", "#666c78"),
}

SEVERITY_GLYPHS = {
    "Critical": "\u2716",   # heavy multiplication x
    "High": "\u25B2",       # triangle
    "Medium": "\u25CF",     # circle
    "Low": "\u25C6",        # diamond
    "Info": "\u2139",       # info
}


def _severity_gradient(sev: str) -> str:
    c1, c2 = SEVERITY_GRADIENTS.get(sev, ("#9aa0ab", "#666c78"))
    return f"linear-gradient(135deg, {c1}, {c2})"

MODULE_LABELS = {
    "secrets": "Secrets & Config Exposure",
    "dll_hijack": "DLL Hijacking Detection",
    "signature": "Signature / Integrity Check",
    "re_exposure": "RE / Anti-Tamper Exposure",
    "linux": "Linux Thick-Client Assessment",
    "macos": "macOS Thick-Client Assessment",
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
}


def _load_brand_logo_tag() -> str:
    """Embed the real Warden logo as a base64 data URI so the report stays
    a single self-contained HTML file with no external image asset."""
    logo_path = Path(__file__).resolve().parent.parent / "assets" / "logo_report.png"
    try:
        data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        return f'<img class="badge-icon" src="data:image/png;base64,{data}" width="46" height="46" alt="Warden">'
    except Exception:
        # Fallback glyph if the asset is ever missing, so report generation
        # never fails just because the logo file wasn't shipped alongside it.
        return (
            '<svg class="badge-icon" width="26" height="26" viewBox="0 0 34 34" '
            'xmlns="http://www.w3.org/2000/svg">'
            '<path d="M5.4 0.7 H28.6 L34 5.4 V15.6 L17 33.3 L0 15.6 V5.4 Z" fill="#6d8cf0"/>'
            '<polyline points="7.5,10.2 12.2,21.1 17,13.6 21.8,21.1 26.5,10.2" fill="none" '
            'stroke="#11131a" stroke-width="2.9" stroke-linecap="round" stroke-linejoin="round"/>'
            "</svg>"
        )


_BRAND_SVG = _load_brand_logo_tag()

_STYLE = """
:root {
  --bg: #0a0b0e;
  --bg-radial: radial-gradient(1200px 600px at 15% -10%, rgba(109,140,240,.08), transparent 60%),
               radial-gradient(900px 500px at 100% 0%, rgba(143,109,240,.06), transparent 55%);
  --panel: #14161b;
  --panel-alt: #101216;
  --panel-elevated: #191c22;
  --border: #22252c;
  --border-soft: #1b1e24;
  --text: #edeef2;
  --text-secondary: #b4b9c4;
  --muted: #868c98;
  --accent: #6d8cf0;
  --accent-soft: #9db0f5;
  --accent-dim: rgba(109,140,240,.14);
  --radius-lg: 14px;
  --radius-md: 10px;
  --radius-sm: 7px;
  --shadow-card: 0 1px 2px rgba(0,0,0,.24), 0 8px 24px -12px rgba(0,0,0,.5);
  --shadow-card-hover: 0 2px 4px rgba(0,0,0,.28), 0 16px 40px -16px rgba(0,0,0,.6);
  --ease: cubic-bezier(.2,.7,.3,1);
}
:root[data-theme="light"] {
  --bg: #f3f4f7;
  --bg-radial: radial-gradient(1200px 600px at 15% -10%, rgba(58,91,217,.05), transparent 60%),
               radial-gradient(900px 500px at 100% 0%, rgba(143,109,240,.04), transparent 55%);
  --panel: #ffffff;
  --panel-alt: #eef0f3;
  --panel-elevated: #ffffff;
  --border: #dbdfe5;
  --border-soft: #e6e9ed;
  --text: #191b1f;
  --text-secondary: #454b54;
  --muted: #6b7280;
  --accent: #3a5bd9;
  --accent-soft: #2f4bb8;
  --accent-dim: rgba(58,91,217,.10);
  --shadow-card: 0 1px 2px rgba(20,25,35,.06), 0 8px 20px -14px rgba(20,25,35,.16);
  --shadow-card-hover: 0 2px 6px rgba(20,25,35,.08), 0 14px 32px -16px rgba(20,25,35,.20);
}
:root[data-theme="light"] code,
:root[data-theme="light"] .evidence-box,
:root[data-theme="light"] pre.poc,
:root[data-theme="light"] ul.file-list {
  background: #f6f7f9;
  color: #2a2f37;
}
:root[data-theme="light"] pre.poc { color: #1f4d2e; }
:root[data-theme="light"] .toolbar input[type=search] {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%236b7280' stroke-width='2'><circle cx='11' cy='11' r='7'/><line x1='21' y1='21' x2='16.65' y2='16.65'/></svg>");
}
body, .finding, .dash-panel, .summary-card, details.module-section, .risk-banner {
  transition: background-color .2s var(--ease), border-color .2s var(--ease), color .2s var(--ease);
}
.theme-toggle {
  display: inline-flex; align-items: center; gap: 7px;
  background: var(--panel-alt); border: 1px solid var(--border); color: var(--text-secondary);
  font-size: 11.5px; font-weight: 700; letter-spacing: 0.3px;
  padding: 8px 14px; border-radius: var(--radius-sm); cursor: pointer; font-family: inherit;
  transition: border-color .15s var(--ease), color .15s var(--ease);
}
.theme-toggle:hover { border-color: var(--accent); color: var(--accent-soft); }
.theme-toggle .icon { font-size: 13px; line-height: 0; }
* { box-sizing: border-box; }
html { -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; }
body {
  background: var(--bg-radial), var(--bg);
  background-attachment: fixed;
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', 'Helvetica Neue', Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  margin: 0;
  padding: 0;
  -moz-osx-font-smoothing: grayscale;
}
::selection { background: var(--accent-dim); color: var(--text); }
.wrap { max-width: 1200px; margin: 0 auto; padding: 48px 32px 72px; }

/* ---------- Header ---------- */
header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 28px;
  margin-bottom: 28px;
}
header .brand { display: flex; align-items: center; gap: 14px; margin-bottom: 14px; }
header .brand .badge-icon {
  display: inline-flex; line-height: 0; padding: 6px;
  background: var(--panel-elevated); border: 1px solid var(--border);
  border-radius: var(--radius-sm); box-shadow: var(--shadow-card);
}
header .eyebrow {
  color: var(--accent-soft); font-size: 11px; font-weight: 700; letter-spacing: 2px;
  text-transform: uppercase; margin: 0 0 6px 0;
}
header h1 {
  color: var(--text);
  font-size: 25px;
  letter-spacing: -0.2px;
  margin: 0;
  font-weight: 700;
}
header .subtitle { color: var(--muted); font-size: 13px; margin-top: 4px; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1px;
  margin-top: 22px;
  background: var(--border-soft);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  overflow: hidden;
}
.meta-item { background: var(--panel-alt); padding: 12px 16px; }
.meta-item .meta-label {
  color: var(--muted); font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.9px; margin-bottom: 5px;
}
.meta-item .meta-value {
  color: var(--text); font-size: 13px; font-weight: 600; word-break: break-word;
  font-variant-numeric: tabular-nums;
}
.meta-item .meta-value.mono { font-family: 'SF Mono', 'Consolas', 'Fira Code', monospace; font-size: 12px; font-weight: 500; color: var(--text-secondary); }

/* ---------- Risk banner ---------- */
.risk-banner {
  position: relative;
  border-radius: var(--radius-lg);
  padding: 20px 26px;
  margin-bottom: 24px;
  border: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 18px;
  box-shadow: var(--shadow-card);
  overflow: hidden;
}
.risk-banner::before {
  content: ""; position: absolute; inset: 0;
  background: linear-gradient(135deg, rgba(255,255,255,.04), rgba(255,255,255,0) 45%);
  pointer-events: none;
}
.risk-icon-circle {
  flex-shrink: 0;
  width: 44px; height: 44px;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 19px;
  box-shadow: 0 4px 14px -4px rgba(0,0,0,.5), inset 0 0 0 1px rgba(255,255,255,.12);
}
.risk-banner .risk-title { font-size: 16px; font-weight: 700; letter-spacing: 0.1px; }
.risk-banner .risk-sub { color: var(--text-secondary); font-size: 12.5px; margin-top: 4px; }

/* ---------- Section titles ---------- */
.section-title {
  color: var(--text);
  font-size: 12px; font-weight: 700; letter-spacing: 1.4px; text-transform: uppercase;
  margin: 32px 0 14px;
  display: flex; align-items: center; gap: 9px;
}
.section-title::before {
  content: ""; width: 3px; height: 13px; border-radius: 2px;
  background: linear-gradient(180deg, var(--accent), var(--accent-soft));
  display: inline-block;
}

/* ---------- Dashboard ---------- */
.dashboard-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-bottom: 8px; }
.dash-panel {
  background: linear-gradient(180deg, var(--panel-elevated), var(--panel));
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 16px 18px;
  box-shadow: var(--shadow-card);
  transition: border-color .18s var(--ease), transform .18s var(--ease);
}
.dash-panel:hover { border-color: #2c3038; transform: translateY(-1px); }
.dash-panel h2 {
  font-size: 11px; margin: 0 0 10px 0; color: var(--accent-soft);
  text-transform: uppercase; letter-spacing: 1.2px; font-weight: 700;
  display: flex; align-items: center; gap: 7px;
}
.dash-panel h2::before {
  content: ""; width: 6px; height: 6px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim);
}
.dash-panel div { font-size: 12.5px; color: var(--text-secondary); line-height: 1.65; }

.heatmap { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
.heat-cell {
  position: relative;
  min-height: 54px;
  border-radius: var(--radius-sm);
  padding: 9px 10px;
  color: #000000;
  font-weight: 800;
  text-shadow: none;
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.18), 0 4px 12px -6px rgba(0,0,0,.5);
  overflow: hidden;
  transition: transform .15s var(--ease);
}
.heat-cell .heat-label { display: block; font-size: 9.5px; text-transform: uppercase; letter-spacing: .5px; opacity: .85; font-weight: 800; color: #000000; }
.heat-cell .heat-count { display: block; font-size: 20px; line-height: 1.25; margin-top: 3px; font-variant-numeric: tabular-nums; color: #000000; font-weight: 800; }
.heat-cell:hover { transform: translateY(-2px); }

/* ---------- Severity summary cards ---------- */
.summary { display: flex; gap: 14px; margin-bottom: 26px; flex-wrap: wrap; }
.summary-card {
  position: relative;
  background: linear-gradient(180deg, var(--panel-elevated), var(--panel));
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 0;
  min-width: 118px;
  flex: 1;
  cursor: pointer;
  overflow: hidden;
  box-shadow: var(--shadow-card);
  transition: transform .16s var(--ease), box-shadow .16s var(--ease), border-color .16s var(--ease);
  user-select: none;
}
.summary-card .card-accent { height: 3px; width: 100%; }
.summary-card .card-body { padding: 16px 20px 18px; }
.summary-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-card-hover); border-color: #2c3038; }
.summary-card.active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent), var(--shadow-card-hover); }
.summary-card .count { font-size: 28px; font-weight: 800; line-height: 1; letter-spacing: -0.5px; font-variant-numeric: tabular-nums; }
.summary-card .label { color: var(--muted); font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.1px; margin-top: 8px; }

/* ---------- Toolbar ---------- */
.toolbar {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 20px; gap: 12px; flex-wrap: wrap;
}
.toolbar .count-label { color: var(--muted); font-size: 12px; }
.toolbar input[type=search] {
  background: var(--panel-alt); border: 1px solid var(--border); color: var(--text);
  border-radius: var(--radius-sm); padding: 10px 14px 10px 34px; font-size: 13px; min-width: 260px;
  font-family: inherit;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%23868c98' stroke-width='2'><circle cx='11' cy='11' r='7'/><line x1='21' y1='21' x2='16.65' y2='16.65'/></svg>");
  background-repeat: no-repeat; background-position: 12px center;
  transition: border-color .15s var(--ease), box-shadow .15s var(--ease);
}
.toolbar input[type=search]:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }

/* ---------- Module sections ---------- */
details.module-section {
  margin-bottom: 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--panel-alt);
  overflow: hidden;
  box-shadow: var(--shadow-card);
}
details.module-section > summary {
  cursor: pointer;
  list-style: none;
  padding: 16px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  user-select: none;
  background: linear-gradient(180deg, var(--panel-elevated), var(--panel));
  transition: background .15s var(--ease);
}
details.module-section > summary:hover { background: var(--panel-elevated); }
details.module-section > summary::-webkit-details-marker { display: none; }
details.module-section > summary::before {
  content: "";
  width: 8px; height: 8px;
  border-right: 2px solid var(--accent-soft); border-bottom: 2px solid var(--accent-soft);
  transform: rotate(-45deg);
  transition: transform .2s var(--ease);
  flex-shrink: 0;
}
details.module-section[open] > summary::before { transform: rotate(45deg); }
.module-title { font-size: 14px; font-weight: 700; letter-spacing: 0.1px; }
.module-count {
  color: var(--muted); font-size: 11px; font-weight: 600; margin-left: auto;
  background: var(--panel-alt); border: 1px solid var(--border); border-radius: 20px; padding: 3px 11px;
}
.module-sevdots { display: flex; gap: 6px; }
.module-sevdots span { width: 9px; height: 9px; border-radius: 50%; display: inline-block; box-shadow: inset 0 0 0 1px rgba(255,255,255,.14); }
.module-body { padding: 16px; display: flex; flex-direction: column; gap: 14px; }

/* ---------- Finding cards ---------- */
.finding {
  position: relative;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 20px 24px;
  transition: border-color .15s var(--ease), box-shadow .15s var(--ease);
  box-shadow: var(--shadow-card);
}
.finding::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px;
  background: var(--finding-accent, #444); border-radius: var(--radius-md) 0 0 var(--radius-md);
}
.finding:hover { border-color: #2b2f38; }
.finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  font-size: 10.5px;
  font-weight: 700;
  padding: 5px 12px;
  border-radius: 20px;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  color: #12131a;
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.22), 0 2px 6px -2px rgba(0,0,0,.4);
}
.badge .glyph { font-size: 9px; }
.finding-title { font-size: 15.5px; font-weight: 650; color: var(--text); letter-spacing: -.1px; }
.affected-count {
  color: var(--text-secondary); font-size: 11px; font-weight: 600;
  background: var(--panel-alt); border: 1px solid var(--border);
  border-radius: 20px; padding: 3px 10px;
}
.finding-meta { color: var(--muted); font-size: 11.5px; margin-bottom: 14px; letter-spacing: .1px; }
.finding-meta b { color: var(--text-secondary); font-weight: 600; }
.finding-section { font-size: 13px; margin-top: 12px; }
.finding-section .label {
  color: var(--accent-soft); font-size: 10px; text-transform: uppercase; letter-spacing: 1.1px;
  margin-bottom: 6px; font-weight: 700;
}
.finding-section > div:not(.label):not(.evidence-box) { color: var(--text-secondary); line-height: 1.6; }

/* ---------- Code / evidence blocks (terminal look) ---------- */
code, .evidence-box {
  background: #0c0d10;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 14px;
  display: block;
  font-size: 12.5px;
  font-family: 'SF Mono', 'Consolas', 'Fira Code', monospace;
  color: #e0c780;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.55;
}
.poc-section { border-top: 1px solid var(--border-soft); padding-top: 14px; margin-top: 16px; }
.poc-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.copy-btn {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--panel-alt);
  border: 1px solid var(--border);
  color: var(--muted);
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.4px;
  text-transform: uppercase;
  padding: 5px 12px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-family: inherit;
  transition: border-color .15s var(--ease), color .15s var(--ease), background .15s var(--ease);
}
.copy-btn:hover { border-color: var(--accent); color: var(--accent-soft); background: var(--accent-dim); }
.copy-btn.copied { border-color: #5fa876; color: #8fd1a4; background: rgba(95,168,118,.12); }
pre.poc {
  position: relative;
  background: #0c0d10;
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius-sm);
  padding: 14px 18px;
  font-size: 12px;
  line-height: 1.7;
  color: #c7d6bd;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 10px 0 0 0;
  font-family: 'SF Mono', 'Consolas', 'Fira Code', monospace;
}
details.files-details { margin: 0; }
details.files-details > summary {
  cursor: pointer; list-style: none; color: var(--accent-soft); font-size: 12px; font-weight: 600;
  padding: 5px 0; user-select: none; display: flex; align-items: center; gap: 6px;
}
details.files-details > summary::-webkit-details-marker { display: none; }
details.files-details > summary::before {
  content: ""; width: 6px; height: 6px;
  border-right: 2px solid var(--accent-soft); border-bottom: 2px solid var(--accent-soft);
  transform: rotate(-45deg); transition: transform .2s var(--ease); display: inline-block;
}
details.files-details[open] > summary::before { transform: rotate(45deg); }
ul.file-list {
  margin: 10px 0 0 0; padding: 12px 16px; list-style: none;
  background: #0c0d10; border: 1px solid var(--border); border-radius: var(--radius-sm);
  max-height: 260px; overflow-y: auto; font-family: 'SF Mono', monospace; font-size: 11.5px; color: var(--text-secondary);
}
ul.file-list li { padding: 4px 0; border-bottom: 1px solid var(--border-soft); word-break: break-all; }
ul.file-list li:last-child { border-bottom: none; }
.tags { display: flex; flex-wrap: wrap; gap: 6px; }
.tags span {
  display: inline-block;
  background: var(--panel-alt);
  color: var(--text-secondary);
  font-size: 10px;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 20px;
  border: 1px solid var(--border);
  transition: border-color .15s var(--ease), color .15s var(--ease);
}
.tags span:hover { border-color: var(--accent); color: var(--accent-soft); }
.confidence-low { opacity: 0.76; }
footer {
  color: var(--muted); font-size: 11.5px; margin-top: 44px; border-top: 1px solid var(--border);
  padding-top: 20px; text-align: center; letter-spacing: .1px;
}
.empty-state {
  text-align: center; color: var(--muted); padding: 56px 0; font-size: 13px;
  border: 1px dashed var(--border); border-radius: var(--radius-lg);
}
@media (max-width: 760px) {
  .dashboard-grid { grid-template-columns: 1fr; }
  .heatmap { grid-template-columns: repeat(2, 1fr); }
  .wrap { padding: 28px 18px 48px; }
}

/* ---------- Print ---------- */
@media print {
  body { background: #ffffff !important; color: #111 !important; }
  .wrap { max-width: 100%; padding: 0 12px; }
  .toolbar, .copy-btn { display: none !important; }
  details { break-inside: avoid; }
  details.module-section, .finding, .dash-panel, .summary-card, .risk-banner {
    box-shadow: none !important; border: 1px solid #ccc !important; background: #fff !important;
  }
  details.module-section > summary { background: #f4f4f4 !important; }
  code, .evidence-box, pre.poc, ul.file-list { background: #f6f6f6 !important; color: #222 !important; border-color: #ccc !important; }
  .finding-title, .module-title, header h1 { color: #111 !important; }
  .finding-meta, .dash-panel div, .toolbar .count-label { color: #444 !important; }
}
"""

_SCRIPT = """
function filterBySeverity(sev, cardEl) {
  document.querySelectorAll('.summary-card').forEach(c => c.classList.remove('active'));
  const state = window.__activeFilter;
  if (state === sev) { window.__activeFilter = null; }
  else { window.__activeFilter = sev; cardEl.classList.add('active'); }
  applyFilters();
}
function applyFilters() {
  const q = (document.getElementById('searchBox').value || '').toLowerCase();
  const sev = window.__activeFilter;
  let visible = 0;
  document.querySelectorAll('.module-section').forEach(sec => { let anyVisible = false;
    sec.querySelectorAll('.finding').forEach(f => {
      const matchesSev = !sev || f.dataset.severity === sev;
      const matchesQuery = !q || f.dataset.search.includes(q);
      const show = matchesSev && matchesQuery;
      f.style.display = show ? '' : 'none';
      if (show) { visible++; anyVisible = true; }
    });
    sec.style.display = anyVisible ? '' : 'none';
    if (anyVisible && (sev || q)) { sec.setAttribute('open', ''); }
  });
  document.getElementById('visibleCount').textContent = visible;
}
function copyPoc(btn, encoded) {
  const text = decodeURIComponent(encoded);
  const done = () => {
    const original = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1600);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}
function fallbackCopy(text, cb) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
  cb();
}
function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  const icon = document.getElementById('themeToggleIcon');
  const label = document.getElementById('themeToggleLabel');
  if (icon && label) {
    if (mode === 'light') { icon.innerHTML = '&#9789;'; label.textContent = 'Dark Mode'; }
    else { icon.innerHTML = '&#9728;'; label.textContent = 'Light Mode'; }
  }
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
  try { localStorage.setItem('warden-report-theme', next); } catch (e) {}
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('searchBox').addEventListener('input', applyFilters);
  let saved = 'dark';
  try { saved = localStorage.getItem('warden-report-theme') || 'dark'; } catch (e) {}
  applyTheme(saved);
});
"""


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _render_summary(counts: dict) -> str:
    cards = []
    for sev, count in counts.items():
        color = SEVERITY_COLORS.get(sev, "#8b8f96")
        gradient = _severity_gradient(sev)
        cards.append(
            f'<div class="summary-card" '
            f'onclick="filterBySeverity(\'{sev}\', this)">'
            f'<div class="card-accent" style="background:{gradient};"></div>'
            f'<div class="card-body">'
            f'<div class="count" style="color:{color}">{count}</div>'
            f'<div class="label">{_esc(sev)}</div></div></div>'
        )
    return f'<div class="summary">{"".join(cards)}</div>'


def _render_risk_banner(counts: dict) -> str:
    if counts.get("Critical"):
        level, icon, color, bg = "Critical Risk", "\u26A0", "#d9695f", "#2e1f1c"
        sub = f"{counts['Critical']} critical finding(s) require immediate remediation before release."
    elif counts.get("High"):
        level, icon, color, bg = "High Risk", "\u26A0", "#dd9457", "#2e2419"
        sub = f"{counts['High']} high-severity finding(s) should be remediated before release."
    elif counts.get("Medium"):
        level, icon, color, bg = "Moderate Risk", "\u25CF", "#d8bd66", "#2a2819"
        sub = f"{counts['Medium']} medium-severity finding(s) identified \u2014 review recommended."
    elif counts.get("Low"):
        level, icon, color, bg = "Low Risk", "\u25CF", "#8aa6bd", "#1c2429"
        sub = "Only low-severity findings identified \u2014 no urgent action required."
    else:
        level, icon, color, bg = "No Significant Risk", "\u2713", "#93a56e", "#1e2419"
        sub = "No findings above informational severity were identified in this scan."
    return f"""<div class="risk-banner" style="background:{bg}; border-color:{color}44;">
  <div class="risk-icon-circle" style="background:linear-gradient(135deg, {color}, {color}99); color:#12131a;">{icon}</div>
  <div>
    <div class="risk-title" style="color:{color};">{_esc(level)}</div>
    <div class="risk-sub">{_esc(sub)}</div>
  </div>
</div>"""


def _mapped_values(f: dict, mapping: dict[str, str]) -> list[str]:
    tags = set(f.get("tags", []))
    values = [v for tag, v in mapping.items() if tag in tags]
    return sorted(set(values))


def _render_dashboard(findings: list[dict], counts: dict) -> str:
    mitre = sorted({v for f in findings for v in _mapped_values(f, MITRE_BY_TAG)})
    cwes = sorted({v for f in findings for v in _mapped_values(f, CWE_BY_TAG)})
    attack_tags = sorted({t for f in findings for t in f.get("tags", []) if t in {
        "credential", "database", "auto-update", "signature", "dependency-graph", "named-pipe", "registry-key", "url"
    }})
    heat_cells = "".join(
        f'<div class="heat-cell" style="background:{_severity_gradient(sev)}">'
        f'<span class="heat-label">{_esc(sev)}</span><span class="heat-count">{_esc(count)}</span></div>'
        for sev, count in counts.items()
    )
    return f"""<div class="section-title">Assessment Overview</div>
<div class="dashboard-grid">
  <div class="dash-panel"><h2>Executive Summary</h2><div>{len(findings)} grouped finding(s). Highest active severity: {_esc(next((s for s, c in counts.items() if c), "None"))}.</div></div>
  <div class="dash-panel"><h2>Risk Heatmap</h2><div class="heatmap">{heat_cells}</div></div>
  <div class="dash-panel"><h2>Attack Surface</h2><div>{_esc(", ".join(attack_tags[:12]) or "No notable attack-surface tags detected.")}</div></div>
  <div class="dash-panel"><h2>MITRE ATT&CK</h2><div>{_esc(", ".join(mitre[:10]) or "No mapping available for current tags.")}</div></div>
  <div class="dash-panel"><h2>CWE</h2><div>{_esc(", ".join(cwes[:10]) or "No CWE mapping available for current tags.")}</div></div>
  <div class="dash-panel"><h2>Remediation Focus</h2><div>Prioritize Critical/High findings, rotate exposed credentials, validate signing trust, review privilege manifests, and harden update/dependency surfaces.</div></div>
</div>"""


def _group_findings(findings: list[dict]) -> list[dict]:
    """Collapse findings that represent the same issue (same rule +
    title + severity) into one entry, listing every affected file path
    instead of repeating the whole finding block per file. Each location's
    code context (when the module supplied one) travels with it so the
    report can still show exactly where to look for every affected file,
    not just the first one."""
    return group_finding_dicts(findings)


def _render_finding(f: dict, idx: int) -> str:
    color = SEVERITY_COLORS.get(f["severity"], "#8b8f96")
    gradient = _severity_gradient(f["severity"])
    glyph = SEVERITY_GLYPHS.get(f["severity"], "\u25CF")
    conf_class = "confidence-low" if f.get("confidence") == "Low" else ""
    tags_html = "".join(f"<span>{_esc(t)}</span>" for t in f.get("tags", []))
    mitre_html = ", ".join(_mapped_values(f, MITRE_BY_TAG))
    cwe_html = ", ".join(_mapped_values(f, CWE_BY_TAG))
    locations = f.get("locations", [f["file_path"]])
    contexts = f.get("contexts", [])
    affected_badge = f'<span class="affected-count">{len(locations)} affected file{"s" if len(locations) != 1 else ""}</span>'

    if len(locations) > 3:
        preview = "".join(f"<li>{_esc(loc)}</li>" for loc in locations)
        files_html = f"""<details class="files-details">
      <summary>Show {len(locations)} affected files</summary>
      <ul class="file-list">{preview}</ul>
    </details>"""
    else:
        files_html = "".join(f"<div class='evidence-box' style='margin-bottom:4px;'>{_esc(loc)}</div>" for loc in locations)

    # Multi-line code-context snippets (matched line + surrounding lines,
    # numbered) for each affected location that has one — this is what lets
    # an analyst pinpoint the exact spot in the file instead of just seeing
    # the bare matched string in isolation.
    context_entries = [(loc, ctx) for loc, ctx in zip(locations, contexts) if ctx]
    context_html = ""
    if context_entries:
        shown = context_entries[:3]
        blocks = "".join(
            f"<div style='margin-bottom:8px;'>"
            f"<div style='color:var(--muted); font-size:10.5px; margin-bottom:3px;'>{_esc(loc)}</div>"
            f"<pre class='evidence-box' style='margin:0;'>{_esc(ctx)}</pre>"
            f"</div>"
            for loc, ctx in shown
        )
        more_note = (
            f"<div style='color:var(--muted); font-size:11px;'>+ {len(context_entries) - 3} more location(s) with context not shown here — see Affected Files above.</div>"
            if len(context_entries) > 3 else ""
        )
        context_html = f"""<div class="finding-section">
    <div class="label">Code Context</div>
    {blocks}{more_note}
  </div>"""

    search_blob = _esc(" ".join([f["title"], f["rule_id"], f["module"]] + [l for l in locations[:50]])).lower()

    poc_html = ""
    if f.get("poc"):
        import urllib.parse
        encoded_poc = urllib.parse.quote(str(f["poc"]))
        note = ' (example \u2014 first affected file shown; repeat against each file listed above)' if len(locations) > 1 else ''
        poc_html = f"""<div class="finding-section poc-section">
    <div class="poc-head">
      <div class="label" style="margin-bottom:0;">Proof of Concept / Reproduction Steps{note}</div>
      <button class="copy-btn" onclick="copyPoc(this, '{encoded_poc}')">Copy</button>
    </div>
    <pre class="poc">{_esc(f['poc'])}</pre>
  </div>"""

    return f"""
<div class="finding {conf_class}" id="finding-{idx}" style="--finding-accent:{gradient};" data-severity="{_esc(f['severity'])}" data-search="{search_blob}">
  <div class="finding-header">
    <span class="badge" style="background:{gradient};"><span class="glyph">{glyph}</span>{_esc(f['severity'])}</span>
    <span class="finding-title">{_esc(f['title'])}</span>
    {affected_badge}
  </div>
  <div class="finding-meta">
    rule: {_esc(f['rule_id'])} &middot; confidence: {_esc(f['confidence'])}{' &middot; MITRE: ' + _esc(mitre_html) if mitre_html else ''}{' &middot; CWE: ' + _esc(cwe_html) if cwe_html else ''}
  </div>
  <div class="finding-section">
    <div class="label">Affected Files</div>
    {files_html}
  </div>
  <div class="finding-section">
    <div class="label">Evidence</div>
    <div class="evidence-box">{_esc(f['evidence'])}</div>
  </div>
  {context_html}
  <div class="finding-section">
    <div class="label">Description</div>
    <div>{_esc(f['description'])}</div>
  </div>
  <div class="finding-section">
    <div class="label">Remediation</div>
    <div>{_esc(f['remediation'])}</div>
  </div>
  {poc_html}
  <div class="finding-section tags">{tags_html}</div>
</div>
"""


def _render_module_section(module: str, findings: list[dict], start_idx: int, open_by_default: bool) -> str:
    label = MODULE_LABELS.get(module, module.replace("_", " ").title())
    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    dots = "".join(
        f'<span style="background:{_severity_gradient(s)};" title="{_esc(s)}: {c}"></span>'
        for s, c in sorted(sev_counts.items(), key=lambda kv: SEVERITY_ORDER.index(kv[0]) if kv[0] in SEVERITY_ORDER else 99)
    )
    findings_html = "".join(_render_finding(f, start_idx + i) for i, f in enumerate(findings))
    open_attr = " open" if open_by_default else ""
    return f"""<details class="module-section"{open_attr}>
  <summary>
    <span class="module-title">{_esc(label)}</span>
    <div class="module-sevdots">{dots}</div>
    <span class="module-count">{len(findings)} grouped finding{"s" if len(findings) != 1 else ""}</span>
  </summary>
  <div class="module-body">{findings_html}</div>
</details>"""


def generate_html_report(result: ScanResult, output_path: str | Path) -> Path:
    """Render `result` to a self-contained HTML file at `output_path`."""
    findings = _group_findings([f.to_dict() for f in result.sorted_findings()])
    meta = result.metadata
    counts = result.summary_counts()

    by_module: dict[str, list[dict]] = {}
    module_order: list[str] = []
    for f in findings:
        mod = f["module"]
        if mod not in by_module:
            by_module[mod] = []
            module_order.append(mod)
        by_module[mod].append(f)

    # Order modules by worst severity present, then by name, so the riskiest
    # module sections surface first.
    def _module_rank(mod: str) -> int:
        sevs = [f["severity"] for f in by_module[mod]]
        for i, sev in enumerate(SEVERITY_ORDER):
            if sev in sevs:
                return i
        return len(SEVERITY_ORDER)

    module_order.sort(key=_module_rank)

    sections_html = []
    idx = 0
    for mod in module_order:
        mod_findings = by_module[mod]
        open_default = True
        sections_html.append(_render_module_section(mod, mod_findings, idx, open_default))
        idx += len(mod_findings)

    body_html = "".join(sections_html)
    if not body_html:
        body_html = '<div class="empty-state">No findings detected by the modules run in this scan.</div>'

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Warden Scan Report</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="brand" style="justify-content:space-between;">
    <div style="display:flex;align-items:center;gap:14px;">{_BRAND_SVG}<div><div class="eyebrow">Static Security Assessment Report</div><h1>Warden</h1></div></div>
    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" type="button"><span class="icon" id="themeToggleIcon">&#9728;</span><span id="themeToggleLabel">Light Mode</span></button>
  </div>
  <div class="subtitle">Static security analysis for thick-client applications</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value mono">{_esc(meta.target_path)}</div></div>
    <div class="meta-item"><div class="meta-label">Scan Started</div><div class="meta-value">{_esc(meta.started_at)}</div></div>
    <div class="meta-item"><div class="meta-label">Scan Finished</div><div class="meta-value">{_esc(meta.finished_at)}</div></div>
    <div class="meta-item"><div class="meta-label">Files Scanned</div><div class="meta-value">{_esc(meta.files_scanned)}</div></div>
    <div class="meta-item"><div class="meta-label">Grouped Findings</div><div class="meta-value">{len(findings)}</div></div>
    <div class="meta-item"><div class="meta-label">Tool Version</div><div class="meta-value">{_esc(meta.tool_version)}</div></div>
  </div>
</header>
{_render_risk_banner(counts)}
{_render_dashboard(findings, counts)}
<div class="section-title">Severity Summary</div>
{_render_summary(counts)}
<div class="toolbar">
  <input type="search" id="searchBox" placeholder="Filter by title, rule, or file path\u2026">
  <div class="count-label">Showing <span id="visibleCount">{len(findings)}</span> of {len(findings)} grouped findings &middot; click a severity card to filter</div>
</div>
<div class="section-title">Findings Detail</div>
<div class="findings">
{body_html}
</div>
<footer>
  Generated by Warden &mdash; static-analysis-only tool for authorized VAPT engagements
  on owned/client-consented applications. No dynamic exploitation or bypass tooling included.
</footer>
</div>
<script>{_SCRIPT}</script>
</body>
</html>
"""
    output_path = Path(output_path)
    output_path.write_text(doc, encoding="utf-8")
    return output_path
