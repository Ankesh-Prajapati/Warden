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

from core.scanner import ScanResult

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_COLORS = {
    "Critical": "#e0645c",
    "High": "#d9944f",
    "Medium": "#d0b352",
    "Low": "#6f9bd8",
    "Info": "#8b8f96",
}

MODULE_LABELS = {
    "secrets": "Secrets & Config Exposure",
    "dll_hijack": "DLL Hijacking Detection",
    "signature": "Signature / Integrity Check",
    "re_exposure": "RE / Anti-Tamper Exposure",
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
  --bg: #101113;
  --panel: #17181b;
  --panel-alt: #131416;
  --border: #24262a;
  --text: #e9eaec;
  --muted: #8b8f96;
  --accent: #6d8cf0;
  --accent-soft: #93aaf3;
}
* { box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', Arial, sans-serif;
  margin: 0;
  padding: 0;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 28px 60px; }

header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 22px;
  margin-bottom: 20px;
}
header .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
header .brand .badge-icon { display: inline-flex; line-height: 0; }
header h1 {
  color: var(--text);
  font-size: 21px;
  letter-spacing: 0.3px;
  margin: 0;
  font-weight: 600;
}
header .meta { color: var(--muted); font-size: 12.5px; line-height: 1.7; margin-top: 10px; }
header .meta b { color: var(--text); font-weight: 600; }

.risk-banner {
  border-radius: 10px;
  padding: 16px 22px;
  margin-bottom: 22px;
  border: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 16px;
}
.risk-banner .risk-icon { font-size: 26px; line-height: 1; }
.risk-banner .risk-title { font-size: 15px; font-weight: 700; letter-spacing: 0.3px; }
.risk-banner .risk-sub { color: var(--muted); font-size: 12px; margin-top: 3px; }

.summary { display: flex; gap: 12px; margin-bottom: 22px; flex-wrap: wrap; }
.summary-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 22px;
  min-width: 108px;
  flex: 1;
  cursor: pointer;
  transition: transform .12s ease, border-color .12s ease;
  user-select: none;
}
.summary-card:hover { transform: translateY(-2px); border-color: var(--accent); }
.summary-card.active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent) inset; }
.summary-card .count { font-size: 26px; font-weight: 700; line-height: 1; }
.summary-card .label { color: var(--muted); font-size: 10.5px; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; }

.toolbar {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 18px; gap: 12px; flex-wrap: wrap;
}
.toolbar .count-label { color: var(--muted); font-size: 12.5px; }
.toolbar input[type=search] {
  background: var(--panel-alt); border: 1px solid var(--border); color: var(--text);
  border-radius: 6px; padding: 8px 12px; font-size: 13px; min-width: 240px;
  font-family: inherit;
}
.toolbar input[type=search]:focus { outline: none; border-color: var(--accent); }

/* --- Module sections --- */
details.module-section {
  margin-bottom: 14px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--panel-alt);
  overflow: hidden;
}
details.module-section > summary {
  cursor: pointer;
  list-style: none;
  padding: 14px 18px;
  display: flex;
  align-items: center;
  gap: 12px;
  user-select: none;
  background: var(--panel);
}
details.module-section > summary::-webkit-details-marker { display: none; }
details.module-section > summary:before { content: "\\25B8"; color: var(--accent); font-size: 13px; width: 12px; }
details.module-section[open] > summary:before { content: "\\25BE"; }
.module-title { font-size: 13.5px; font-weight: 700; letter-spacing: 0.2px; }
.module-count { color: var(--muted); font-size: 11.5px; margin-left: auto; }
.module-sevdots { display: flex; gap: 5px; }
.module-sevdots span { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.module-body { padding: 14px; }

.finding {
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 4px solid #444;
  border-radius: 8px;
  padding: 18px 22px;
  margin-bottom: 12px;
}
.finding:last-child { margin-bottom: 0; }
.finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
.badge {
  font-size: 10.5px;
  font-weight: 700;
  padding: 4px 11px;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #101113;
}
.finding-title { font-size: 15px; font-weight: 600; color: var(--text); }
.affected-count {
  color: var(--muted); font-size: 11px; font-weight: 600;
  background: var(--panel-alt); border: 1px solid var(--border);
  border-radius: 10px; padding: 2px 9px;
}
.finding-meta { color: var(--muted); font-size: 11.5px; margin-bottom: 12px; }
.finding-section { font-size: 13px; margin-top: 10px; }
.finding-section .label { color: var(--accent-soft); font-size: 10.5px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; font-weight: 700; }
code, .evidence-box {
  background: #0b0c0d;
  border: 1px solid var(--border);
  border-radius: 5px;
  padding: 8px 12px;
  display: block;
  font-size: 12.5px;
  font-family: 'Consolas', 'SF Mono', 'Fira Code', monospace;
  color: #d7c07a;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.poc-section { border-top: 1px dashed var(--border); padding-top: 12px; margin-top: 14px; }
.poc-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.copy-btn {
  background: var(--panel-alt);
  border: 1px solid var(--border);
  color: var(--muted);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.3px;
  padding: 4px 10px;
  border-radius: 5px;
  cursor: pointer;
  font-family: inherit;
  transition: border-color .12s ease, color .12s ease;
}
.copy-btn:hover { border-color: var(--accent); color: var(--accent-soft); }
.copy-btn.copied { border-color: #7f9e7a; color: #a8c4a3; }
pre.poc {
  background: #0b0c0d;
  border: 1px solid #3a3626;
  border-left: 3px solid #93a56e;
  border-radius: 5px;
  padding: 12px 16px;
  font-size: 12px;
  line-height: 1.65;
  color: #b9d0a8;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 8px 0 0 0;
  font-family: 'Consolas', 'SF Mono', 'Fira Code', monospace;
}
details.files-details { margin: 0; }
details.files-details > summary {
  cursor: pointer; list-style: none; color: var(--muted); font-size: 12px;
  padding: 4px 0; user-select: none;
}
details.files-details > summary::-webkit-details-marker { display: none; }
details.files-details > summary:before { content: "\\25B8  "; color: var(--accent); }
details.files-details[open] > summary:before { content: "\\25BE  "; }
ul.file-list {
  margin: 8px 0 0 0; padding: 10px 14px; list-style: none;
  background: #0b0c0d; border: 1px solid var(--border); border-radius: 5px;
  max-height: 260px; overflow-y: auto; font-family: 'Consolas', monospace; font-size: 11.5px; color: #c7cbd1;
}
ul.file-list li { padding: 2px 0; border-bottom: 1px solid #2c2620; word-break: break-all; }
ul.file-list li:last-child { border-bottom: none; }
.tags span {
  display: inline-block;
  background: var(--panel-alt);
  color: var(--muted);
  font-size: 10px;
  padding: 3px 9px;
  border-radius: 10px;
  margin-right: 6px;
  margin-top: 4px;
  border: 1px solid var(--border);
}
.confidence-low { opacity: 0.72; }
footer { color: var(--muted); font-size: 11px; margin-top: 34px; border-top: 1px solid var(--border); padding-top: 16px; text-align: center; }
.empty-state { text-align: center; color: var(--muted); padding: 40px 0; font-size: 13px; }
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
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('searchBox').addEventListener('input', applyFilters);
});
"""


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _render_summary(counts: dict) -> str:
    cards = []
    for sev, count in counts.items():
        color = SEVERITY_COLORS.get(sev, "#8b8f96")
        cards.append(
            f'<div class="summary-card" style="border-top: 3px solid {color};" '
            f'onclick="filterBySeverity(\'{sev}\', this)">'
            f'<div class="count" style="color:{color}">{count}</div>'
            f'<div class="label">{_esc(sev)}</div></div>'
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
  <div class="risk-icon" style="color:{color};">{icon}</div>
  <div>
    <div class="risk-title" style="color:{color};">{_esc(level)}</div>
    <div class="risk-sub">{_esc(sub)}</div>
  </div>
</div>"""


def _group_findings(findings: list[dict]) -> list[dict]:
    """Collapse findings that represent the same vulnerability (same rule +
    title + severity) into one entry, listing every affected file path
    instead of repeating the whole finding block per file."""
    grouped: dict[tuple, dict] = {}
    order: list[tuple] = []
    for f in findings:
        key = (f["module"], f["rule_id"], f["title"], f["severity"])
        loc = f["file_path"] + (f" (line {f['line_number']})" if f.get("line_number") else "")
        if key not in grouped:
            grouped[key] = dict(f)
            grouped[key]["locations"] = [loc]
            order.append(key)
        else:
            grouped[key]["locations"].append(loc)
    return [grouped[k] for k in order]


def _render_finding(f: dict, idx: int) -> str:
    color = SEVERITY_COLORS.get(f["severity"], "#8b8f96")
    conf_class = "confidence-low" if f.get("confidence") == "Low" else ""
    tags_html = "".join(f"<span>{_esc(t)}</span>" for t in f.get("tags", []))
    locations = f.get("locations", [f["file_path"]])
    affected_badge = f'<span class="affected-count">{len(locations)} affected file{"s" if len(locations) != 1 else ""}</span>'

    if len(locations) > 3:
        preview = "".join(f"<li>{_esc(loc)}</li>" for loc in locations)
        files_html = f"""<details class="files-details">
      <summary>Show {len(locations)} affected files</summary>
      <ul class="file-list">{preview}</ul>
    </details>"""
    else:
        files_html = "".join(f"<div class='evidence-box' style='margin-bottom:4px;'>{_esc(loc)}</div>" for loc in locations)

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
<div class="finding {conf_class}" id="finding-{idx}" style="border-left-color:{color};" data-severity="{_esc(f['severity'])}" data-search="{search_blob}">
  <div class="finding-header">
    <span class="badge" style="background:{color};">{_esc(f['severity'])}</span>
    <span class="finding-title">{_esc(f['title'])}</span>
    {affected_badge}
  </div>
  <div class="finding-meta">
    rule: {_esc(f['rule_id'])} &middot; confidence: {_esc(f['confidence'])}
  </div>
  <div class="finding-section">
    <div class="label">Affected Files</div>
    {files_html}
  </div>
  <div class="finding-section">
    <div class="label">Evidence</div>
    <div class="evidence-box">{_esc(f['evidence'])}</div>
  </div>
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
        f'<span style="background:{SEVERITY_COLORS.get(s, "#8b8f96")};" title="{_esc(s)}: {c}"></span>'
        for s, c in sorted(sev_counts.items(), key=lambda kv: SEVERITY_ORDER.index(kv[0]) if kv[0] in SEVERITY_ORDER else 99)
    )
    findings_html = "".join(_render_finding(f, start_idx + i) for i, f in enumerate(findings))
    open_attr = " open" if open_by_default else ""
    return f"""<details class="module-section"{open_attr}>
  <summary>
    <span class="module-title">{_esc(label)}</span>
    <div class="module-sevdots">{dots}</div>
    <span class="module-count">{len(findings)} vulnerabilit{"y" if len(findings) == 1 else "ies"}</span>
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
        open_default = _module_rank(mod) <= 1  # auto-expand Critical/High-containing modules
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
  <div class="brand">{_BRAND_SVG}<h1>Warden &mdash; Static Security Analysis Report</h1></div>
  <div class="meta">
    Target: <b>{_esc(meta.target_path)}</b><br>
    Scan started: {_esc(meta.started_at)} &middot; finished: {_esc(meta.finished_at)}<br>
    Files scanned: <b>{_esc(meta.files_scanned)}</b> &middot; Unique vulnerabilities: <b>{len(findings)}</b> &middot; Tool version: {_esc(meta.tool_version)}
  </div>
</header>
{_render_risk_banner(counts)}
{_render_summary(counts)}
<div class="toolbar">
  <input type="search" id="searchBox" placeholder="Filter by title, rule, or file path\u2026">
  <div class="count-label">Showing <span id="visibleCount">{len(findings)}</span> of {len(findings)} vulnerabilities &middot; click a severity card to filter</div>
</div>
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
