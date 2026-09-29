"""Generate a self-contained, safely escaped HTML report."""
from html import escape
from pathlib import Path

def render_html(report):
    counts=report.get("summary",{}).get("by_severity",{})
    cards="".join('<div class="metric"><b>'+escape(str(counts.get(level,0)))+'</b><span>'+escape(level.title())+'</span></div>' for level in ("critical","high","medium","low","info"))
    rows=[]
    for f in report.get("findings",[]):
        if f.get("suppressed"): continue
        sev=escape(str(f.get("severity","info")).lower())
        rows.append('<tr><td><span class="sev '+sev+'">'+sev.upper()+'</span></td><td><code>'+escape(str(f.get("rule","")))+'</code></td><td><code>'+escape(str(f.get("file","")))+':'+escape(str(f.get("line","")))+'</code></td><td>'+escape(str(f.get("message","")))+'<details><summary>Remediation</summary>'+escape(str(f.get("remediation","")))+'</details></td></tr>')
    body="".join(rows) or '<tr><td colspan="4">No unsuppressed findings in this report.</td></tr>'
    target=escape(str(report.get("target","")),quote=True)
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnLens Security Report</title><style>
:root{color-scheme:light dark;font:16px system-ui,sans-serif}body{max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5}h1{margin-bottom:.2rem}.muted{opacity:.7}.metrics{display:flex;gap:.75rem;flex-wrap:wrap;margin:1.5rem 0}.metric{border:1px solid #8886;border-radius:12px;padding:1rem;min-width:90px;display:grid}.metric b{font-size:1.7rem}.sev{font-weight:700}.critical,.high{color:#e66}.medium{color:#db9b25}.low{color:#5a9}.info{color:#79aaff}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:.75rem;border-bottom:1px solid #8885}th{position:sticky;top:0;background:Canvas}code{overflow-wrap:anywhere}details{margin-top:.4rem}footer{margin-top:2rem;font-size:.9rem;opacity:.75}</style></head><body>
<h1>VulnLens Security Report</h1><p class="muted">Target: <code>"""+target+"""</code> · Version """+escape(str(report.get("version","")))+"""</p>
<div class="metrics">"""+cards+"""</div><p>"""+escape(str(report.get("notice","Heuristic scan; review findings manually.")))+"""</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Finding</th></tr></thead><tbody>"""+body+"""</tbody></table>
<footer>Generated locally by VulnLens. This report may contain sensitive repository paths; review before sharing.</footer></body></html>"""

def write_html(report, destination):
    Path(destination).write_text(render_html(report),encoding="utf-8")
