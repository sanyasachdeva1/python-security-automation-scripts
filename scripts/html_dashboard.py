import argparse
import html
from pathlib import Path

try:
    from soc_common import sort_findings, summarize_findings
    from soc_triage import analyze_workspace
except ModuleNotFoundError:
    from scripts.soc_common import sort_findings, summarize_findings
    from scripts.soc_triage import analyze_workspace


SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#0369a1",
    "INFO": "#475569",
}


def render_dashboard(findings):
    findings = sort_findings(findings)
    summary = summarize_findings(findings)
    cards = "\n".join(
        f"<section class='metric'><span>{severity}</span><strong>{summary.get(severity, 0)}</strong></section>"
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    rows = "\n".join(
        "<tr>"
        f"<td><span class='badge' style='background:{SEVERITY_COLORS.get(f.severity, '#475569')}'>{f.severity}</span></td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{f.risk_score}/100</td>"
        f"<td>{html.escape(f.source)}</td>"
        f"<td>{html.escape(', '.join(f.mitre_attack))}</td>"
        f"<td>{html.escape(f.recommendation)}</td>"
        "</tr>"
        for f in findings
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOC Dashboard Report</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #111827; background: #f8fafc; }}
    header {{ padding: 28px 36px; background: #111827; color: #f9fafb; }}
    h1 {{ margin: 0; font-size: 28px; }}
    main {{ padding: 28px 36px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 24px; }}
    .metric {{ background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; }}
    .metric span {{ display: block; font-size: 12px; color: #64748b; }}
    .metric strong {{ font-size: 30px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    th {{ font-size: 12px; color: #475569; background: #f1f5f9; }}
    .badge {{ color: white; border-radius: 999px; padding: 4px 8px; font-size: 12px; font-weight: bold; }}
  </style>
</head>
<body>
  <header><h1>SOC & Incident Response Dashboard</h1></header>
  <main>
    <section class="metrics">{cards}</section>
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Risk</th><th>Source</th><th>MITRE ATT&CK</th><th>Recommendation</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </main>
</body>
</html>
"""


def build_parser():
    parser = argparse.ArgumentParser(description="Generate an HTML SOC dashboard report.")
    parser.add_argument("--data-dir", default="sample-data", help="Directory containing sample data.")
    parser.add_argument("--output", default="reports/soc_dashboard.html", help="Output HTML path.")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_dashboard(analyze_workspace(args.data_dir)), encoding="utf-8")
    print(f"Wrote HTML dashboard to {output}")
