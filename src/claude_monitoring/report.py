"""Report generation for AI Runtime Monitor.

Generates shareable summary reports in Markdown, HTML, and CSV formats.
"""

import csv
import io
import json
import sqlite3
from pathlib import Path

from claude_monitoring.utils import now_iso


def generate_summary_report(db_path, period_days: int = 7, fmt: str = "html") -> str:
    """Generate a summary report for the given period.

    Args:
        db_path: Path to the SQLite database.
        period_days: Number of days to include (default 7).
        fmt: Output format - "html", "markdown", or "csv".

    Returns:
        Report content as a string.
    """
    db = sqlite3.connect(str(db_path))
    db.row_factory = sqlite3.Row
    stats = _gather_period_stats(db, period_days)
    db.close()

    if fmt == "html":
        return _render_standalone_html(stats, period_days)
    elif fmt == "csv":
        return _render_csv(stats)
    else:
        return _render_markdown(stats, period_days)


def _gather_period_stats(db, period_days: int) -> dict:
    """Query the database for period statistics."""
    since = f"-{period_days} days"

    # Sessions summary
    sessions = db.execute(
        """SELECT COUNT(*) as count,
                  COALESCE(SUM(total_input_tokens), 0) as input_tokens,
                  COALESCE(SUM(total_output_tokens), 0) as output_tokens,
                  COALESCE(SUM(total_turns), 0) as turns
           FROM sessions WHERE last_activity >= datetime('now', ?)""",
        (since,),
    ).fetchone()

    # Model breakdown
    models = db.execute(
        """SELECT model, COUNT(*) as sessions,
                  COALESCE(SUM(total_input_tokens), 0) as input_tokens,
                  COALESCE(SUM(total_output_tokens), 0) as output_tokens
           FROM sessions
           WHERE model IS NOT NULL AND model != '' AND last_activity >= datetime('now', ?)
           GROUP BY model ORDER BY sessions DESC""",
        (since,),
    ).fetchall()

    # Top tools
    tools = db.execute(
        """SELECT json_extract(data_json, '$.name') as tool, COUNT(*) as cnt
           FROM events
           WHERE event_type = 'tool_use' AND timestamp >= datetime('now', ?)
           GROUP BY tool ORDER BY cnt DESC LIMIT 15""",
        (since,),
    ).fetchall()

    # Projects
    projects = db.execute(
        """SELECT cwd, COUNT(*) as sessions,
                  COALESCE(SUM(total_turns), 0) as turns
           FROM sessions
           WHERE cwd IS NOT NULL AND cwd != '' AND last_activity >= datetime('now', ?)
           GROUP BY cwd ORDER BY sessions DESC""",
        (since,),
    ).fetchall()

    # Alerts
    alerts = db.execute(
        """SELECT json_extract(data_json, '$.severity') as severity, COUNT(*) as cnt
           FROM events
           WHERE event_type = 'sensitive_data' AND timestamp >= datetime('now', ?)
           GROUP BY severity ORDER BY cnt DESC""",
        (since,),
    ).fetchall()

    # Daily breakdown
    daily = db.execute(
        """SELECT date(timestamp) as day,
                  COALESCE(SUM(json_extract(data_json, '$.input_tokens')), 0) as input_tokens,
                  COALESCE(SUM(json_extract(data_json, '$.output_tokens')), 0) as output_tokens
           FROM events
           WHERE event_type = 'token_usage' AND timestamp >= datetime('now', ?)
           GROUP BY day ORDER BY day""",
        (since,),
    ).fetchall()

    return {
        "sessions": dict(sessions),
        "models": [dict(m) for m in models],
        "tools": [dict(t) for t in tools],
        "projects": [dict(p) for p in projects],
        "alerts": [dict(a) for a in alerts],
        "daily": [dict(d) for d in daily],
        "generated_at": now_iso(),
    }


def _render_markdown(stats: dict, period_days: int) -> str:
    """Render report as Markdown tables."""
    s = stats["sessions"]
    lines = [
        f"# AI Runtime Monitor Report ({period_days}-day)",
        "",
        f"Generated: {stats['generated_at']}",
        "",
        "## Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Sessions | {s['count']} |",
        f"| Total Turns | {s['turns']} |",
        f"| Input Tokens | {s['input_tokens']:,} |",
        f"| Output Tokens | {s['output_tokens']:,} |",
        "",
    ]

    if stats["models"]:
        lines.extend([
            "## Models",
            "",
            "| Model | Sessions | Input Tokens | Output Tokens |",
            "|-------|----------|--------------|---------------|",
        ])
        for m in stats["models"]:
            lines.append(
                f"| {m['model']} | {m['sessions']} | {m['input_tokens']:,} | {m['output_tokens']:,} |"
            )
        lines.append("")

    if stats["tools"]:
        lines.extend([
            "## Top Tools",
            "",
            "| Tool | Calls |",
            "|------|-------|",
        ])
        for t in stats["tools"]:
            lines.append(f"| {t['tool']} | {t['cnt']} |")
        lines.append("")

    if stats["projects"]:
        lines.extend([
            "## Projects",
            "",
            "| Project | Sessions | Turns |",
            "|---------|----------|-------|",
        ])
        for p in stats["projects"]:
            proj_name = Path(p["cwd"]).name if p["cwd"] else "unknown"
            lines.append(f"| {proj_name} | {p['sessions']} | {p['turns']} |")
        lines.append("")

    if stats["alerts"]:
        lines.extend([
            "## Alerts",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        for a in stats["alerts"]:
            lines.append(f"| {a['severity']} | {a['cnt']} |")
        lines.append("")

    if stats["daily"]:
        lines.extend([
            "## Daily Breakdown",
            "",
            "| Day | Input Tokens | Output Tokens |",
            "|-----|--------------|---------------|",
        ])
        for d in stats["daily"]:
            lines.append(
                f"| {d['day']} | {int(d['input_tokens'] or 0):,} | {int(d['output_tokens'] or 0):,} |"
            )
        lines.append("")

    return "\n".join(lines)


def _render_standalone_html(stats: dict, period_days: int) -> str:
    """Render report as a standalone HTML document with inline CSS and Chart.js."""
    s = stats["sessions"]
    daily = stats["daily"]

    # Build chart data
    daily_labels = json.dumps([d["day"] for d in daily])
    daily_input = json.dumps([int(d["input_tokens"] or 0) for d in daily])
    daily_output = json.dumps([int(d["output_tokens"] or 0) for d in daily])

    tool_labels = json.dumps([t["tool"] or "unknown" for t in stats["tools"][:10]])
    tool_counts = json.dumps([t["cnt"] for t in stats["tools"][:10]])

    # Models table rows
    models_rows = ""
    for m in stats["models"]:
        models_rows += f"<tr><td>{m['model']}</td><td>{m['sessions']}</td><td>{m['input_tokens']:,}</td><td>{m['output_tokens']:,}</td></tr>"

    # Projects table rows
    projects_rows = ""
    for p in stats["projects"]:
        proj_name = Path(p["cwd"]).name if p["cwd"] else "unknown"
        projects_rows += f"<tr><td>{proj_name}</td><td>{p['sessions']}</td><td>{p['turns']}</td></tr>"

    # Alerts summary
    alert_html = ""
    total_alerts = sum(a["cnt"] for a in stats["alerts"])
    if stats["alerts"]:
        alert_items = ", ".join(f"{a['severity']}: {a['cnt']}" for a in stats["alerts"])
        alert_html = f'<div class="alert-box">{total_alerts} alerts ({alert_items})</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Runtime Monitor - {period_days}-Day Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
  h2 {{ color: #c9d1d9; margin-top: 32px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat .label {{ font-size: 12px; color: #8b949e; text-transform: uppercase; }}
  .stat .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
  .blue {{ color: #58a6ff; }} .green {{ color: #3fb950; }} .red {{ color: #f85149; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }}
  th {{ color: #8b949e; font-size: 12px; text-transform: uppercase; }}
  .chart-container {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 16px 0; }}
  .charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .alert-box {{ background: #f8514922; border: 1px solid #f85149; border-radius: 8px; padding: 12px 16px; margin: 12px 0; color: #f85149; }}
  .footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #30363d; font-size: 12px; color: #8b949e; }}
  @media (max-width: 768px) {{ .charts-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<h1>AI Runtime Monitor Report</h1>
<p style="color:#8b949e">Period: {period_days} days | Generated: {stats['generated_at']}</p>

<div class="stats">
  <div class="stat"><div class="label">Sessions</div><div class="value blue">{s['count']}</div></div>
  <div class="stat"><div class="label">Total Turns</div><div class="value">{s['turns']}</div></div>
  <div class="stat"><div class="label">Input Tokens</div><div class="value">{s['input_tokens']:,}</div></div>
  <div class="stat"><div class="label">Output Tokens</div><div class="value">{s['output_tokens']:,}</div></div>
  <div class="stat"><div class="label">Alerts</div><div class="value red">{total_alerts}</div></div>
</div>

{alert_html}

<div class="charts-grid">
  <div class="chart-container"><h3>Daily Usage</h3><canvas id="chart-daily"></canvas></div>
  <div class="chart-container"><h3>Top Tools</h3><canvas id="chart-tools"></canvas></div>
</div>

<h2>Models</h2>
<table><thead><tr><th>Model</th><th>Sessions</th><th>Input Tokens</th><th>Output Tokens</th></tr></thead>
<tbody>{models_rows}</tbody></table>

<h2>Projects</h2>
<table><thead><tr><th>Project</th><th>Sessions</th><th>Turns</th></tr></thead>
<tbody>{projects_rows}</tbody></table>

<div class="footer">Generated by AI Runtime Monitor</div>

<script>
const chartOpts = {{responsive:true,plugins:{{legend:{{labels:{{color:'#e6edf3'}}}}}},scales:{{x:{{ticks:{{color:'#8b949e'}}}},y:{{ticks:{{color:'#8b949e'}}}}}}}};

new Chart(document.getElementById('chart-daily'), {{
  type:'bar', data:{{
    labels:{daily_labels},
    datasets:[
      {{label:'Input',data:{daily_input},backgroundColor:'rgba(88,166,255,0.7)'}},
      {{label:'Output',data:{daily_output},backgroundColor:'rgba(63,185,80,0.7)'}}
    ]
  }}, options:{{...chartOpts,scales:{{x:{{stacked:true,ticks:{{color:'#8b949e'}}}},y:{{stacked:true,ticks:{{color:'#8b949e'}}}}}}}}
}});

const colors = ['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#39d2c0','#f0883e','#a5d6ff'];
new Chart(document.getElementById('chart-tools'), {{
  type:'bar', data:{{
    labels:{tool_labels},
    datasets:[{{label:'Calls',data:{tool_counts},backgroundColor:colors.slice(0,{len(stats['tools'][:10])})}}]
  }}, options:{{...chartOpts,indexAxis:'y'}}
}});
</script>
</body>
</html>"""


def _render_csv(stats: dict) -> str:
    """Render daily breakdown as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["day", "input_tokens", "output_tokens"])
    for d in stats["daily"]:
        writer.writerow([d["day"], int(d["input_tokens"] or 0), int(d["output_tokens"] or 0)])
    return output.getvalue()
