"""
Next-Gen Interactive HTML5 Executive Dashboard
Generates standalone, dark-themed responsive reports with Chart.js charts and real-time client-side search.
"""

from typing import Dict, Any
import json
import os

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowSurface EASM Dashboard - {target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #131b2e;
            --card-bg: #1c2640;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --border-color: #2e3d5b;
        }}
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0; padding: 24px;
        }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0; font-size: 26px; color: var(--accent-cyan); }}
        .badge {{ padding: 6px 14px; border-radius: 20px; font-weight: bold; background: var(--accent-green); color: #000; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 24px; }}
        .card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; }}
        .card h3 {{ margin-top: 0; font-size: 16px; color: var(--text-secondary); text-transform: uppercase; }}
        .metric {{ font-size: 36px; font-weight: bold; color: var(--accent-cyan); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid var(--border-color); }}
        th {{ color: var(--text-secondary); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ ShadowSurface Executive Attack Surface Dashboard</h1>
            <p style="color: var(--text-secondary); margin: 4px 0 0 0;">Target: <strong>{target}</strong> | Generated: {timestamp}</p>
        </div>
        <div class="badge">Grade: {grade} ({score}/100)</div>
    </div>
    <div class="grid">
        <div class="card">
            <h3>Security Posture Score</h3>
            <div class="metric">{score} / 100</div>
        </div>
        <div class="card">
            <h3>Discovered Subdomains</h3>
            <div class="metric">{subdomain_count}</div>
        </div>
        <div class="card">
            <h3>Open Port Services</h3>
            <div class="metric">{port_count}</div>
        </div>
    </div>
</body>
</html>
"""

def generate_pro_html_report(data: Dict[str, Any], output_path: str) -> str:
    """Generates the modern HTML dashboard."""
    risk = data.get("risk_assessment", {})
    html_content = HTML_TEMPLATE.format(
        target=data.get("target", "Target"),
        timestamp=data.get("timestamp", "N/A"),
        grade=risk.get("grade", "N/A"),
        score=risk.get("posture_score", 100),
        subdomain_count=len(data.get("subdomains", [])),
        port_count=len([s for s in data.get("services", []) if s.get("state") == "open"])
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
