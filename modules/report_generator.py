"""
ShadowSurface Report Generator Module
Compiles assessment results into machine-readable JSON and styled HTML dashboards.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any

try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


def generate_reports(scan_data: Dict[str, Any], output_dir: str = "reports") -> Dict[str, str]:
    """Saves scan results to JSON and HTML formats."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    domain = scan_data.get("target", "target_scan")
    timestamp_slug = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    json_path = os.path.join(output_dir, f"{domain}_{timestamp_slug}.json")
    html_path = os.path.join(output_dir, f"{domain}_{timestamp_slug}.html")

    # 1. Write JSON Report
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2)

    # 2. Write HTML Report
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "report_template.html")
    if os.path.exists(template_path) and JINJA_AVAILABLE:
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template_str = f.read()

            template = Template(template_str)
            rendered_html = template.render(
                target=scan_data.get("target"),
                timestamp=scan_data.get("timestamp"),
                risk=scan_data.get("risk_assessment", {}),
                services=scan_data.get("services", []),
                subdomains=scan_data.get("subdomains", []),
                dns=scan_data.get("dns", {}),
                http=scan_data.get("http", {})
            )

            with open(html_path, "w", encoding="utf-8") as f:
                f.write(rendered_html)
        except Exception as e:
            print(f"[!] HTML rendering error: {e}")
            html_path = ""
    else:
        html_path = ""

    return {
        "json_report": json_path,
        "html_report": html_path
    }
