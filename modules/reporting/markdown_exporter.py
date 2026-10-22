"""
Clean GitHub-Flavored Markdown Executive Summary Generator
Generates ready-to-paste markdown reports for Jira, GitHub pull requests, or Bugcrowd/HackerOne disclosures.
"""

from typing import Dict, Any

def export_to_markdown(data: Dict[str, Any], output_md_path: str) -> str:
    """Exports scan results to formatted Markdown."""
    risk = data.get("risk_assessment", {})
    md_lines = [
        f"# 🛡️ ShadowSurface Reconnaissance Report: {data.get('target')}",
        "",
        f"> **Timestamp:** {data.get('timestamp')}",
        f"> **Posture Score:** {risk.get('posture_score', 100)}/100 | **Grade:** {risk.get('grade', 'A')}",
        "",
        "---",
        "",
        "## 📊 Executive Summary",
        "",
        f"- **Total Discovered Subdomains:** {len(data.get('subdomains', []))}",
        f"- **Open Port Services:** {len([s for s in data.get('services', []) if s.get('state') == 'open'])}",
        f"- **Identified Issues:** {len(risk.get('findings', []))}",
        "",
        "---",
        "",
        "## 🔎 Key Findings & Vulnerabilities",
        "",
        "| Severity | Finding | Impact |",
        "| :--- | :--- | :--- |"
    ]

    for f in risk.get("findings", []):
        sev = f.get("severity", "LOW")
        title = f.get("title", "")
        desc = f.get("description", "")
        md_lines.append(f"| **{sev}** | {title} | {desc} |")

    md_lines.append("")
    md_lines.append("---")
    md_lines.append("*Generated automatically by ShadowSurface External Attack Surface Management Framework.*")

    with open(output_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    return output_md_path
