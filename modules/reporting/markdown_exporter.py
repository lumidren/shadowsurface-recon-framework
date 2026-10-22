"""
Clean GitHub-Flavored Markdown Executive Summary Generator
Generates ready-to-paste markdown reports for Jira, GitHub pull requests, or Bugcrowd/HackerOne disclosures.
"""

from typing import Dict, Any

def export_to_markdown(data: Dict[str, Any], output_md_path: str) -> str:
    """Exports scan results to formatted Markdown."""
    risk = data.get("risk_assessment", {})
    md = f"""# 🛡️ ShadowSurface Reconnaissance Report: {data.get('target')}

> **Timestamp:** {data.get('timestamp')}  
> **Posture Score:** {risk.get('posture_score', 100)}/100 | **Grade:** {risk.get('grade', 'A')}  

---

## 📊 Executive Summary

- **Total Discovered Subdomains:** {len(data.get('subdomains', []))}
- **Open Port Services:** {len([s for s in data.get('services', []) if s.get('state') == 'open'])}
- **Identified Issues:** {len(risk.get('findings', []))}

---

## 🔎 Key Findings & Vulnerabilities

| Severity | Finding | Impact |
| :--- | :--- | :--- |
"""
    for f in risk.get("findings", []):
        md += f"| **{f.get('severity', 'LOW')}** | {f.get('title', '')} | {f.get('description', '')} |
"

    md += """
---
*Generated automatically by ShadowSurface External Attack Surface Management Framework.*
"""
    with open(output_md_path, "w", encoding="utf-8") as f:
        f.write(md)

    return output_md_path
