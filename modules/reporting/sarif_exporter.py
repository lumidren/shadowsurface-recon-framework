"""
OASIS SARIF v2.1.0 Exporter
Produces standard Static Analysis Results Interchange Format for GitHub Advanced Security code scanning alerts.
"""

import json
from typing import Dict, Any

def export_to_sarif(data: Dict[str, Any], output_sarif_path: str) -> str:
    """Converts assessment findings into standard SARIF v2.1.0 JSON."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ShadowSurface EASM",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/lumidren/shadowsurface-recon-framework",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    findings = data.get("risk_assessment", {}).get("findings", [])
    for idx, f in enumerate(findings):
        rule_id = f"EASM-{idx+1:03d}"
        sarif["runs"][0]["tool"]["driver"]["rules"].append({
            "id": rule_id,
            "name": f.get("title", "Attack Surface Exposure"),
            "shortDescription": {"text": f.get("title", "")}
        })
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning",
            "message": {"text": f.get("description", f.get("title", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": data.get("target", "domain")}
                }
            }]
        })

    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    return output_sarif_path
