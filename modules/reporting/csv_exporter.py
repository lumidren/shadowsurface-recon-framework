"""
CSV and Excel-Compatible Flat File Inventory Exporter
Exports discovered subdomains, IP bindings, and open ports into clean tabular spreadsheets.
"""

import csv
from typing import Dict, Any

def export_assets_to_csv(data: Dict[str, Any], output_csv_path: str) -> str:
    """Exports asset inventory to CSV format."""
    with open(output_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target Domain", "Asset Type", "Asset Value", "Discovered Details"])

        # Subdomains
        for sub in data.get("subdomains", []):
            writer.writerow([data.get("target"), "Subdomain", sub, "Publicly Discovered"])

        # Ports
        for svc in data.get("services", []):
            if svc.get("state") == "open":
                writer.writerow([data.get("target"), "Open Port", f"{svc.get('port')}/tcp", svc.get("banner", "")])

        # Risk findings
        for issue in data.get("risk_assessment", {}).get("findings", []):
            writer.writerow([data.get("target"), "Finding", issue.get("title", ""), f"Severity: {issue.get('severity', '')}"])

    return output_csv_path
