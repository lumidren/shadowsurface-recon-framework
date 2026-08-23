"""
ShadowSurface Risk Analyzer & Security Scoring Engine
Quantifies external exposure risk, categorizes findings by CVSS severity, and assigns an overall Grade.
"""

from typing import Dict, Any, List

def calculate_attack_surface_risk(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Calculates weighted risk score (0-100) and produces executive metrics."""
    risk_score = 10.0  # Base exposure baseline
    findings = []

    # 1. Evaluate DNS & Email Security
    dns_data = scan_results.get("dns", {})
    for issue in dns_data.get("email_security_issues", []):
        if "Missing SPF" in issue or "Missing DMARC" in issue:
            risk_score += 12.0
            findings.append({"category": "Email Security", "title": issue, "severity": "High", "impact": "Enables domain impersonation and phishing campaigns."})
        else:
            risk_score += 6.0
            findings.append({"category": "Email Security", "title": issue, "severity": "Medium", "impact": "Suboptimal email authentication enforcement."})

    # 2. Evaluate Exposed Network Services
    services = scan_results.get("services", [])
    for s in services:
        port = s.get("port")
        srv_name = s.get("service")
        if port in [445, 3389, 6379, 27017, 9200]:
            risk_score += 20.0
            findings.append({
                "category": "Exposed Services",
                "title": f"High-Risk Port Open: {port}/{srv_name}",
                "severity": "Critical",
                "impact": "Direct external access to internal datastore or remote desktop management."
            })
        elif port in [21, 22, 3306, 5432]:
            risk_score += 10.0
            findings.append({
                "category": "Exposed Services",
                "title": f"Management Service Exposed: {port}/{srv_name}",
                "severity": "Medium",
                "impact": "Exposed authentication surface susceptible to brute-force or unpatched exploits."
            })

    # 3. Evaluate HTTP Security Headers
    http_data = scan_results.get("http", {})
    for missing in http_data.get("missing_headers", []):
        sev = missing.get("severity", "Low")
        if sev == "High":
            risk_score += 8.0
        elif sev == "Medium":
            risk_score += 5.0
        else:
            risk_score += 2.0
        findings.append({
            "category": "Web Security",
            "title": f"Missing Header: {missing.get('name')}",
            "severity": sev,
            "impact": missing.get("description")
        })

    # 4. Cap Risk Score
    final_score = min(100.0, max(0.0, risk_score))

    # Determine Letter Grade & Risk Level
    if final_score < 25:
        grade = "A"
        risk_level = "Low Risk (Hardened Posture)"
        color = "#10B981" # Green
    elif final_score < 50:
        grade = "B"
        risk_level = "Moderate Risk (Action Recommended)"
        color = "#F59E0B" # Yellow
    elif final_score < 75:
        grade = "C"
        risk_level = "Elevated Risk (Significant Exposure)"
        color = "#F97316" # Orange
    else:
        grade = "F"
        risk_level = "Critical Risk (Immediate Remediation Required)"
        color = "#EF4444" # Red

    # Count Severities
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")

    return {
        "score": round(final_score, 1),
        "posture_score": round(100.0 - final_score, 1), # 100 is best
        "grade": grade,
        "risk_level": risk_level,
        "color": color,
        "counts": {
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "total": len(findings)
        },
        "all_findings": findings
    }
