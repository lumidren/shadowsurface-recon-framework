#!/usr/bin/env python3
"""
==============================================================================
 ShadowSurface: 1-Click Live Demonstration & Presentation Script
 Runs a live assessment or loads a rich simulated enterprise scan for presentations.
==============================================================================
"""

import os
import sys
import webbrowser
from core.orchestrator import run_attack_surface_assessment
from modules.risk_analyzer import calculate_attack_surface_risk
from modules.report_generator import generate_reports

def run_simulated_enterprise_demo():
    """Generates a rich, multi-finding simulated enterprise assessment for presentation demos."""
    print("\n[*] Loading Presentation Demo Scenario: 'corp-global-fintech.com'...")

    simulated_data = {
        "target": "corp-global-fintech.com",
        "timestamp": "2026-08-23 09:30:00 UTC",
        "dns": {
            "domain": "corp-global-fintech.com",
            "a_records": ["198.51.100.42", "198.51.100.43"],
            "mx_records": ["10 mail.corp-global-fintech.com", "20 backup-mx.corp-global-fintech.com"],
            "ns_records": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            "txt_records": ["v=spf1 include:_spf.google.com ~all"],
            "spf_status": "Moderate (SoftFail ~all)",
            "dmarc_status": "Missing",
            "email_security_issues": [
                "Missing DMARC record: Domain lacks email spoofing protection policy.",
                "SPF policy uses SoftFail (~all), allowing email spoofing acceptance on some gateways."
            ]
        },
        "subdomains": [
            "vpn.corp-global-fintech.com",
            "admin-portal.corp-global-fintech.com",
            "dev-api.corp-global-fintech.com",
            "grafana.corp-global-fintech.com",
            "jenkins.corp-global-fintech.com",
            "staging-db.corp-global-fintech.com",
            "auth.corp-global-fintech.com"
        ],
        "services": [
            {"port": 80, "service": "HTTP", "state": "open", "banner": "HTTP/1.1 301 Moved Permanently", "risk_tag": "Informational"},
            {"port": 443, "service": "HTTPS", "state": "open", "banner": "HTTP/1.1 200 OK (nginx/1.18.0)", "risk_tag": "Informational"},
            {"port": 22, "service": "SSH", "state": "open", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu", "risk_tag": "Medium Risk (Direct Management / DB Exposure)"},
            {"port": 3389, "service": "RDP (Remote Desktop)", "state": "open", "banner": "Remote Desktop Protocol Active", "risk_tag": "High Risk (Exposed Internal Service)"},
            {"port": 8080, "service": "HTTP-Proxy / Jenkins / Tomcat", "state": "open", "banner": "Jenkins Admin Dashboard 2.3", "risk_tag": "Informational"}
        ],
        "http": {
            "target_url": "https://corp-global-fintech.com",
            "status_code": 200,
            "server_banner": "nginx/1.18.0 (Ubuntu)",
            "powered_by": "PHP/7.4.3",
            "missing_headers": [
                {"header": "Content-Security-Policy", "name": "CSP (Content Security Policy)", "severity": "High", "description": "Mitigates Cross-Site Scripting (XSS) and data injection."},
                {"header": "Strict-Transport-Security", "name": "HSTS", "severity": "Medium", "description": "Protects against SSL stripping and downgrade attacks."},
                {"header": "X-Frame-Options", "name": "X-Frame-Options", "severity": "Medium", "description": "Prevents unauthorized UI redressing / clickjacking."}
            ],
            "present_headers": {"X-Content-Type-Options": "nosniff"}
        }
    }

    # Calculate Risk Score
    risk = calculate_attack_surface_risk(simulated_data)
    simulated_data["risk_assessment"] = risk

    # Compile Reports
    reports = generate_reports(simulated_data, output_dir="reports")
    simulated_data["reports"] = reports

    print("\n" + "=" * 65)
    print(f" [*] ASSESSMENT EXECUTIVE SUMMARY FOR: {simulated_data['target'].upper()}")
    print("=" * 65)
    print(f"  Security Posture Score : {risk.get('posture_score')}/100")
    print(f"  Security Grade         : {risk.get('grade')} ({risk.get('risk_level')})")
    print(f"  Total Findings         : {risk.get('counts', {}).get('total')}")
    print(f"    - Critical Severity  : {risk.get('counts', {}).get('critical')}")
    print(f"    - High Severity      : {risk.get('counts', {}).get('high')}")
    print(f"    - Medium Severity    : {risk.get('counts', {}).get('medium')}")
    print(f"    - Low Severity       : {risk.get('counts', {}).get('low')}")
    print("=" * 65)

    html_file = reports.get("html_report")
    if html_file and os.path.exists(html_file):
        print(f"\n[+] Interactive visual dashboard generated: {html_file}")
        try:
            webbrowser.open(f"file://{os.path.abspath(html_file)}")
        except Exception:
            pass

def main():
    print("=" * 65)
    print(" [SHADOWSURFACE] LIVE DEMONSTRATION RUNNER")
    print("=" * 65)
    print("  [1] Run Simulated Enterprise Presentation Demo (Recommended for Demo)")
    print("  [2] Run Live Scan on Custom Domain")
    print("  [Q] Quit")
    
    choice = input("\nEnter choice [1/2/Q]: ").strip()
    if choice == "1":
        run_simulated_enterprise_demo()
    elif choice == "2":
        target = input("Enter target domain (e.g. scanme.nmap.org): ").strip()
        if target:
            run_attack_surface_assessment(target)
    else:
        print("Exiting.")

if __name__ == "__main__":
    main()
