"""
ShadowSurface Core Orchestrator
Coordinates end-to-end OSINT, DNS analysis, Port/Service discovery, HTTP Auditing, Risk Scoring, and Report Generation.
"""

from datetime import datetime
from typing import Dict, Any

from modules.dns_recon import enumerate_dns
from modules.crt_sh import enumerate_subdomains_crtsh
from modules.service_scan import scan_host_services
from modules.http_headers_audit import audit_http_posture
from modules.risk_analyzer import calculate_attack_surface_risk
from modules.report_generator import generate_reports

def run_attack_surface_assessment(domain: str, scan_ports: bool = True, output_dir: str = "reports") -> Dict[str, Any]:
    """Executes full automated reconnaissance lifecycle."""
    print(f"\n[*] Initiating ShadowSurface Assessment for: {domain}")
    print(f"[*] Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # 1. DNS Reconnaissance
    print("[+] Phase 1/4: Querying DNS records and email security policies (SPF/DMARC)...")
    dns_results = enumerate_dns(domain)

    # 2. Passive Subdomain Discovery via CT logs
    print("[+] Phase 2/4: Querying Certificate Transparency logs (crt.sh)...")
    subdomains = enumerate_subdomains_crtsh(domain)
    print(f"    -> Discovered {len(subdomains)} active public subdomain(s).")

    # 3. Port & Service Discovery
    services = []
    if scan_ports and dns_results.get("a_records"):
        target_ip = dns_results["a_records"][0]
        print(f"[+] Phase 3/4: Probing high-value exposed services on primary IP ({target_ip})...")
        services = scan_host_services(target_ip)
        print(f"    -> Found {len(services)} open port(s)/service(s).")
    else:
        print("[!] Phase 3/4: Skipping port scan (No resolved A record or disabled).")

    # 4. Web & HTTP Security Headers Audit
    print("[+] Phase 4/4: Auditing HTTP response headers and web exposure...")
    http_results = audit_http_posture(domain)

    # 5. Risk Scoring & Quantification
    raw_data = {
        "target": domain,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dns": dns_results,
        "subdomains": subdomains,
        "services": services,
        "http": http_results
    }

    print("[*] Calculating Attack Surface Risk Index & Posture Grade...")
    risk_assessment = calculate_attack_surface_risk(raw_data)
    raw_data["risk_assessment"] = risk_assessment

    # 6. Report Compilation
    report_files = generate_reports(raw_data, output_dir=output_dir)
    raw_data["reports"] = report_files

    print(f"[+] Assessment completed. Posture Score: {risk_assessment['posture_score']}/100 (Grade: {risk_assessment['grade']})")
    if report_files.get("html_report"):
        print(f"[+] Interactive Dashboard saved to: {report_files['html_report']}")

    return raw_data
