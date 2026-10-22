"""
ShadowSurface Core Orchestrator
Coordinates end-to-end 10-Phase OSINT, DNS analysis, Port/Service discovery, Web Auditing,
Cloud hunting, Vulnerability correlation, Risk Scoring, and Report Generation.
"""

from datetime import datetime
from typing import Dict, Any

from modules.dns_recon import enumerate_dns
from modules.crt_sh import enumerate_subdomains_crtsh
from modules.service_scan import scan_host_services
from modules.http_headers_audit import audit_http_posture
from modules.risk_analyzer import calculate_attack_surface_risk
from modules.report_generator import generate_reports

# Extended 100-Feature Modules Integration
from modules.osint.aggregator import aggregate_all_subdomains
from modules.osint.asn_lookup import lookup_asn
from modules.osint.whois_recon import lookup_whois_rdap
from modules.dns.dnssec import check_dnssec
from modules.dns.spf_deep import deep_analyze_spf
from modules.dns.dmarc_deep import deep_analyze_dmarc
from modules.network.port_profiles import get_ports_for_profile
from modules.network.cdn_detector import detect_cdn
from modules.network.waf_fingerprint import fingerprint_waf
from modules.web.tech_detector import detect_technologies
from modules.web.sensitive_paths import scan_sensitive_paths
from modules.cloud.s3_hunter import hunt_s3_buckets
from modules.cloud.azure_hunter import hunt_azure_blobs
from modules.vuln.cve_correlator import correlate_cves
from modules.storage.database import AssetDatabase
from modules.reporting.html_pro import generate_pro_html_report
from modules.reporting.csv_exporter import export_assets_to_csv
from modules.reporting.sarif_exporter import export_to_sarif
from modules.reporting.markdown_exporter import export_to_markdown
from modules.cli.ui import TerminalUI

def run_attack_surface_assessment(domain: str, scan_ports: bool = True, output_dir: str = "reports") -> Dict[str, Any]:
    """Executes full automated 10-phase reconnaissance lifecycle."""
    TerminalUI.header(f"SHADOWSURFACE COMPREHENSIVE ASSESSMENT: {domain.upper()}")
    TerminalUI.info(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # 1. DNS Reconnaissance & Mail Hardening
    TerminalUI.info("Phase 1/10: Resolving DNS records, DNSSEC, and deep SPF/DMARC policies...")
    dns_results = enumerate_dns(domain)
    dnssec_info = check_dnssec(domain)
    spf_info = deep_analyze_spf(domain)
    dmarc_info = deep_analyze_dmarc(domain)

    # 2. Multi-Source OSINT Subdomain Aggregation
    TerminalUI.info("Phase 2/10: Aggregating passive OSINT feeds (crt.sh, HackerTarget, OTX, RapidDNS)...")
    osint_data = aggregate_all_subdomains(domain)
    subdomains = osint_data.get("subdomains", [])
    TerminalUI.success(f"Discovered {len(subdomains)} active public subdomain(s).")

    # 3. Network Infrastructure & BGP Routing
    asn_info = {}
    primary_ip = dns_results.get("a_records", [None])[0]
    if primary_ip:
        TerminalUI.info(f"Phase 3/10: Resolving ASN, BGP prefix, and geolocation for primary IP ({primary_ip})...")
        asn_info = lookup_asn(primary_ip)

    # 4. Port & Service Discovery
    services = []
    if scan_ports and primary_ip:
        TerminalUI.info(f"Phase 4/10: Probing exposed services on primary IP ({primary_ip})...")
        services = scan_host_services(primary_ip)
        TerminalUI.success(f"Found {len(services)} open port(s)/service(s).")
    else:
        TerminalUI.warning("Phase 4/10: Skipping port scan (Passive OSINT only or no resolved A record).")

    # 5. CDN & WAF Fingerprinting
    TerminalUI.info("Phase 5/10: Fingerprinting CDN edge proxies and Web Application Firewalls...")
    cdn_info = detect_cdn(domain)
    waf_info = fingerprint_waf(domain)

    # 6. Web Technology & Sensitive Paths Crawling
    TerminalUI.info("Phase 6/10: Fingerprinting web application frameworks and probing sensitive paths...")
    tech_stack = detect_technologies(domain)
    sensitive_paths = scan_sensitive_paths(domain)

    # 7. Cloud Asset Hunting (S3 & Azure)
    TerminalUI.info("Phase 7/10: Hunting for exposed cloud buckets and shadow object storage...")
    s3_buckets = hunt_s3_buckets(domain)
    azure_blobs = hunt_azure_blobs(domain)

    # 8. HTTP Posture & Security Headers Audit
    TerminalUI.info("Phase 8/10: Auditing HTTP response headers, CSP, and HSTS defense policies...")
    http_results = audit_http_posture(domain)

    # 9. Vulnerability Correlation & Posture Scoring
    TerminalUI.info("Phase 9/10: Correlating known CVEs and calculating Attack Surface Risk Index...")
    correlated_cves = []
    for svc in services:
        banner = svc.get("banner", "")
        if banner:
            correlated_cves.extend(correlate_cves(banner))

    raw_data = {
        "target": domain,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dns": dns_results,
        "dnssec": dnssec_info,
        "spf_deep": spf_info,
        "dmarc_deep": dmarc_info,
        "asn": asn_info,
        "subdomains": subdomains,
        "services": services,
        "cdn": cdn_info,
        "waf": waf_info,
        "technologies": tech_stack,
        "sensitive_paths": sensitive_paths,
        "cloud_s3": s3_buckets,
        "cloud_azure": azure_blobs,
        "cves": correlated_cves,
        "http": http_results
    }

    risk_assessment = calculate_attack_surface_risk(raw_data)
    raw_data["risk_assessment"] = risk_assessment

    # 10. Multi-Format Enterprise Reporting & Persistence
    TerminalUI.info("Phase 10/10: Compiling deliverables (HTML Pro, JSON, CSV, SARIF, Markdown)...")
    report_files = generate_reports(raw_data, output_dir=output_dir)

    # Save to SQLite database
    db = AssetDatabase()
    db.save_scan(domain, risk_assessment.get("posture_score", 100), risk_assessment.get("grade", "A"), raw_data)

    # Generate additional exports
    base_name = f"{domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    csv_path = f"{output_dir}/{base_name}.csv"
    sarif_path = f"{output_dir}/{base_name}.sarif"
    md_path = f"{output_dir}/{base_name}.md"
    export_assets_to_csv(raw_data, csv_path)
    export_to_sarif(raw_data, sarif_path)
    export_to_markdown(raw_data, md_path)

    report_files["csv"] = csv_path
    report_files["sarif"] = sarif_path
    report_files["markdown"] = md_path
    raw_data["reports"] = report_files

    TerminalUI.print_risk_meter(risk_assessment['posture_score'], risk_assessment['grade'])
    TerminalUI.success(f"Deliverables generated: HTML, JSON, CSV, SARIF, Markdown saved to {output_dir}/")

    return raw_data
