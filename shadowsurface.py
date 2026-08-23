#!/usr/bin/env python3
"""
==============================================================================
 ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework
 Certified Ethical Hacker (CEH) Graduation Capstone Project
==============================================================================
"""

import sys
import argparse
from core.orchestrator import run_attack_surface_assessment

BANNER = r"""
  ____  _               _                 ____             __                
 / ___|| |__   __ _  __| | _____      __ / ___| _   _ _ __/ _| __ _  ___ ___ 
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / \___ \| | | | '__| |_ / _` |/ __/ _ \
  ___) | | | | (_| | (_| | (_) \ V  V /   ___) | |_| | |  |  _| (_| | (_|  __/
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |____/ \__,_|_|  |_|  \__,_|\___\___|
                                                                             
  [+] External Attack Surface Management & OSINT Reconnaissance Framework
  [+] CEH Methodology: Footprinting, Scanning, Enumeration & Vulnerability Audit
"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain to assess (e.g. example.com)")
    parser.add_argument("--no-ports", action="store_true", help="Disable active TCP port probing (Passive OSINT only)")
    parser.add_argument("-o", "--output", default="reports", help="Output directory for JSON and HTML reports (default: reports/)")

    args = parser.parse_args()
    domain = args.domain.strip().lower()

    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]

    try:
        results = run_attack_surface_assessment(
            domain=domain,
            scan_ports=not args.no_ports,
            output_dir=args.output
        )

        risk = results.get("risk_assessment", {})
        print("\n" + "=" * 65)
        print(f" 📊 ASSESSMENT EXECUTIVE SUMMARY FOR: {domain.upper()}")
        print("=" * 65)
        print(f"  Security Posture Score : {risk.get('posture_score')}/100")
        print(f"  Security Grade         : {risk.get('grade')} ({risk.get('risk_level')})")
        print(f"  Total Findings         : {risk.get('counts', {}).get('total')}")
        print(f"    - Critical Severity  : {risk.get('counts', {}).get('critical')}")
        print(f"    - High Severity      : {risk.get('counts', {}).get('high')}")
        print(f"    - Medium Severity    : {risk.get('counts', {}).get('medium')}")
        print(f"    - Low Severity       : {risk.get('counts', {}).get('low')}")
        print("=" * 65)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Assessment failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
