#!/usr/bin/env python3
"""
==============================================================================
 ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework
 Production-Grade Enterprise Attack Surface Management (EASM) System
==============================================================================
"""

import sys
import argparse
from colorama import Fore, Style, init

from core.orchestrator import run_attack_surface_assessment
from modules.cli.ui import TerminalUI
from modules.cli.repl import start_interactive_shell
from modules.monitoring.cli_diff import compare_json_reports
from modules.monitoring.watchlist import WatchlistManager
from modules.monitoring.daemon_runner import MonitoringDaemon

init(autoreset=True)

BANNER = rf"""{Fore.CYAN}{Style.BRIGHT}
   ____  _               _                 ____             __                
  / ___|| |__   __ _  __| | _____      __ / ___| _   _ _ __/ _| __ _  ___ ___ 
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / \___ \| | | | '__| |_ / _` |/ __/ _ \
   ___) | | | | (_| | (_| | (_) \ V  V /   ___) | |_| | |  |  _| (_| | (_|  __/
  |____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |____/ \__,_|_|  |_|  \__,_|\___\___|
{Fore.GREEN}
   [+] Enterprise External Attack Surface Management (EASM) & OSINT Framework
   [+] 10-Phase Pipeline: Footprinting, Discovery, DNSSEC, Cloud, CVEs & Risk Scoring
   [+] Deliverables: Executive HTML5 Dashboard, JSON, CSV, SARIF & Markdown
{Style.RESET_ALL}"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework"
    )
    parser.add_argument("-d", "--domain", help="Target domain to assess (e.g. example.com)")
    parser.add_argument("--no-ports", action="store_true", help="Disable active TCP port probing (Passive OSINT only)")
    parser.add_argument("--profile", default="top20", choices=["top20", "top100", "top1000", "web", "database", "infra"],
                        help="Port scanning profile presets (default: top20)")
    parser.add_argument("-o", "--output", default="reports", help="Output directory for reports (default: reports/)")
    parser.add_argument("--shell", action="store_true", help="Launch interactive REPL investigation shell")
    parser.add_argument("--diff", nargs=2, metavar=("REPORT_A", "REPORT_B"), help="Compare two JSON scan reports and show asset drift")
    parser.add_argument("--watchlist", help="Run batch assessment on target domains listed in a file")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous daily monitoring daemon mode")
    parser.add_argument("--interval", type=int, default=86400, help="Daemon interval in seconds (default: 86400 / 24h)")

    args = parser.parse_args()

    # 1. Interactive Shell Mode
    if args.shell:
        start_interactive_shell(target_domain=args.domain)
        sys.exit(0)

    # 2. Diff Mode
    if args.diff:
        TerminalUI.header("HISTORICAL SCAN COMPARISON & DRIFT AUDIT")
        try:
            diff = compare_json_reports(args.diff[0], args.diff[1])
            print(f" Target Domain       : {diff.get('target')}")
            print(f" Drift Detected      : {diff.get('has_drift')}")
            print(f" Score Delta         : {diff.get('score_delta'):+d}")
            print(f" New Subdomains      : {len(diff.get('new_subdomains', []))} -> {diff.get('new_subdomains')}")
            print(f" Removed Subdomains  : {len(diff.get('removed_subdomains', []))} -> {diff.get('removed_subdomains')}")
            print(f" Newly Opened Ports  : {len(diff.get('new_open_ports', []))} -> {diff.get('new_open_ports')}")
            print(f" Closed Ports        : {len(diff.get('closed_ports', []))} -> {diff.get('closed_ports')}")
            print("=" * 65)
        except Exception as e:
            TerminalUI.warning(f"Failed to compare reports: {e}")
            sys.exit(1)
        sys.exit(0)

    # 3. Watchlist Mode
    if args.watchlist:
        wm = WatchlistManager(args.watchlist)
        targets = wm.get_targets()
        if not targets:
            TerminalUI.warning(f"No valid targets found in watchlist: {args.watchlist}")
            sys.exit(1)
        TerminalUI.info(f"Loaded {len(targets)} target(s) from watchlist: {args.watchlist}")
        for t in targets:
            try:
                run_attack_surface_assessment(domain=t, scan_ports=not args.no_ports, output_dir=args.output)
            except Exception as e:
                TerminalUI.warning(f"Assessment failed for target {t}: {e}")
        sys.exit(0)

    # 4. Domain Assessment Mode
    if not args.domain:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Error: Either -d/--domain, --shell, --diff, or --watchlist is required.{Style.RESET_ALL}")
        sys.exit(1)

    domain = args.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]

    def execute_scan():
        try:
            results = run_attack_surface_assessment(
                domain=domain,
                scan_ports=not args.no_ports,
                output_dir=args.output
            )
            risk = results.get("risk_assessment", {})
            counts = risk.get("counts", {})
            TerminalUI.header(f"ASSESSMENT EXECUTIVE SUMMARY FOR: {domain.upper()}")
            print(f"  Security Posture Score : {risk.get('posture_score')}/100")
            print(f"  Security Grade         : {risk.get('grade')} ({risk.get('risk_level')})")
            print(f"  Total Findings         : {counts.get('total')}")
            print(f"    - Critical Severity  : {counts.get('critical')}")
            print(f"    - High Severity      : {counts.get('high')}")
            print(f"    - Medium Severity    : {counts.get('medium')}")
            print(f"    - Low Severity       : {counts.get('low')}")
            print("=" * 65)
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            sys.exit(0)
        except Exception as e:
            TerminalUI.warning(f"Assessment failed: {e}")
            sys.exit(1)

    if args.daemon:
        TerminalUI.info(f"Starting continuous daily monitoring daemon for {domain} (Interval: {args.interval}s)...")
        daemon = MonitoringDaemon(interval_seconds=args.interval)
        daemon.run_loop(execute_scan)
    else:
        execute_scan()

if __name__ == "__main__":
    main()
