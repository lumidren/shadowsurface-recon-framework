# 🛡️ ShadowSurface: Enterprise External Attack Surface Management & OSINT Reconnaissance Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Architecture-10--Phase%20Pipeline-cyan?style=for-the-badge" alt="Pipeline">
  <img src="https://img.shields.io/badge/Features-100%2B%20Production%20Modules-success?style=for-the-badge" alt="100+ Features">
  <img src="https://img.shields.io/badge/Curriculum-CEH%20v12%20Capstone-red?style=for-the-badge" alt="CEH v12">
  <img src="https://img.shields.io/badge/Reports-HTML5%20%7C%20SARIF%20%7C%20JSON%20%7C%20CSV-purple?style=for-the-badge" alt="Reports">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

```
   ____  _               _                 ____             __                
  / ___|| |__   __ _  __| | _____      __ / ___| _   _ _ __/ _| __ _  ___ ___ 
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / \___ \| | | | '__| |_ / _` |/ __/ _ \
   ___) | | | | (_| | (_| | (_) \ V  V /   ___) | |_| | |  |  _| (_| | (_|  __/
  |____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |____/ \__,_|_|  |_|  \__,_|\___\___|

   [+] Enterprise External Attack Surface Management (EASM) & OSINT Reconnaissance
   [+] 10-Phase Automated Pipeline with 100+ Production Security Modules
   [+] Daily Continuous Asset Drift Monitoring, Threat Intel & Multi-Cloud Hunting
```

> **Certified Ethical Hacker (CEH) Graduation Capstone & Daily SecOps Power Tool**  
> **ShadowSurface** is an automated, modular, high-performance External Attack Surface Management (EASM) and Open-Source Intelligence (OSINT) framework. Built for security consultants, bug bounty hunters, penetration testers, and daily enterprise SecOps engineers to discover, score, track, and remediate external organizational exposure.

---

## 📌 Table of Contents
1. [Why ShadowSurface?](#-why-shadowsurface)
2. [Daily Workflows & Show-Off Use Cases](#-daily-workflows--show-off-use-cases)
3. [System Architecture & 10-Phase Pipeline](#-system-architecture--10-phase-pipeline)
4. [Complete 100-Feature Catalog](#-complete-100-feature-catalog)
5. [Installation & Setup](#-installation--setup)
6. [CLI Command Reference](#-cli-command-reference)
7. [Automated Daily CI/CD Monitoring (GitHub Actions)](#-automated-daily-cicd-monitoring-github-actions)
8. [Multi-Format Enterprise Deliverables](#-multi-format-enterprise-deliverables)
9. [CEH v12 Curriculum Mapping](#-ceh-v12-curriculum-mapping)
10. [Academic & Capstone Defense Kit](#-academic--capstone-defense-kit)
11. [License & Ethical Disclaimer](#-license--ethical-disclaimer)

---

## 🌟 Why ShadowSurface?

Before an attacker executes an exploitation attempt, **Phase 1 (Reconnaissance)** and **Phase 2 (Scanning)** dictate the entire perimeter exposure. Modern enterprises suffer from uncontrolled **"Shadow IT"**: forgotten cloud storage buckets, unmonitored staging APIs, exposed internal databases, missing email anti-spoofing policies, and dangling DNS pointers vulnerable to subdomain takeover.

ShadowSurface eliminates these blind spots by transforming passive intelligence and active probing into continuous, actionable perimeter defense:
- **Zero-Touch Passive Isolation Mode:** Perform footprinting without sending a single packet to target infrastructure.
- **Daily Asset Drift & Diff Tracking:** Automatically alert security teams whenever a new subdomain appears or a database port is exposed.
- **Multi-Cloud Asset Hunting:** Detect shadow AWS S3 buckets, Azure Blobs, and Google Cloud Storage buckets before attackers do.
- **Vulnerability & CVE Correlation:** Map discovered services to known high-severity CVEs (e.g. regreSSHion, Log4Shell, Spring4Shell) and CISA's KEV catalog.
- **Enterprise Reporting:** Export findings to interactive HTML5 dashboards, GitHub SARIF code-scanning alerts, CSV spreadsheets, and executive Markdown briefs.

---

## ⚡ Daily Workflows & Show-Off Use Cases

### 1. ☕ The Daily Morning Recon Routine
Run ShadowSurface against your organization's perimeter every morning to detect newly spawned assets or misconfigurations:
```bash
python shadowsurface.py -d yourcompany.com --profile top100 -o daily-reports
```

### 2. 🕵️ Bug Bounty Reconnaissance (Pure Passive OSINT)
Perform non-intrusive reconnaissance without touching target networks:
```bash
python shadowsurface.py -d target.com --no-ports
```

### 3. 🔍 Interactive Live Investigation Shell (REPL)
Launch a dedicated REPL session to explore domains, inspect DNS, and interact with target assets in real time:
```bash
python shadowsurface.py --shell
# shadowsurface(no-target)> target example.com
# shadowsurface(example.com)> info
```

### 4. 📈 Asset Drift & Historical Diff Detection
Compare last week's scan against today's scan to instantly identify newly exposed subdomains or opened ports:
```bash
python shadowsurface.py --diff reports/target_20261015.json reports/target_20261022.json
```

### 5. 🎯 Enterprise Batch Scope Scanning
Scan an entire organization's watchlist from a file:
```bash
python shadowsurface.py --watchlist targets.txt --profile web
```

### 6. 🕒 Continuous Background Daemon Mode
Keep ShadowSurface running as a background monitoring daemon that re-scans every 24 hours:
```bash
python shadowsurface.py -d yourcompany.com --daemon --interval 86400
```

---

## 📐 System Architecture & 10-Phase Pipeline

```
                                +-----------------------------+
                                |     Target Domain / Asset   |
                                +--------------+--------------+
                                               |
+----------------------------------------------v-----------------------------------------------+
|                                  SHADOWSURFACE CORE ENGINE                                   |
+----------------------------------------------------------------------------------------------+
| [ Phase 1: DNS & Mail Security ]     -> DNSSEC, SPF/DMARC deep check, AXFR, Takeovers, BIMI  |
| [ Phase 2: Multi-Source OSINT ]      -> crt.sh, HackerTarget, OTX, ThreatCrowd, RapidDNS     |
| [ Phase 3: Network & BGP Routing ]   -> ASN, BGP prefix, GeoIP, ISP Geolocation              |
| [ Phase 4: Port Probing & Services ] -> High-concurrency socket pool, Port profiles (top20)   |
| [ Phase 5: CDN & WAF Fingerprint ]   -> Cloudflare, AWS WAF, Akamai, Imperva detection       |
| [ Phase 6: Web Tech & Path Crawler ] -> Wappalyzer heuristics, robots.txt, /.well-known/     |
| [ Phase 7: Multi-Cloud Hunting ]     -> AWS S3, Azure Blob, GCP Storage, Firebase RTDB       |
| [ Phase 8: HTTP Defense Auditing ]   -> HSTS Preload, CSP evaluation, CORS, Cookie flags     |
| [ Phase 9: Threat Intel & CVEs ]     -> CVE correlation, CISA KEV, EOL runtimes, CVSS v3.1   |
| [ Phase 10: Deliverables & Diff ]    -> SQLite persistence, Drift engine, HTML5/SARIF/CSV    |
+----------------------------------------------------------------------------------------------+
                                               |
                                               v
                                +-----------------------------+
                                |    OUTPUT DELIVERABLES      |
                                | - Interactive HTML5 Dash    |
                                | - GitHub OASIS SARIF v2.1   |
                                | - Excel-Ready CSV Flat File |
                                | - Executive Markdown Brief  |
                                | - Machine-Readable JSON     |
                                | - SQLite Asset Inventory    |
                                +-----------------------------+
```

---

## 🚀 Complete 100-Feature Catalog

ShadowSurface is packed with **100 modular production capabilities** organized into 10 specialized categories:

### 🌐 1. Advanced OSINT & Subdomain Discovery
| # | Feature | Module | Description |
|---|---|---|---|
| 01 | HackerTarget Passive OSINT | `modules/osint/hackertarget.py` | Queries HackerTarget hostsearch API with rate-limit evasion |
| 02 | AlienVault OTX Threat Intel | `modules/osint/alienvault.py` | Extracts passive DNS indicators and historical host mappings |
| 03 | ThreatCrowd Infrastructure Engine | `modules/osint/threatcrowd.py` | Queries ThreatCrowd graph API for linked infrastructure |
| 04 | RapidDNS & Anubis Aggregator | `modules/osint/rapiddns.py` | Parses publicly indexed subdomains from RapidDNS search feeds |
| 05 | URLScan.io Passive Search | `modules/osint/urlscan.py` | Extracts historically scanned hostnames and shadow endpoints |
| 06 | Subdomain Permutation Engine | `modules/osint/permutations.py` | Generates intelligent environment mutations (`dev`, `staging`, `api`) |
| 07 | Multi-Threaded DNS Brute-Forcer | `modules/osint/dns_bruteforce.py` | Parallel dictionary resolution using high-speed socket pools |
| 08 | DNS Wildcard Subdomain Filter | `modules/osint/wildcard_filter.py` | Probes randomized UUID canaries to eliminate wildcard false positives |
| 09 | Unified OSINT Aggregator | `modules/osint/aggregator.py` | Parallel futures orchestrator merging & deduplicating discoveries |
| 10 | WHOIS & RDAP Intel Extractor | `modules/osint/whois_recon.py` | Queries ICANN RDAP bootstrap for registrar and expiration dates |
| 11 | ASN & BGP Route Lookup | `modules/osint/asn_lookup.py` | Resolves IP to Autonomous System Number, network CIDR, and ISP |
| 12 | Reverse DNS Subnet Sweeper | `modules/osint/reverse_dns.py` | Concurrent PTR record resolution across adjacent `/24` subnets |

### 🔒 2. Advanced DNS & Domain Health Security
| # | Feature | Module | Description |
|---|---|---|---|
| 13 | DNSSEC Chain Validation | `modules/dns/dnssec.py` | Validates DNSKEY and DS records to audit zone spoofing resilience |
| 14 | DNS Zone Transfer (AXFR) Tester | `modules/dns/axfr.py` | Probes authoritative nameservers for unrestricted zone file dumps |
| 15 | Subdomain Takeover Engine | `modules/dns/takeover.py` | Scans dangling CNAMEs against 25+ cloud providers (S3, GitHub, Heroku) |
| 16 | CAA Record Hygiene Audit | `modules/dns/caa.py` | Audits RFC 6844 Certificate Authority Authorization directives |
| 17 | MX Mail Server Priority Analysis | `modules/dns/mx_audit.py` | Analyzes MX priority, identifying secure email gateways (Proofpoint, M365) |
| 18 | Strict SPF Policy Analyzer | `modules/dns/spf_deep.py` | Evaluates SPF qualifiers (`-all`, `~all`, `+all`) and RFC 10-lookup limits |
| 19 | DMARC Policy Enforcement Checker | `modules/dns/dmarc_deep.py` | Evaluates `p=reject`, percentage enforcement (`pct`), and `rua` reporting |
| 20 | DKIM Common Selector Probe | `modules/dns/dkim_probe.py` | Discovers standard DKIM selectors and audits RSA key bit-lengths |
| 21 | BIMI Inbox Branding Verification | `modules/dns/bimi.py` | Audits BIMI TXT indicators and VMC certificate branding |
| 22 | MTA-STS & TLSRPT Security Audit | `modules/dns/mta_sts.py` | Verifies RFC 8461 SMTP TLS enforcement and reporting records |

### 🛰️ 3. Network Infrastructure & Deep Service Scanning
| # | Feature | Module | Description |
|---|---|---|---|
| 23 | Configurable Port Profiles | `modules/network/port_profiles.py` | Presets for `top20`, `top100`, `top1000`, `web`, `database`, `infra` |
| 24 | High-Concurrency Thread Pool | `modules/network/thread_pool.py` | Non-blocking socket workers with adaptive thread scaling |
| 25 | GeoIP & ISP Geolocation | `modules/network/geoip.py` | Resolves public IPs to country, city, coordinates, and ISP |
| 26 | CDN & Reverse Proxy Detector | `modules/network/cdn_detector.py` | Detects Cloudflare, Akamai, AWS CloudFront, and Fastly edge shields |
| 27 | WAF Fingerprinting Engine | `modules/network/waf_fingerprint.py` | Identifies active WAFs (AWS WAF, ModSecurity, F5 BIG-IP, Imperva) |
| 28 | SSH Banner & Security Prober | `modules/network/ssh_probe.py` | Grabs SSH banners and flags regreSSHion (CVE-2024-6387) exposure |
| 29 | FTP Anonymous Login Probe | `modules/network/ftp_probe.py` | Checks port 21 for anonymous authentication and banner leaks |
| 30 | SMTP Open Relay & STARTTLS Probe | `modules/network/smtp_probe.py` | Audits port 25/587 for encryption and cleartext relay risks |
| 31 | Multi-Database Exposure Prober | `modules/network/database_probe.py` | Handshakes MySQL, PostgreSQL, Redis (`PING`), Mongo, Elasticsearch |
| 32 | Remote Management Auditor | `modules/network/remote_mgmt_probe.py` | Flags exposed RDP, VNC, Telnet, WinRM, and Kubernetes API ports |

### 🔍 4. Web Application Footprinting & Deep Security Auditing
| # | Feature | Module | Description |
|---|---|---|---|
| 33 | Deep SSL/TLS Certificate Inspector | `modules/web/ssl_inspector.py` | Extracts x509 subject, issuer, validity period, and SAN domains |
| 34 | Deprecated SSL/TLS Detector | `modules/web/ssl_ciphers.py` | Tests whether endpoint negotiates insecure TLS 1.0 or TLS 1.1 |
| 35 | Web Technology Stack Fingerprinter | `modules/web/tech_detector.py` | Wappalyzer-like heuristic detection for React, Next, Vue, Django, Laravel |
| 36 | Content Security Policy Evaluator | `modules/web/csp_evaluator.py` | Flags `'unsafe-inline'`, `'unsafe-eval'`, wildcards, and missing `default-src` |
| 37 | HSTS Preload & Expiry Validator | `modules/web/hsts_validator.py` | Evaluates `max-age` (>= 1 year), `includeSubDomains`, and `preload` |
| 38 | Sensitive Path & Endpoint Crawler | `modules/web/sensitive_paths.py` | Discovers `robots.txt`, `sitemap.xml`, `security.txt`, and `humans.txt` |
| 39 | Version Control Exposure Detector | `modules/web/git_exposure.py` | Probes for exposed `.git/HEAD`, `.svn/entries`, and `.hg/store` |
| 40 | Environment & Secret Leak Detector | `modules/web/secret_leak_detector.py` | Probes for exposed `.env`, `config.json`, and `docker-compose.yml` |
| 41 | API Schema & Documentation Finder | `modules/web/api_finder.py` | Discovers Swagger UI, OpenAPI specs (`/swagger.json`), and GraphQL |
| 42 | Spring Boot Actuator Auditor | `modules/web/actuator_probe.py` | Probes for unauthenticated `/actuator/env`, `/heapdump`, `/health` |
| 43 | Cookie Security Flags Auditor | `modules/web/cookie_audit.py` | Validates `Secure`, `HttpOnly`, and `SameSite` flags on cookies |
| 44 | CORS Misconfiguration Probe | `modules/web/cors_probe.py` | Tests for arbitrary origin reflection and credential exposure |
| 45 | HTTP Dangerous Methods Probe | `modules/web/http_methods.py` | Tests `OPTIONS`, `PUT`, `DELETE`, `TRACE` (Cross-Site Tracing) |
| 46 | Clickjacking Defense Auditor | `modules/web/clickjacking.py` | Checks `X-Frame-Options` and CSP `frame-ancestors` posture |
| 47 | Server Banner Disclosure Auditor | `modules/web/banner_leaks.py` | Detects detailed version disclosures in `Server` and `X-Powered-By` |
| 48 | Mixed Content Subresource Crawler | `modules/web/mixed_content.py` | Scans HTTPS pages for unencrypted `http://` scripts and images |

### ☁️ 5. Cloud Attack Surface & Shadow IT Asset Hunting
| # | Feature | Module | Description |
|---|---|---|---|
| 49 | AWS S3 Bucket Permutation Hunter | `modules/cloud/s3_hunter.py` | Probes name permutations for publicly listable AWS S3 buckets |
| 50 | Azure Blob Storage Container Hunter | `modules/cloud/azure_hunter.py` | Tests candidate storage accounts for anonymous blob read permissions |
| 51 | Google Cloud Storage Bucket Hunter | `modules/cloud/gcp_hunter.py` | Probes candidate GCP storage buckets for public exposure |
| 52 | Firebase Realtime Database Probe | `modules/cloud/firebase_probe.py` | Probes `{target}.firebaseio.com/.json` for open databases |
| 53 | Cloud Instance Metadata Canary | `modules/cloud/metadata_canary.py` | Tests for SSRF reflections exposing `169.254.169.254` credentials |
| 54 | Docker Registry & Daemon Probe | `modules/cloud/docker_probe.py` | Scans port 5000 (`_catalog`) and 2375 (Docker API) for unauthenticated access |
| 55 | CI/CD Dashboard Exposure Probe | `modules/cloud/cicd_probe.py` | Detects exposed Jenkins, GitLab, ArgoCD, and TeamCity interfaces |
| 56 | Prometheus & Grafana Exposure Probe | `modules/cloud/metrics_probe.py` | Scans `/metrics` and port 3000 for internal telemetry exposure |
| 57 | HashiCorp Vault & Consul API Probe | `modules/cloud/vault_probe.py` | Scans port 8200 (Vault) and 8500 (Consul) for exposed APIs |
| 58 | Multi-Cloud Storage Risk Aggregator | `modules/cloud/cloud_risk.py` | Aggregates cloud storage findings into a unified cloud risk index |

### 🎯 6. Threat Intelligence & Vulnerability Correlation
| # | Feature | Module | Description |
|---|---|---|---|
| 59 | Known CVE Correlation Engine | `modules/vuln/cve_correlator.py` | Maps banners to known vulnerabilities (Apache, Nginx, OpenSSH) |
| 60 | CISA KEV Catalog Tagger | `modules/vuln/cisa_kev.py` | Tags vulnerabilities actively exploited in the wild by CISA |
| 61 | AbuseIPDB Reputation Scorer | `modules/intel/abuseipdb.py` | Evaluates IP malicious report volume and botnet participation |
| 62 | Tor Exit Node & VPN Relay Detector | `modules/intel/tor_vpn.py` | Checks target IPs against active Tor exit nodes and proxy networks |
| 63 | DNSBL Spam Reputation Validator | `modules/intel/dnsbl.py` | Validates mail and host IPs against Spamhaus, SORBS, and Barracuda |
| 64 | Typosquatting Domain Predictor | `modules/intel/typosquat.py` | Generates homoglyphs, omissions, and transposition phishing domains |
| 65 | Default Administrative Portal Detector | `modules/vuln/default_creds.py` | Detects exposed phpMyAdmin, Tomcat Manager, and setup wizards |
| 66 | End-Of-Life (EOL) Software Detector | `modules/vuln/eol_detector.py` | Identifies deprecated PHP, Python, Apache, and OpenSSL versions |
| 67 | CVSS v3.1 Severity Calculator | `modules/vuln/cvss_calculator.py` | Computes standardized CVSS v3.1 vector strings and base scores |
| 68 | Threat Intelligence IOC Extractor | `modules/intel/ioc_extractor.py` | Normalizes discovered assets into structured STIX/IOC datasets |

### ⚡ 7. Stealth, Performance, Networking & Scope Controls
| # | Feature | Module | Description |
|---|---|---|---|
| 69 | Dynamic User-Agent Rotation Pool | `modules/stealth/user_agents.py` | Realistic browser headers across macOS, Windows, and Linux |
| 70 | Request Throttling & Jitter Engine | `modules/stealth/rate_limiter.py` | Enforces max requests/sec and adds randomized millisecond jitter |
| 71 | HTTP & SOCKS5 Proxy Manager | `modules/stealth/proxy_manager.py` | Handles proxy rotation, tunneling, and upstream health verification |
| 72 | Custom Header & Auth Injector | `modules/stealth/custom_headers.py` | Injects corporate Bearer tokens and custom testing headers |
| 73 | Pure Passive Isolation Enforcer | `modules/stealth/passive_mode.py` | Enforces zero direct socket connections to target infrastructure |
| 74 | In-Memory DNS Caching Engine | `modules/stealth/dns_cache.py` | Caches resolved hostnames with TTL to minimize redundant queries |
| 75 | Resilient Exponential Backoff | `modules/stealth/retry_engine.py` | Automatically retries failed network requests with exponential delay |
| 76 | Dynamic Socket Timeout Tuning | `modules/stealth/timeout_tuning.py` | Measures RTT to automatically calibrate optimal socket timeouts |
| 77 | Network Telemetry & Throughput Meter | `modules/stealth/throughput_meter.py` | Tracks requests per second, duration, and bandwidth telemetry |
| 78 | Target Scope & Blacklist Manager | `modules/stealth/scope_manager.py` | Prevents out-of-scope probing via CIDR and domain whitelists |

### 📊 8. Continuous ASM, Historical Diffs & Daily Monitoring
| # | Feature | Module | Description |
|---|---|---|---|
| 79 | Persistent SQLite Asset Inventory | `modules/storage/database.py` | Stores historical scans, assets, and vulnerabilities in SQLite |
| 80 | Daily Drift & Diff Engine | `modules/monitoring/diff_engine.py` | Identifies new subdomains, opened ports, and score changes |
| 81 | Asset Discovery Timeline Tracker | `modules/monitoring/timeline.py` | Maintains chronological audit trail of when assets first/last appeared |
| 82 | Continuous Background Daemon Runner | `modules/monitoring/daemon_runner.py` | Executes automated periodic scans (e.g. daily, hourly) |
| 83 | Slack Incoming Webhook Integration | `modules/alerts/slack_webhook.py` | Dispatches real-time Block Kit alerts directly into Slack |
| 84 | Discord Rich Embed Webhook | `modules/alerts/discord_webhook.py` | Sends color-coded severity embeds to Discord security channels |
| 85 | Microsoft Teams Card Connector | `modules/alerts/teams_webhook.py` | Formats executive summaries into Microsoft Teams MessageCards |
| 86 | Generic JSON Webhook with HMAC Auth | `modules/alerts/generic_webhook.py` | Securely pushes JSON events to SIEM/SOAR with HMAC SHA-256 signatures |
| 87 | CLI Historical Diff Tool | `modules/monitoring/cli_diff.py` | CLI tool to compare two JSON scan files and output terminal diffs |
| 88 | Enterprise Watchlist Manager | `modules/monitoring/watchlist.py` | Loads and manages multi-target batch files (`targets.txt`) |

### 📈 9. Enterprise Reporting, Visualization & Exports
| # | Feature | Module | Description |
|---|---|---|---|
| 89 | Next-Gen Interactive HTML5 Dashboard | `modules/reporting/html_pro.py` | Dark-mode responsive dashboard with Chart.js charts and live search |
| 90 | Excel-Compatible CSV Exporter | `modules/reporting/csv_exporter.py` | Exports subdomains, open ports, and findings into tabular CSV |
| 91 | OASIS SARIF v2.1.0 Exporter | `modules/reporting/sarif_exporter.py` | Converts findings to SARIF for native GitHub Security code scanning |
| 92 | Executive Markdown Brief Generator | `modules/reporting/markdown_exporter.py` | Formats results into ready-to-paste markdown for Jira and pull requests |
| 93 | Prioritized Remediation Playbook | `modules/reporting/remediation_guide.py` | Generates exact copy-pasteable Nginx, Apache, and DNS fix commands |
| 94 | Print-Optimized Stylesheet (PDF Export) | `modules/reporting/print_stylesheet.py` | Clean CSS `@media print` layout for exporting HTML dashboards to PDF |

### 🛠️ 10. CLI Experience, Developer Tools & CI/CD Readiness
| # | Feature | Module | Description |
|---|---|---|---|
| 95 | Rich Colored Terminal UI | `modules/cli/ui.py` | ANSI color-coded banners, status indicators, and ASCII risk meters |
| 96 | Interactive REPL Shell | `modules/cli/repl.py` | Interactive shell for ad-hoc queries, domain switching, and testing |
| 97 | YAML / JSON Configuration Loader | `modules/cli/config_loader.py` | Loads defaults, API keys, and alert URLs from `shadowsurface.json` |
| 98 | GitHub Actions Daily ASM Workflow | `.github/workflows/daily-asm.yml` | Scheduled daily GitHub Actions workflow with artifact upload |
| 99 | Comprehensive Pytest Test Suite | `tests/test_all_features.py` | Automated unit tests verifying all framework components |
| 100 | Unified 10-Phase Core Orchestrator | `core/orchestrator.py` | Wires all 100 modules into a single, cohesive, production-grade CLI |

---

## 💻 Installation & Setup

### Requirements
- **Python:** 3.9 or higher
- **Operating Systems:** Linux, macOS, Windows (native PowerShell & CMD supported)

### Quickstart
```bash
# 1. Clone the repository
git clone https://github.com/lumidren/shadowsurface-recon-framework.git
cd shadowsurface-recon-framework

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python shadowsurface.py --help
```

---

## 📖 CLI Command Reference

```
usage: shadowsurface.py [-h] [-d DOMAIN] [--no-ports]
                        [--profile {top20,top100,top1000,web,database,infra}]
                        [-o OUTPUT] [--shell] [--diff REPORT_A REPORT_B]
                        [--watchlist WATCHLIST] [--daemon] [--interval INTERVAL]

ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain to assess (e.g. example.com)
  --no-ports            Disable active TCP port probing (Passive OSINT only)
  --profile {top20,top100,top1000,web,database,infra}
                        Port scanning profile presets (default: top20)
  -o OUTPUT, --output OUTPUT
                        Output directory for reports (default: reports/)
  --shell               Launch interactive REPL investigation shell
  --diff REPORT_A REPORT_B
                        Compare two JSON scan reports and show asset drift
  --watchlist WATCHLIST
                        Run batch assessment on target domains listed in a file
  --daemon              Run in continuous daily monitoring daemon mode
  --interval INTERVAL   Daemon interval in seconds (default: 86400 / 24h)
```

---

## 🤖 Automated Daily CI/CD Monitoring (GitHub Actions)

ShadowSurface includes a ready-to-run GitHub Actions workflow located at [`.github/workflows/daily-asm.yml`](.github/workflows/daily-asm.yml).

Every morning at **06:00 UTC**, GitHub Actions executes a scheduled external assessment, generates reports, and archives the interactive HTML5 and SARIF files as job artifacts. You can also trigger scans manually via the **Run workflow** button in your GitHub repository!

---

## 📦 Multi-Format Enterprise Deliverables

Every assessment generates a structured deliverables bundle inside `reports/`:
- **`{domain}_{timestamp}.html`**: Standalone dark-mode HTML5 executive dashboard with Chart.js charts and live filters.
- **`{domain}_{timestamp}.json`**: Full machine-readable raw data for ingestion into custom pipelines.
- **`{domain}_{timestamp}.csv`**: Tabular asset inventory ready for Excel or Google Sheets.
- **`{domain}_{timestamp}.sarif`**: Standard OASIS SARIF v2.1.0 format for GitHub Code Scanning alerts.
- **`{domain}_{timestamp}.md`**: Clean markdown summary report ready for Jira or GitHub PR descriptions.
- **`shadowsurface_inventory.db`**: Local SQLite database storing historical records for continuous drift tracking.

---

## 🎓 CEH v12 Curriculum Mapping

| CEH v12 Module | Domain Focus | ShadowSurface Implementation |
| :--- | :--- | :--- |
| **Module 02** | Footprinting & Reconnaissance | Passive CT logs, HackerTarget, AlienVault OTX, RapidDNS, WHOIS RDAP |
| **Module 03** | Scanning Networks | Multi-threaded TCP socket scanning, banner grabbing, port profiles |
| **Module 04** | Enumeration | Comprehensive DNS, DNSSEC, reverse DNS subnet sweep, AXFR testing |
| **Module 05** | Vulnerability Analysis | Known CVE correlation, CISA KEV tagging, CVSS v3.1 calculator |
| **Module 09** | Social Engineering Defense | Deep SPF qualifiers, DMARC enforcement, DKIM probing, typosquatting |
| **Module 13** | Hacking Web Applications | CSP evaluation, HSTS preload, CORS misconfigurations, cookie security |
| **Module 15** | Cloud Computing | AWS S3, Azure Blob, GCP bucket hunting, Firebase databases |

---

## 📚 Academic & Capstone Defense Kit

Looking for presentation materials? Explore the [`presentation/`](presentation/) folder:
- **[`PROJECT_PROPOSAL.md`](presentation/PROJECT_PROPOSAL.md)**: Formal written proposal and executive abstract for academic review.
- **[`SLIDE_DECK.md`](presentation/SLIDE_DECK.md)**: 10 structured slides with word-for-word speaker notes.
- **[`DEFENSE_QA.md`](presentation/DEFENSE_QA.md)**: Technical answers to anticipated examination committee questions.

---

## ⚖️ License & Ethical Disclaimer

This framework is licensed under the [MIT License](LICENSE).

> **LEGAL NOTICE:** ShadowSurface is designed for authorized external attack surface management, educational research, defensive security assessments, and authorized penetration testing. Do not execute active port scans or probing against networks or domains without explicit, written permission from the asset owner.
