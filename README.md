# 🛡️ ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Curriculum: CEH v12](https://img.shields.io/badge/Curriculum-CEH%20v12-red.svg)](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9+-green.svg)](https://python.org)
[![Reports: HTML%20%26%20JSON](https://img.shields.io/badge/Reports-HTML%20%26%20JSON-purple.svg)]()

> **Certified Ethical Hacker (CEH) Graduation Capstone Project**  
> An automated, modular External Attack Surface Management (EASM) and Open Source Intelligence (OSINT) framework designed for ethical hackers, penetration testers, and security consultants to discover, score, and report external organizational exposure.

---

## 📌 Table of Contents
1. [Project Overview](#-project-overview)
2. [CEH Module Mapping](#-ceh-module-mapping)
3. [System Architecture](#-system-architecture)
4. [Project Directory Structure](#-project-directory-structure)
5. [Installation & Setup](#-installation--setup)
6. [Usage & Commands](#-usage--commands)
7. [Running the Live Presentation Demo](#-running-the-live-presentation-demo)
8. [Academic & Presentation Kit](#-academic--presentation-kit)

---

## 🌟 Project Overview

Before an ethical hacker executes an exploitation attempt, **Phase 1 (Reconnaissance)** and **Phase 2 (Scanning)** dictate the attack surface. Modern organizations suffer from unmonitored "Shadow IT" (forgotten cloud servers, staging APIs, unauthenticated databases, and missing email authentication records).

**ShadowSurface** automates the entire footprinting and discovery lifecycle:
- **Passive Subdomain Enumeration** via public Certificate Transparency logs (`crt.sh`).
- **DNS Infrastructure & Email Authentication Hygiene** (SPF, DMARC, DKIM analysis).
- **Multi-Threaded Service Probing & Banner Grabbing** across high-value management and database ports.
- **Web Defense Posture & HTTP Security Header Auditing** (CSP, HSTS, X-Frame-Options, server leaks).
- **Algorithmic Security Posture Scoring (0–100)** with interactive, dark-mode HTML executive dashboards.

---

## 🎯 CEH Module Mapping

| CEH v12 Module | Domain Focus | Implemented Feature in ShadowSurface |
| :--- | :--- | :--- |
| **Module 02** | Footprinting & Reconnaissance | Passive Certificate Transparency log queries & OSINT discovery |
| **Module 03** | Scanning Networks | Multi-threaded socket-based TCP port scanning & banner grabbing |
| **Module 04** | Enumeration | Comprehensive DNS record analysis (A, MX, NS, TXT) |
| **Module 09** | Social Engineering Defense | Identification of missing/weak SPF & DMARC email spoofing policies |
| **Module 13** | Hacking Web Applications | HTTP security headers audit (CSP, HSTS, Clickjacking protection) |

---

## ⚡ System Architecture

```
                               +-----------------------------+
                               |     Target Domain / Asset   |
                               +--------------+--------------+
                                              |
                                              v
+-------------------------------------------------------------------------------------------+
|                                SHADOWSURFACE CORE ENGINE                                  |
+----------------------+----------------------+----------------------+----------------------+
|                      |                      |                      |                      |
v                      v                      v                      v                      v
[ 1. DNS Recon ]       [ 2. Passive OSINT ]   [ 3. Service Scan ]    [ 4. Web Auditor ]     [ 5. Risk Scorer ]
- A / MX / NS Records  - crt.sh CT Logs       - Multi-Thread Probing - HSTS / CSP / X-Frame - CVSS-based weights
- SPF / DMARC Checks   - Subdomain Discovery  - Banner Grabbing      - Server Token Leaks   - Letter Grade (A-F)
|                      |                      |                      |                      |
+----------------------+----------------------+----------------------+----------------------+
                                              |
                                              v
                               +-----------------------------+
                               |    OUTPUT DELIVERABLES      |
                               | - Machine-Readable JSON     |
                               | - Interactive HTML Report   |
                               | - Remediation Action Plan   |
                               +-----------------------------+
```

---

## 📁 Project Directory Structure

```
shadowsurface-recon-framework/
├── shadowsurface.py               # Main CLI entry point
├── demo_run.py                    # 1-Click live presentation runner
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git configuration
├── README.md                      # Complete documentation
│
├── core/
│   ├── __init__.py
│   └── orchestrator.py            # Reconnaissance pipeline coordinator
│
├── modules/
│   ├── __init__.py
│   ├── dns_recon.py               # DNS zone & SPF/DMARC mail audit
│   ├── crt_sh.py                  # Certificate Transparency log queries
│   ├── service_scan.py            # Multi-threaded TCP port & banner discovery
│   ├── http_headers_audit.py      # HTTP defense headers & server disclosures
│   ├── risk_analyzer.py           # Weighted risk scoring & posture grading
│   └── report_generator.py        # HTML and JSON artifact generation
│
├── templates/
│   └── report_template.html       # Responsive dark-mode HTML report template
│
└── presentation/
    ├── PROJECT_PROPOSAL.md        # Formal capstone project proposal & abstract
    ├── SLIDE_DECK.md              # 10-slide ready-to-present deck with speaker notes
    └── DEFENSE_QA.md              # Anticipated CEH defense questions and answers
```

---

## 🚀 Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-username/shadowsurface-recon-framework.git
cd shadowsurface-recon-framework

# 2. Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage & Commands

```bash
# Run a full automated assessment against a target domain
python shadowsurface.py -d target.com

# Run in pure passive OSINT mode (no direct port scans sent to target)
python shadowsurface.py -d target.com --no-ports

# Custom output directory
python shadowsurface.py -d target.com -o /path/to/reports
```

---

## 🎬 Running the Live Presentation Demo

For your CEH presentation or faculty defense:

```bash
python demo_run.py
```
Select **[1]** to run the rich simulated enterprise scenario. Within 2 seconds, the tool conducts the full multi-phase assessment, displays the executive terminal summary, and automatically opens the interactive HTML report in your default browser!

---

## 🎓 Academic & Presentation Kit

In the [`presentation/`](presentation/) folder:
- **[`PROJECT_PROPOSAL.md`](presentation/PROJECT_PROPOSAL.md)**: Formal written proposal and executive abstract for faculty review.
- **[`SLIDE_DECK.md`](presentation/SLIDE_DECK.md)**: 10 structured slides with word-for-word speaker notes.
- **[`DEFENSE_QA.md`](presentation/DEFENSE_QA.md)**: Technical answers to committee questions on passive vs active recon, CT logs, and risk scoring.

---

## ⚖️ License
Open-source under the [MIT License](LICENSE). Built for educational, research, and CEH capstone defense purposes.
