# CEH Capstone Project Proposal

## Project Title
**ShadowSurface: Automated External Attack Surface Management & OSINT Reconnaissance Framework**

## Academic & Professional Context
* **Certification / Curriculum:** Certified Ethical Hacker (CEH v12) / Penetration Testing Track
* **CEH Modules Addressed:**
  * Module 02: Footprinting and Reconnaissance
  * Module 03: Scanning Networks & Host Discovery
  * Module 04: Enumeration (DNS, Services, OSINT)
  * Module 13: Hacking Web Applications (HTTP Security Posture)

---

## 1. Executive Summary & Problem Statement
The primary phase of any cybersecurity penetration test or adversary campaign is **Reconnaissance and Footprinting**. Organizations today rapidly deploy cloud workloads, microservices, and third-party SaaS integrations, often creating unmonitored "Shadow IT" and forgotten internet-facing assets.

Manual reconnaissance is slow, prone to human error, and fails to provide a unified risk posture score. **ShadowSurface** is an automated, modular External Attack Surface Management (EASM) framework designed for ethical hackers and security teams to continuously discover, audit, score, and report external organizational exposure before malicious actors can exploit it.

---

## 2. Project Objectives
1. **Passive OSINT Asset Discovery:** Passively enumerate valid subdomains without alerting target intrusion detection systems (IDS/IPS) using Certificate Transparency logs (`crt.sh`).
2. **DNS & Email Authentication Hygiene Audit:** Evaluate DNS infrastructure, nameservers, and assess email spoofing resilience (SPF, DMARC, DKIM).
3. **Multi-Threaded Service Probing:** Identify exposed management interfaces (SSH, RDP, Database ports, Admin consoles) and gather banners safely.
4. **Web Security Posture & Header Auditing:** Inspect HTTP response headers (CSP, HSTS, X-Frame-Options) and identify dangerous technology stack information disclosure.
5. **Algorithmic Risk Scoring & Reporting:** Translate technical findings into an objective **Security Posture Score (0–100)** and generate interactive HTML/JSON reports for stakeholders.

---

## 3. System Architecture & Methodology

```
+-------------------------------------------------------------+
|                      TARGET DOMAIN                          |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                 SHADOWSURFACE CORE ENGINE                   |
+---------------+--------------+---------------+--------------+
|               |              |               |              |
v               v              v               v              v
[DNS Recon] [CT Logs OSINT] [Service Probe] [HTTP Auditor] [Risk Scorer]
- A/MX/NS   - crt.sh API    - Multi-Thread  - HSTS / CSP   - CVSS Metric
- SPF/DMARC - Subdomains    - Banner Grab   - Server Leaks - Grade A-F
|               |              |               |              |
+---------------+--------------+---------------+--------------+
                               |
                               v
+-------------------------------------------------------------+
|                     OUTPUT DELIVERABLES                     |
|   - Machine-Readable JSON Export                            |
|   - Standalone Interactive Dark-Mode HTML Dashboard         |
|   - Executive Remediation Roadmap                           |
+-------------------------------------------------------------+
```

---

## 4. Key Deliverables
* **Modular Python Engine:** Clean architecture with independent, extensible auditing modules.
* **Stand-Alone HTML Report Dashboard:** Modern visual interface rendering posture grades and vulnerability matrices.
* **1-Click Demonstration Script:** `demo_run.py` pre-loaded with comprehensive enterprise scenarios for live evaluation.
* **Defense & Presentation Kit:** Complete slide deck, formal proposal, and anticipated committee Q&A.
