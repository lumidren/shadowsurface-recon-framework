# 🎓 ShadowSurface: CEH Capstone Project Presentation Deck
*10-slide ready-to-present deck with slide visuals and word-for-word speaker notes.*

---

## Slide 1: Title & Introduction
**Visual:** Project Title in bold cyan, CEH Logo / Shield icon, student name, and date.
* **Title:** ShadowSurface: Automated External Attack Surface & OSINT Reconnaissance Framework
* **Subtitle:** Modernizing Footprinting, Asset Discovery, and Risk Scoring for Ethical Hackers

> 🗣️ **Speaker Notes:**  
> "Good morning, members of the evaluation committee. Today, I am excited to present ShadowSurface, an automated External Attack Surface Management and OSINT reconnaissance framework developed as a capstone project for the Certified Ethical Hacker curriculum."

---

## Slide 2: The Problem: Expanding Attack Surfaces & Blind Spots
**Visual:** Diagram contrasting known corporate assets vs hidden "Shadow IT" (forgotten dev servers, exposed staging databases, missing email policies).
* **The Problem:**
  * Modern organizations have dynamic, sprawling internet assets.
  * Over 60% of data breaches originate from unknown, unmonitored external exposure.
  * Manual reconnaissance is fragmented across dozens of disconnected tools.

> 🗣️ **Speaker Notes:**  
> "In ethical hacking and penetration testing, Phase 1—Reconnaissance—determines the entire success of the assessment. If you cannot see an asset, you cannot defend it or test it. Today, organizations suffer from 'Shadow IT'—staging servers, dev APIs, and unauthenticated databases exposed directly to the internet. ShadowSurface automates this discovery process."

---

## Slide 3: Project Goals & CEH Alignment
**Visual:** 4 core stages mapped to CEH phases: 1. Passive OSINT $\rightarrow$ 2. DNS Footprinting $\rightarrow$ 3. Service Probing $\rightarrow$ 4. Risk Scoring & Reporting.
* **Core Objectives:**
  * Passive Subdomain Discovery via Certificate Transparency.
  * Comprehensive DNS & Email Spoofing vulnerability checks (SPF/DMARC).
  * Fast, non-destructive port and service banner discovery.
  * Automated calculation of an Organizational Risk Index (0-100) and Grade.

> 🗣️ **Speaker Notes:**  
> "Our goal was to build a unified, modular Python engine that implements the reconnaissance methodologies defined in CEH Modules 2, 3, 4, and 13, aggregating diverse telemetry into a standardized, quantifiable security posture grade."

---

## Slide 4: System Architecture
**Visual:** Clean pipeline diagram from Target Domain $\rightarrow$ Multi-Module Processing $\rightarrow$ Scoring Engine $\rightarrow$ HTML/JSON Reporting.
* **Architecture Highlights:**
  * **Zero-Noise Passive Discovery:** Utilizes public Certificate Transparency (`crt.sh`) logs without sending packets to the target.
  * **Multi-Threaded Probing:** Concurrently checks critical management and database ports.
  * **Header Auditing Engine:** Evaluates HTTP defense headers and identifies framework leaks.

> 🗣️ **Speaker Notes:**  
> "Here is our architectural blueprint. The engine operates in distinct stages. First, it performs passive intelligence gathering using Certificate Transparency logs. Next, it analyzes DNS records and mail authentication. Then, it conducts concurrent TCP port probing and audits HTTP security headers, feeding all data into our weighted risk analyzer."

---

## Slide 5: Passive Reconnaissance & DNS Security
**Visual:** DNS Analysis breakdown showing SPF SoftFail vs HardFail and DMARC enforcement.
* **Key Capabilities:**
  * **Certificate Transparency:** Extracts historical and live SSL/TLS certificate records.
  * **Email Spoofing Risk Assessment:** Flags missing or weak SPF policies (`~all` or `+all`) and unenforced DMARC policies (`p=none`).
  * **Nameserver & Zone Enumeration:** Identifies external DNS hosting providers.

> 🗣️ **Speaker Notes:**  
> "A unique strength of ShadowSurface is its passive intelligence capability. By leveraging Certificate Transparency logs, we discover valid subdomains and development portals without triggering target intrusion detection systems. Furthermore, our mail audit identifies domain spoofability that attackers exploit in CEO fraud and phishing."

---

## Slide 6: Service Fingerprinting & Web Posture
**Visual:** Table of high-risk port exposures (RDP 3389, Redis 6379, SMB 445) and missing security headers.
* **Service Exposure Auditing:**
  * Detects exposed databases, remote desktop management, and cache servers.
* **HTTP Header Auditing:**
  * Verifies HSTS, CSP, and X-Frame-Options against clickjacking and XSS.
  * Detects information disclosure in `Server` and `X-Powered-By` banners.

> 🗣️ **Speaker Notes:**  
> "In the active probing stage, ShadowSurface identifies high-risk services—such as exposed Remote Desktop Protocol, unauthenticated Redis instances, or database ports. It also checks web applications for essential defense-in-depth headers, such as Content Security Policy and HTTP Strict Transport Security."

---

## Slide 7: Algorithmic Risk Scoring & Visual Reporting
**Visual:** Screenshot of the dark-mode HTML assessment dashboard with risk gauge and findings breakdown.
* **Scoring Methodology:**
  * Base baseline + weighted penalty per vulnerability severity.
  * Produces an intuitive Letter Grade (A, B, C, F) and Posture Score (0-100).
  * Automatically generates standalone interactive HTML and JSON reports.

> 🗣️ **Speaker Notes:**  
> "Raw scan output is difficult for management to digest. ShadowSurface solves this by using a weighted risk algorithm that transforms technical findings into an intuitive Security Posture Score out of 100 and a Letter Grade, accompanied by a clean, interactive HTML dashboard."

---

## Slide 8: Live Demonstration
**Visual:** Screenshot of `demo_run.py` terminal output side-by-side with rendered HTML dashboard.
* **Live Scenarios:**
  * **Scenario 1:** Complete end-to-end passive and active assessment of an enterprise asset.
  * **Scenario 2:** Instant generation and automatic browser launch of the HTML assessment report.

> 🗣️ **Speaker Notes:**  
> "To demonstrate that ShadowSurface is 100% functional, we will now execute our demonstration script. Within seconds, the tool conducts the full multi-phase assessment, scores the target, and produces a complete HTML report ready for executive presentation."

---

## Slide 9: Comparison with Industry Tools
**Visual:** Comparison matrix comparing ShadowSurface with Nmap, Amass, and Nikto.
* **Why ShadowSurface stands out:**
  * Combines OSINT, Port Scanning, Mail Security, and Web Header audits into a **single unified CLI**.
  * Outputs executive HTML dashboards natively with zero external dependencies.
  * Lightweight, fast, and 100% Python-based.

> 🗣️ **Speaker Notes:**  
> "Unlike traditional tools that only perform one isolated function—like Nmap for ports or Amass for subdomains—ShadowSurface bridges passive OSINT, service discovery, web posture, and automated executive reporting into a single lightweight platform."

---

## Slide 10: Conclusion & Committee Q&A
**Visual:** Summary bullet points, GitHub repo link, and "Thank You".
* **Summary:**
  * Production-grade OSINT & Attack Surface Management framework.
  * Fully aligned with CEH Reconnaissance and Scanning methodologies.
  * Generates actionable, executive-ready security assessment reports.
* **Open for Questions!**

> 🗣️ **Speaker Notes:**  
> "In conclusion, ShadowSurface proves how automation enhances ethical hacking reconnaissance, saving hours of manual discovery while providing clear remediation roadmaps. Thank you, and I look forward to your questions."
