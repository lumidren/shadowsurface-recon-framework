# 🛡️ ShadowSurface: CEH Project Defense Q&A Guide
*Top questions asked by ethical hacking professors, examiners, and committee members, with rock-solid technical answers.*

---

### Q1: "What is the difference between Passive Reconnaissance and Active Reconnaissance in your tool?"
**Your Answer:**  
> *"Passive reconnaissance gathers intelligence without sending packets directly to the target infrastructure, ensuring zero detection. In ShadowSurface, our Certificate Transparency module (`crt.sh`) and public DNS lookups are completely passive. Active reconnaissance, on the other hand, involves direct interaction—such as our multi-threaded TCP socket probing and HTTP header requests to the target IP. Users can disable active probing using the `--no-ports` flag to perform 100% stealthy passive OSINT."*

---

### Q2: "How does Certificate Transparency (crt.sh) discover subdomains that traditional DNS brute-forcing misses?"
**Your Answer:**  
> *"Whenever a Certificate Authority (CA) issues an SSL/TLS certificate for any subdomain (e.g., `dev-vpn.target.com`), it is cryptographically logged to public, append-only Certificate Transparency logs by industry requirement. ShadowSurface queries these global logs via the crt.sh API. This allows us to discover ephemeral, unlisted, or staging subdomains in seconds without generating thousands of noisy DNS brute-force queries."*

---

### Q3: "Why is checking SPF and DMARC records an essential part of an ethical hacking assessment?"
**Your Answer:**  
> *"In CEH Module 9 (Social Engineering), email spoofing is the primary attack vector for spear-phishing and Business Email Compromise (BEC). If a target domain lacks SPF or DMARC, or sets DMARC to `p=none`, an attacker can send emails impersonating the CEO or IT administrator that land directly in victim inboxes with zero warnings. ShadowSurface flags this immediately as an email spoofing risk."*

---

### Q4: "How does your risk scoring engine determine the overall Posture Score and Grade?"
**Your Answer:**  
> *"We implement a weighted vulnerability scoring model inspired by CVSS. The target starts with a 100% baseline posture. High-risk exposures (such as exposed RDP port 3389 or unauthenticated database ports) incur heavy penalties (-20 points), high web vulnerabilities like missing CSP incur -8 points, and missing email authentication incurs -12 points. The final score maps directly into an intuitive Letter Grade (A, B, C, F) for executive stakeholders."*

---

### Q5: "How does ShadowSurface compare to commercial External Attack Surface Management (EASM) tools like Shodan, Censys, or OWASP Amass?"
**Your Answer:**  
> *"While enterprise tools like Shodan or Amass provide massive internet-wide datasets, they often require paid API keys, complex database setups, or output raw command-line text that requires manual formatting. ShadowSurface was designed to be completely lightweight, open-source, and self-contained in Python—generating a ready-to-present, interactive HTML executive report out-of-the-box in under 15 seconds."*
