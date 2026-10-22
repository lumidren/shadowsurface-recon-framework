"""
Prioritized Remediation Playbook Generator with Exact CLI Fixes
Provides copy-pasteable Nginx, Apache, and DNS remediation commands for discovered exposures.
"""

from typing import Dict, Any, List

REMEDIATION_SNIPPETS = {
    "DMARC": {
        "title": "Enforce Strict DMARC Policy",
        "command": "Add DNS TXT: _dmarc.domain.com 'v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@domain.com;'"
    },
    "SPF": {
        "title": "Harden SPF Mail Qualifier",
        "command": "Update DNS TXT: domain.com 'v=spf1 include:_spf.provider.com -all'"
    },
    "HSTS": {
        "title": "Enable Strict Transport Security",
        "command": "Nginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;"
    },
    "CSP": {
        "title": "Implement Content Security Policy",
        "command": "Nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;"
    }
}

def generate_remediation_playbook(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Builds prioritized fix recommendations based on findings."""
    playbook = []
    for f in findings:
        title = f.get("title", "")
        for key, rec in REMEDIATION_SNIPPETS.items():
            if key.lower() in title.lower():
                playbook.append({
                    "issue": title,
                    "recommended_fix": rec["title"],
                    "cli_snippet": rec["command"]
                })
                break
    return playbook
