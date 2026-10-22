"""
MX Mail Server Priority & Blackhole Analysis
Audits mail exchanger records, identifies enterprise providers, and detects backup MX risks.
"""

import socket
from typing import Dict, Any, List

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

KNOWN_MAIL_PROVIDERS = {
    "google.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Exchange Online",
    "pphosted.com": "Proofpoint Enterprise Mail Gateway",
    "mimecast.com": "Mimecast Secure Email Gateway",
    "barracudanetworks.com": "Barracuda Email Security",
    "zoho.com": "Zoho Workplace"
}

def audit_mx_infrastructure(domain: str) -> Dict[str, Any]:
    """Analyzes MX records for hygiene, redundancy, and gateway posture."""
    result = {
        "domain": domain,
        "mx_servers": [],
        "identified_providers": [],
        "has_backup_mx": False,
        "mail_secure_gateway": False
    }
    if not DNS_AVAILABLE:
        return result

    try:
        answers = dns.resolver.resolve(domain, "MX")
        sorted_answers = sorted(answers, key=lambda r: r.preference)
        priorities = []
        for r in sorted_answers:
            host = r.exchange.to_text().rstrip(".")
            pref = r.preference
            priorities.append(pref)
            result["mx_servers"].append({"host": host, "priority": pref})

            for domain_key, name in KNOWN_MAIL_PROVIDERS.items():
                if domain_key in host.lower() and name not in result["identified_providers"]:
                    result["identified_providers"].append(name)
                    result["mail_secure_gateway"] = True

        if len(set(priorities)) > 1:
            result["has_backup_mx"] = True
    except Exception:
        pass

    return result
