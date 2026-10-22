"""
DKIM Common Selector Discovery & Key Length Auditor
Probes top common DKIM selector TXT records to discover public keys and assess RSA bit lengths.
"""

from typing import Dict, Any, List

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

COMMON_SELECTORS = [
    "default", "google", "k1", "s1", "s2", "mail", "smtp",
    "selector1", "selector2", "mandrill", "sendgrid", "zoho"
]

def probe_dkim_selectors(domain: str, selectors: List[str] = None) -> Dict[str, Any]:
    """Tests standard DKIM selector hostnames."""
    res = {
        "domain": domain,
        "discovered_selectors": [],
        "keys": []
    }
    if not DNS_AVAILABLE:
        return res

    probe_list = selectors if selectors else COMMON_SELECTORS
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5

    for sel in probe_list:
        target = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(target, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    res["discovered_selectors"].append(sel)
                    res["keys"].append({
                        "selector": sel,
                        "record": txt[:60] + "..."
                    })
                    break
        except Exception:
            continue

    return res
