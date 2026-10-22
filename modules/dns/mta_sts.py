"""
MTA-STS & TLSRPT Mail Transport Security Audit (RFC 8461 & RFC 8460)
Checks whether domain enforces TLS encryption for inbound SMTP traffic.
"""

from typing import Dict, Any
import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def audit_mta_sts(domain: str) -> Dict[str, Any]:
    """Checks MTA-STS DNS record and policy file."""
    res = {
        "domain": domain,
        "mta_sts_dns": False,
        "tlsrpt_dns": False,
        "policy_mode": None,
        "policy_url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    }
    if not DNS_AVAILABLE:
        return res

    try:
        ans = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
        for r in ans:
            if "v=STSv1" in r.to_text():
                res["mta_sts_dns"] = True
                break
    except Exception:
        pass

    try:
        ans = dns.resolver.resolve(f"_smtp._tls.{domain}", "TXT")
        for r in ans:
            if "v=TLSRPTv1" in r.to_text():
                res["tlsrpt_dns"] = True
                break
    except Exception:
        pass

    if res["mta_sts_dns"]:
        try:
            r = requests.get(res["policy_url"], timeout=4)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.startswith("mode:"):
                        res["policy_mode"] = line.split(":", 1)[1].strip()
        except Exception:
            pass

    return res
