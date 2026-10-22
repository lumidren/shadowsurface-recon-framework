"""
Brand Indicators for Message Identification (BIMI) Audit
Verifies BIMI TXT indicators and VMC certificates for trusted email inbox branding.
"""

from typing import Dict, Any

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def check_bimi(domain: str) -> Dict[str, Any]:
    """Checks for BIMI record at default._bimi.{domain}."""
    res = {
        "domain": domain,
        "bimi_configured": False,
        "bimi_record": None,
        "svg_location": None,
        "vmc_certificate": None
    }
    if not DNS_AVAILABLE:
        return res

    bimi_target = f"default._bimi.{domain}"
    try:
        answers = dns.resolver.resolve(bimi_target, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if "v=BIMI1" in txt:
                res["bimi_configured"] = True
                res["bimi_record"] = txt
                parts = [p.strip() for p in txt.split(";") if "=" in p]
                for p in parts:
                    k, v = p.split("=", 1)
                    if k.strip() == "l":
                        res["svg_location"] = v.strip()
                    elif k.strip() == "a":
                        res["vmc_certificate"] = v.strip()
                break
    except Exception:
        pass

    return res
