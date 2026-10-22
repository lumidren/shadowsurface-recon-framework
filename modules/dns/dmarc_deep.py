"""
DMARC Policy Enforcement Checker (RFC 7489)
Evaluates enforcement disposition, subdomain policies, and forensic reporting configurations.
"""

from typing import Dict, Any

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def deep_analyze_dmarc(domain: str) -> Dict[str, Any]:
    """Examines DMARC policy strength and reporting configuration."""
    res = {
        "domain": domain,
        "dmarc_record": None,
        "policy": "none",
        "subdomain_policy": None,
        "percentage": 100,
        "rua_configured": False,
        "ruf_configured": False,
        "is_enforcing": False,
        "issues": []
    }
    if not DNS_AVAILABLE:
        return res

    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if "v=DMARC1" in txt:
                res["dmarc_record"] = txt
                tags = [t.strip() for t in txt.split(";") if "=" in t]
                tag_dict = {}
                for t in tags:
                    k, v = t.split("=", 1)
                    tag_dict[k.strip().lower()] = v.strip().lower()

                res["policy"] = tag_dict.get("p", "none")
                res["subdomain_policy"] = tag_dict.get("sp")
                res["percentage"] = int(tag_dict.get("pct", "100"))
                res["rua_configured"] = "rua" in tag_dict
                res["ruf_configured"] = "ruf" in tag_dict

                if res["policy"] in ["reject", "quarantine"]:
                    res["is_enforcing"] = True
                else:
                    res["issues"].append("HIGH: DMARC policy is set to 'p=none' (Monitoring only, no spoofing rejection).")

                if not res["rua_configured"]:
                    res["issues"].append("MEDIUM: DMARC aggregate reporting (rua) is not configured.")

                if res["percentage"] < 100:
                    res["issues"].append(f"WARNING: DMARC policy only applies to {res['percentage']}% of messages.")
                break
    except Exception:
        res["issues"].append("CRITICAL: Missing DMARC record. Domain is vulnerable to CEO fraud and spoofing.")

    return res
