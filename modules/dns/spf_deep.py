"""
Strict SPF Policy Analyzer (RFC 7208)
Evaluates qualifier strength, mechanism lookup limits, and overly broad CIDR allocations.
"""

from typing import Dict, Any, List
import re

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def deep_analyze_spf(domain: str) -> Dict[str, Any]:
    """Inspects SPF record for security weaknesses."""
    res = {
        "domain": domain,
        "spf_record": None,
        "qualifier": "Missing",
        "lookup_count": 0,
        "has_all_pass": False,
        "has_softfail": False,
        "has_hardfail": False,
        "broad_cidr_detected": False,
        "issues": []
    }
    if not DNS_AVAILABLE:
        return res

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                res["spf_record"] = txt
                parts = txt.split()
                # Count lookups
                lookup_mechanisms = ["include", "a", "mx", "ptr", "exists", "redirect"]
                for p in parts:
                    for lm in lookup_mechanisms:
                        if p.startswith(lm) or f":{lm}" in p:
                            res["lookup_count"] += 1

                if "+all" in txt:
                    res["qualifier"] = "+all"
                    res["has_all_pass"] = True
                    res["issues"].append("CRITICAL: SPF uses '+all' allowing anyone in the world to spoof emails.")
                elif "~all" in txt:
                    res["qualifier"] = "~all"
                    res["has_softfail"] = True
                    res["issues"].append("WARNING: SPF uses SoftFail (~all). Spoofed emails may still be accepted.")
                elif "-all" in txt:
                    res["qualifier"] = "-all"
                    res["has_hardfail"] = True

                # Check CIDR
                if re.search(r'ip4:[0-9\.]+\/(8|16)', txt):
                    res["broad_cidr_detected"] = True
                    res["issues"].append("HIGH: Overly permissive CIDR range (/8 or /16) authorized in SPF.")

                if res["lookup_count"] > 10:
                    res["issues"].append(f"HIGH: SPF mechanism lookup limit exceeded ({res['lookup_count']}/10 max).")
                break
    except Exception:
        res["issues"].append("No SPF record found for domain.")

    return res
