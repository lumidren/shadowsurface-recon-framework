"""
CAA (Certificate Authority Authorization) Record Hygiene Audit
Checks RFC 6844 CAA directives to prevent unauthorized TLS certificate issuance.
"""

from typing import Dict, Any, List

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def audit_caa_records(domain: str) -> Dict[str, Any]:
    """Audits CAA records for target domain."""
    res = {
        "domain": domain,
        "has_caa": False,
        "authorized_cas": [],
        "wildcard_restricted": False,
        "iodef_reporting": None,
        "risk_level": "Medium"
    }
    if not DNS_AVAILABLE:
        return res

    try:
        answers = dns.resolver.resolve(domain, "CAA")
        for rdata in answers:
            tag = rdata.tag.decode("utf-8") if isinstance(rdata.tag, bytes) else str(rdata.tag)
            val = rdata.value.decode("utf-8") if isinstance(rdata.value, bytes) else str(rdata.value)
            if tag == "issue":
                res["authorized_cas"].append(val)
            elif tag == "issuewild":
                res["wildcard_restricted"] = True
            elif tag == "iodef":
                res["iodef_reporting"] = val

        if res["authorized_cas"]:
            res["has_caa"] = True
            res["risk_level"] = "Low"
    except Exception:
        res["has_caa"] = False
        res["risk_level"] = "Medium"

    return res
