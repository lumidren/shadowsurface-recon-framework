"""
ShadowSurface DNS Reconnaissance & Mail Security Module
Enumerates DNS records, nameservers, mail exchanges, and evaluates SPF/DMARC posture.
"""

import socket
from typing import Dict, Any, List

try:
    import dns.resolver
    DNS_RESOLVER_AVAILABLE = True
except ImportError:
    DNS_RESOLVER_AVAILABLE = False


def enumerate_dns(domain: str) -> Dict[str, Any]:
    """Resolves essential DNS records and evaluates email authentication hygiene."""
    results = {
        "domain": domain,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "spf_status": "Missing",
        "dmarc_status": "Missing",
        "email_security_issues": []
    }

    if not DNS_RESOLVER_AVAILABLE:
        # Fallback to standard socket resolution
        try:
            ip = socket.gethostbyname(domain)
            results["a_records"].append(ip)
        except Exception:
            pass
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. A Records
    try:
        answers = resolver.resolve(domain, "A")
        results["a_records"] = [str(rdata) for rdata in answers]
    except Exception:
        pass

    # 2. MX Records
    try:
        answers = resolver.resolve(domain, "MX")
        results["mx_records"] = [f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}" for rdata in answers]
    except Exception:
        pass

    # 3. NS Records
    try:
        answers = resolver.resolve(domain, "NS")
        results["ns_records"] = [rdata.target.to_text().rstrip('.') for rdata in answers]
    except Exception:
        pass

    # 4. TXT Records & SPF Check
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_str = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
            results["txt_records"].append(txt_str)
            if "v=spf1" in txt_str:
                results["spf_record"] = txt_str
                if "-all" in txt_str:
                    results["spf_status"] = "Strong (HardFail -all)"
                elif "~all" in txt_str:
                    results["spf_status"] = "Moderate (SoftFail ~all)"
                    results["email_security_issues"].append("SPF policy uses SoftFail (~all), allowing email spoofing acceptance on some gateways.")
                elif "+all" in txt_str or "?all" in txt_str:
                    results["spf_status"] = "Insecure (+all / ?all)"
                    results["email_security_issues"].append("SPF policy permits all senders (+all/?all), enabling unrestricted domain spoofing.")
    except Exception:
        pass

    if results["spf_status"] == "Missing":
        results["email_security_issues"].append("Missing SPF record: Domain is vulnerable to direct email spoofing.")

    # 5. DMARC Check (_dmarc.<domain>)
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            dmarc_str = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
            if "v=DMARC1" in dmarc_str:
                results["dmarc_record"] = dmarc_str
                if "p=reject" in dmarc_str:
                    results["dmarc_status"] = "Enforced (p=reject)"
                elif "p=quarantine" in dmarc_str:
                    results["dmarc_status"] = "Quarantine (p=quarantine)"
                elif "p=none" in dmarc_str:
                    results["dmarc_status"] = "Monitoring Only (p=none)"
                    results["email_security_issues"].append("DMARC policy is set to 'p=none' (monitoring only). Spoofed emails are not blocked.")
    except Exception:
        results["email_security_issues"].append("Missing DMARC record: Domain lacks email spoofing protection policy.")

    return results
