"""
DNS Zone Transfer (AXFR) Misconfiguration Tester
Tests authoritative nameservers for insecure, unrestricted full zone dumps.
"""

from typing import Dict, Any, List

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def test_zone_transfer(domain: str, nameservers: List[str] = None) -> Dict[str, Any]:
    """Tests each nameserver for open AXFR transfer."""
    report = {
        "domain": domain,
        "axfr_vulnerable": False,
        "vulnerable_nameservers": [],
        "leaked_records_count": 0,
        "tested_nameservers": []
    }
    if not DNS_AVAILABLE:
        return report

    resolver = dns.resolver.Resolver()
    ns_list = list(nameservers) if nameservers else []

    if not ns_list:
        try:
            ans = resolver.resolve(domain, "NS")
            ns_list = [str(r).rstrip(".") for r in ans]
        except Exception:
            return report

    report["tested_nameservers"] = ns_list

    for ns in ns_list:
        try:
            ns_ip = socket_ip = str(resolver.resolve(ns, "A")[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=4.0))
            if zone and len(zone.nodes) > 1:
                report["axfr_vulnerable"] = True
                report["vulnerable_nameservers"].append(ns)
                report["leaked_records_count"] += len(zone.nodes)
        except Exception:
            continue

    return report
