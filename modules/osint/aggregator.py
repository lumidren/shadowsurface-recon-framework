"""
Unified Multi-Source OSINT Aggregator & De-duplicator
Coordinates parallel execution of all OSINT feeds and merges discoveries into unique list.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from modules.crt_sh import enumerate_subdomains_crtsh
from modules.osint.hackertarget import query_hackertarget
from modules.osint.alienvault import query_alienvault_otx
from modules.osint.threatcrowd import query_threatcrowd
from modules.osint.rapiddns import query_rapiddns
from modules.osint.urlscan import query_urlscan
from modules.osint.wildcard_filter import detect_dns_wildcard

def aggregate_all_subdomains(domain: str) -> Dict[str, Any]:
    """
    Runs all passive OSINT sources in parallel, normalizes and de-duplicates discoveries.
    """
    clean_domain = domain.strip().lower()
    unique_subs = set()
    sources_summary = {}

    # Check wildcard
    wildcard_info = detect_dns_wildcard(clean_domain)

    with ThreadPoolExecutor(max_workers=6) as executor:
        f_crt = executor.submit(enumerate_subdomains_crtsh, clean_domain)
        f_ht = executor.submit(query_hackertarget, clean_domain)
        f_otx = executor.submit(query_alienvault_otx, clean_domain)
        f_tc = executor.submit(query_threatcrowd, clean_domain)
        f_rapid = executor.submit(query_rapiddns, clean_domain)
        f_url = executor.submit(query_urlscan, clean_domain)

        try:
            crt_res = f_crt.result(timeout=15)
            sources_summary["crt_sh"] = len(crt_res)
            unique_subs.update(crt_res)
        except Exception:
            sources_summary["crt_sh"] = 0

        try:
            ht_res = f_ht.result(timeout=10)
            sources_summary["hackertarget"] = len(ht_res)
            for r in ht_res:
                unique_subs.add(r["hostname"])
        except Exception:
            sources_summary["hackertarget"] = 0

        try:
            otx_res = f_otx.result(timeout=12)
            sources_summary["alienvault_otx"] = len(otx_res)
            for r in otx_res:
                unique_subs.add(r["hostname"])
        except Exception:
            sources_summary["alienvault_otx"] = 0

        try:
            tc_res = f_tc.result(timeout=10)
            sources_summary["threatcrowd"] = len(tc_res)
            unique_subs.update(tc_res)
        except Exception:
            sources_summary["threatcrowd"] = 0

        try:
            rapid_res = f_rapid.result(timeout=12)
            sources_summary["rapiddns"] = len(rapid_res)
            unique_subs.update(rapid_res)
        except Exception:
            sources_summary["rapiddns"] = 0

        try:
            url_res = f_url.result(timeout=12)
            sources_summary["urlscan"] = len(url_res)
            unique_subs.update(url_res)
        except Exception:
            sources_summary["urlscan"] = 0

    return {
        "domain": clean_domain,
        "total_unique_subdomains": len(unique_subs),
        "subdomains": sorted(list(unique_subs)),
        "sources": sources_summary,
        "wildcard": wildcard_info
    }
