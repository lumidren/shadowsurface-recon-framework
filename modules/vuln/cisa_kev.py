"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Tagger
Cross-references detected CVEs against CISA's catalog of vulnerabilities actively exploited in the wild.
"""

from typing import Dict, Any, List

KNOWN_KEV_LIST = {
    "CVE-2024-6387": {"due_date": "2024-07-23", "action": "Update OpenSSH to latest patched release."},
    "CVE-2021-44228": {"due_date": "2021-12-24", "action": "Upgrade Log4j to 2.17.1 or higher."},
    "CVE-2021-41773": {"due_date": "2021-11-17", "action": "Upgrade Apache HTTP Server to 2.4.51+."},
    "CVE-2022-22965": {"due_date": "2022-04-25", "action": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+."},
    "CVE-2023-34362": {"due_date": "2023-06-16", "action": "Apply MOVEit Transfer vendor patches."}
}

def tag_cisa_kev(cve_id: str) -> Dict[str, Any]:
    """Checks whether CVE is cataloged by CISA as actively exploited."""
    cve_upper = cve_id.strip().upper()
    if cve_upper in KNOWN_KEV_LIST:
        data = KNOWN_KEV_LIST[cve_upper]
        return {
            "cve": cve_upper,
            "is_in_cisa_kev": True,
            "due_date": data["due_date"],
            "required_action": data["action"],
            "urgency": "IMMEDIATE_EXPLOITATION_IN_WILD"
        }
    return {
        "cve": cve_upper,
        "is_in_cisa_kev": False
    }
