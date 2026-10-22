"""
Known CVE Correlation Engine for Discovered Services
Matches discovered technology versions and service banners against high-impact CVE entries.
"""

from typing import List, Dict, Any
import re

CVE_DATABASE = [
    {"product": "OpenSSH", "version_regex": r"OpenSSH_9\.[0-7]p1", "cve": "CVE-2024-6387", "score": 8.1, "summary": "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH server"},
    {"product": "Apache HTTP Server", "version_regex": r"Apache/2\.4\.49|Apache/2\.4\.50", "cve": "CVE-2021-41773", "score": 9.8, "summary": "Path traversal and remote code execution in Apache HTTP Server"},
    {"product": "Nginx", "version_regex": r"nginx/1\.20\.0|nginx/1\.21\.0", "cve": "CVE-2021-23017", "score": 7.7, "summary": "1-byte memory overwrite in Nginx DNS resolver"},
    {"product": "Log4j", "version_regex": r"log4j-core-2\.(0|[1-9]|1[0-4])\.", "cve": "CVE-2021-44228", "score": 10.0, "summary": "Log4Shell: JNDI Remote Code Execution in Apache Log4j"},
    {"product": "Spring Framework", "version_regex": r"5\.(3\.[0-1][0-7]|2\.[0-1][0-9])", "cve": "CVE-2022-22965", "score": 9.8, "summary": "Spring4Shell: Remote Code Execution via Data Binding"}
]

def correlate_cves(banner_or_tech: str) -> List[Dict[str, Any]]:
    """Correlates a service banner or technology version string against CVE database."""
    matches = []
    for item in CVE_DATABASE:
        if re.search(item["version_regex"], banner_or_tech, re.IGNORECASE):
            matches.append({
                "product": item["product"],
                "cve": item["cve"],
                "cvss_score": item["score"],
                "summary": item["summary"],
                "severity": "CRITICAL" if item["score"] >= 9.0 else "HIGH"
            })
    return matches
