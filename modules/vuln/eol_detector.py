"""
End-Of-Life (EOL) Software and Deprecated Runtime Detector
Identifies deprecated versions of PHP, Python, Apache, and OpenSSL that no longer receive security patches.
"""

from typing import Dict, Any, List
import re

EOL_VERSIONS = [
    {"product": "PHP", "regex": r"PHP/(5\.|7\.[0-3])", "eol_date": "2021-12-06", "severity": "HIGH"},
    {"product": "Python", "regex": r"Python/(2\.|3\.[0-7])", "eol_date": "2023-06-27", "severity": "HIGH"},
    {"product": "Apache HTTP Server", "regex": r"Apache/2\.2\.", "eol_date": "2017-07-01", "severity": "CRITICAL"},
    {"product": "OpenSSL", "regex": r"OpenSSL/1\.0\.", "eol_date": "2019-12-31", "severity": "CRITICAL"}
]

def check_eol_status(banner: str) -> List[Dict[str, Any]]:
    """Scans banner for End-of-Life software signatures."""
    results = []
    for item in EOL_VERSIONS:
        if re.search(item["regex"], banner, re.IGNORECASE):
            results.append({
                "product": item["product"],
                "eol_date": item["eol_date"],
                "severity": item["severity"],
                "details": f"{item['product']} release is past official End-Of-Life ({item['eol_date']}) and lacks patches."
            })
    return results
