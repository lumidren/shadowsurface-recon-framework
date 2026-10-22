"""
Version Control Exposure Detector
Probes target for exposed source code repositories (.git/HEAD, .svn/entries, .hg/store).
"""

from typing import Dict, Any, List
import requests

VCS_ENDPOINTS = [
    {"type": "Git", "path": "/.git/HEAD", "needle": "ref: refs/"},
    {"type": "Git Config", "path": "/.git/config", "needle": "[core]"},
    {"type": "SVN", "path": "/.svn/entries", "needle": "12\n"},
    {"type": "Mercurial", "path": "/.hg/store/00manifest.i", "needle": "\x00\x00"}
]

def detect_vcs_exposure(domain: str) -> List[Dict[str, Any]]:
    """Probes for exposed version control repositories."""
    findings = []
    base_url = f"https://{domain}"

    for vcs in VCS_ENDPOINTS:
        try:
            r = requests.get(f"{base_url}{vcs['path']}", timeout=4, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
            if r.status_code == 200 and vcs["needle"] in r.text:
                findings.append({
                    "vcs_type": vcs["type"],
                    "url": f"{base_url}{vcs['path']}",
                    "severity": "CRITICAL",
                    "description": f"Exposed {vcs['type']} repository allows full source code reconstruction."
                })
        except Exception:
            pass

    return findings
