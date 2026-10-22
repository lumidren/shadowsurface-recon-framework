"""
Comprehensive Web Technology Stack Fingerprinter
Employs signature heuristics across headers, meta tags, and JavaScript bodies to detect technologies.
"""

from typing import Dict, Any, List
import requests

TECH_PATTERNS = {
    "WordPress": {"headers": ["x-pingback"], "body": ["wp-content", "wp-includes"]},
    "Drupal": {"headers": ["x-generator: drupal"], "body": ["Drupal.settings"]},
    "React": {"body": ["react-root", "_reactRootContainer", "data-reactid"]},
    "Next.js": {"headers": ["x-powered-by: next.js"], "body": ["__NEXT_DATA__"]},
    "Vue.js": {"body": ["v-cloak", "data-v-"]},
    "Angular": {"body": ["ng-version", "ng-app"]},
    "Laravel": {"headers": ["laravel_session"], "body": ["csrf-token"]},
    "Django": {"headers": ["csrftoken"], "body": ["csrfmiddlewaretoken"]},
    "Express.js": {"headers": ["x-powered-by: express"]},
    "ASP.NET": {"headers": ["x-aspnet-version", "x-aspnetmvc-version"]},
    "Cloudflare": {"headers": ["server: cloudflare", "cf-ray"]},
    "Nginx": {"headers": ["server: nginx"]},
    "Apache": {"headers": ["server: apache"]}
}

def detect_technologies(domain: str) -> List[str]:
    """Scans domain for installed web technologies."""
    detected = set()
    url = f"https://{domain}"
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
        headers_str = " ".join([f"{k}: {v}" for k, v in r.headers.items()]).lower()
        body_str = r.text.lower()

        for tech, sigs in TECH_PATTERNS.items():
            for h in sigs.get("headers", []):
                if h in headers_str:
                    detected.add(tech)
            for b in sigs.get("body", []):
                if b.lower() in body_str:
                    detected.add(tech)
    except Exception:
        pass

    return sorted(list(detected))
