"""
Content Security Policy (CSP) Deep Evaluator
Evaluates CSP policy strengths and flags dangerous bypasses ('unsafe-inline', 'unsafe-eval', wildcard domains).
"""

from typing import Dict, Any, List

def evaluate_csp_header(csp_string: str) -> Dict[str, Any]:
    """Analyzes a Content-Security-Policy string for vulnerabilities."""
    res = {
        "raw_csp": csp_string,
        "is_configured": bool(csp_string),
        "has_unsafe_inline": False,
        "has_unsafe_eval": False,
        "has_wildcard": False,
        "missing_default_src": False,
        "issues": []
    }
    if not csp_string:
        res["issues"].append("CRITICAL: Missing Content-Security-Policy (CSP) header. Susceptible to XSS.")
        return res

    directives = [d.strip() for d in csp_string.split(";") if d.strip()]
    dir_dict = {}
    for d in directives:
        parts = d.split()
        if parts:
            dir_dict[parts[0].lower()] = [p.lower() for p in parts[1:]]

    if "default-src" not in dir_dict:
        res["missing_default_src"] = True
        res["issues"].append("HIGH: Missing 'default-src' fallback directive.")

    for k, vals in dir_dict.items():
        if "'unsafe-inline'" in vals:
            res["has_unsafe_inline"] = True
            res["issues"].append(f"HIGH: '{k}' directive allows 'unsafe-inline' scripts/styles.")
        if "'unsafe-eval'" in vals:
            res["has_unsafe_eval"] = True
            res["issues"].append(f"MEDIUM: '{k}' directive allows 'unsafe-eval' string-to-code execution.")
        if "*" in vals:
            res["has_wildcard"] = True
            res["issues"].append(f"HIGH: '{k}' contains wildcard '*' source allowing untrusted hosts.")

    return res
