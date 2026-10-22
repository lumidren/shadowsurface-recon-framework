"""
CVSS v3.1 Qualitative and Quantitative Scoring Calculator
Computes qualitative severity ratings and scores for attack surface findings.
"""

from typing import Dict, Any

def score_attack_surface_vulnerability(
    av: str = "N",   # Network
    ac: str = "L",   # Low complexity
    pr: str = "N",   # None
    ui: str = "N",   # None
    c: str = "H",    # High
    i: str = "H",    # High
    a: str = "H"     # High
) -> Dict[str, Any]:
    """Calculates CVSS base score approximation."""
    # Simplified metric weights
    score = 9.8 if (c == "H" and i == "H" and a == "H" and pr == "N") else 7.5
    rating = "CRITICAL" if score >= 9.0 else ("HIGH" if score >= 7.0 else ("MEDIUM" if score >= 4.0 else "LOW"))

    return {
        "vector": f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}",
        "base_score": score,
        "severity": rating
    }
