"""
Typosquatting & Domain Brand Impersonation Predictor
Generates algorithmic variations (omission, homoglyphs, transposition) to detect phishing traps.
"""

from typing import List, Dict, Any

HOMOGLYPHS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["4"]
}

def generate_typosquat_domains(domain: str, limit: int = 25) -> List[str]:
    """Generates candidate typosquatted domains."""
    parts = domain.split(".")
    name = parts[0]
    tld = ".".join(parts[1:])
    candidates = set()

    # Omission
    for i in range(len(name)):
        cand = name[:i] + name[i+1:]
        if cand:
            candidates.add(f"{cand}.{tld}")

    # Transposition
    for i in range(len(name) - 1):
        cand = name[:i] + name[i+1] + name[i] + name[i+2:]
        candidates.add(f"{cand}.{tld}")

    # Homoglyphs
    for char, replacements in HOMOGLYPHS.items():
        if char in name:
            for rep in replacements:
                candidates.add(f"{name.replace(char, rep)}.{tld}")

    return sorted(list(candidates))[:limit]
