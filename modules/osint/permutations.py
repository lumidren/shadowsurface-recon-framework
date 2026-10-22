"""
Subdomain Permutations & Alteration Generator
Generates intelligent candidate mutations (dev, staging, v1, internal, admin) for active verification.
"""

from typing import List, Set

COMMON_ENV_WORDS = [
    "dev", "development", "stage", "staging", "stg", "test", "testing",
    "qa", "uat", "prod", "production", "api", "v1", "v2", "admin", "portal",
    "internal", "corp", "auth", "sso", "vpn", "mail", "app", "demo", "beta"
]

def generate_subdomain_permutations(base_subdomains: List[str], target_domain: str, limit: int = 50) -> List[str]:
    """
    Produces candidate mutations by inserting environment keywords.
    """
    candidates: Set[str] = set()
    clean_target = target_domain.strip().lower()

    # Base keywords
    for word in COMMON_ENV_WORDS:
        candidates.add(f"{word}.{clean_target}")

    for sub in base_subdomains:
        sub_name = sub.replace(f".{clean_target}", "").strip()
        if not sub_name or sub_name == clean_target:
            continue
        for word in COMMON_ENV_WORDS[:10]:
            candidates.add(f"{sub_name}-{word}.{clean_target}")
            candidates.add(f"{word}-{sub_name}.{clean_target}")
            candidates.add(f"{word}.{sub_name}.{clean_target}")
        if len(candidates) >= limit:
            break

    return sorted(list(candidates))[:limit]
