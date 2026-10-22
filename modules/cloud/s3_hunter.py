"""
AWS S3 Bucket Shadow Asset Permutation Hunter
Generates target domain permutations and tests AWS S3 REST endpoints for public bucket listings.
"""

from typing import List, Dict, Any
import requests

S3_PERMUTATIONS = [
    "{base}", "{base}-assets", "{base}-backup", "{base}-backups",
    "{base}-data", "{base}-prod", "{base}-production", "{base}-dev",
    "{base}-staging", "{base}-static", "{base}-media", "{base}-logs"
]

def hunt_s3_buckets(domain: str) -> List[Dict[str, Any]]:
    """Probes candidate AWS S3 bucket names."""
    base = domain.split(".")[0]
    discovered = []

    for perm in S3_PERMUTATIONS:
        bucket_name = perm.format(base=base)
        url = f"https://{bucket_name}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                discovered.append({
                    "provider": "AWS S3",
                    "bucket": bucket_name,
                    "url": url,
                    "status": "OPEN_PUBLIC_LISTING",
                    "severity": "CRITICAL"
                })
            elif r.status_code == 403 and "AccessDenied" in r.text:
                discovered.append({
                    "provider": "AWS S3",
                    "bucket": bucket_name,
                    "url": url,
                    "status": "EXISTS_PROTECTED",
                    "severity": "INFO"
                })
        except Exception:
            pass

    return discovered
