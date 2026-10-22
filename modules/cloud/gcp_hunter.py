"""
Google Cloud Storage (GCP) Public Bucket Hunter
Tests public read permissions on Google Cloud Storage buckets.
"""

from typing import List, Dict, Any
import requests

GCP_PERMUTATIONS = [
    "{base}", "{base}-assets", "{base}-data", "{base}-backup", "{base}-public"
]

def hunt_gcp_buckets(domain: str) -> List[Dict[str, Any]]:
    """Probes candidate GCP storage buckets."""
    base = domain.split(".")[0]
    discovered = []

    for perm in GCP_PERMUTATIONS:
        b_name = perm.format(base=base)
        url = f"https://storage.googleapis.com/{b_name}"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                discovered.append({
                    "provider": "Google Cloud Storage",
                    "bucket": b_name,
                    "url": url,
                    "status": "OPEN_PUBLIC_BUCKET",
                    "severity": "CRITICAL"
                })
            elif r.status_code == 403:
                discovered.append({
                    "provider": "Google Cloud Storage",
                    "bucket": b_name,
                    "url": url,
                    "status": "EXISTS_PROTECTED",
                    "severity": "INFO"
                })
        except Exception:
            pass

    return discovered
