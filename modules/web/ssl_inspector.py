"""
Deep SSL/TLS Certificate Inspector & Expiry Analyzer
Extracts x509 subject, issuer, validity period, days until expiry, and Subject Alternative Names (SANs).
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List

def inspect_tls_certificate(hostname: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    """Inspects target TLS certificate details."""
    res = {
        "hostname": hostname,
        "valid": False,
        "issuer": {},
        "subject": {},
        "days_to_expire": None,
        "expires_on": None,
        "sans": [],
        "is_expired": False,
        "self_signed": False
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # binary fallback
                    der = ssock.getpeercert(binary_form=True)
                    res["valid"] = True
                    return res

                res["valid"] = True
                # Parse notAfter
                exp_date_str = cert.get("notAfter")
                if exp_date_str:
                    exp_date = datetime.strptime(exp_date_str, "%b %d %H:%M:%S %Y %Z")
                    res["expires_on"] = exp_date.isoformat()
                    delta = (exp_date - datetime.utcnow()).days
                    res["days_to_expire"] = delta
                    res["is_expired"] = (delta < 0)

                # Parse SANs
                for field in cert.get("subjectAltName", []):
                    if field[0] == "DNS":
                        res["sans"].append(field[1])

                # Parse issuer & subject
                for item in cert.get("issuer", []):
                    for k, v in item:
                        res["issuer"][k] = v

                for item in cert.get("subject", []):
                    for k, v in item:
                        res["subject"][k] = v

                if res["issuer"].get("commonName") == res["subject"].get("commonName"):
                    res["self_signed"] = True
    except Exception:
        pass

    return res
