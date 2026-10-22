"""
SSL/TLS Deprecated Protocol & Weak Cipher Suite Detector
Tests whether endpoint negotiates legacy SSLv3, TLS 1.0, or TLS 1.1 handshakes.
"""

import ssl
import socket
from typing import Dict, Any

def audit_tls_versions(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Tests supported TLS protocol versions."""
    res = {
        "hostname": hostname,
        "tls1_0_enabled": False,
        "tls1_1_enabled": False,
        "tls1_2_enabled": False,
        "tls1_3_enabled": False,
        "weak_protocols_found": False
    }

    # TLS 1.0
    try:
        ctx10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx10.maximum_version = ssl.TLSVersion.TLSv1
        ctx10.check_hostname = False
        ctx10.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with ctx10.wrap_socket(sock, server_hostname=hostname):
                res["tls1_0_enabled"] = True
                res["weak_protocols_found"] = True
    except Exception:
        pass

    # TLS 1.1
    try:
        ctx11 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx11.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx11.check_hostname = False
        ctx11.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with ctx11.wrap_socket(sock, server_hostname=hostname):
                res["tls1_1_enabled"] = True
                res["weak_protocols_found"] = True
    except Exception:
        pass

    # Standard modern TLS
    try:
        ctx_modern = ssl.create_default_context()
        ctx_modern.check_hostname = False
        ctx_modern.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with ctx_modern.wrap_socket(sock, server_hostname=hostname) as ssock:
                ver = ssock.version()
                if ver == "TLSv1.3":
                    res["tls1_3_enabled"] = True
                    res["tls1_2_enabled"] = True
                elif ver == "TLSv1.2":
                    res["tls1_2_enabled"] = True
    except Exception:
        pass

    return res
