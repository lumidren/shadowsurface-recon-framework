"""
Configurable Port Profiles & Service Mapping Manager
Provides specialized port presets: top20, top100, top1000, database, web, infra, and custom ranges.
"""

from typing import List, Dict

PORT_PROFILES: Dict[str, List[int]] = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "web": [80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9443, 3000, 5000],
    "database": [1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017, 27018, 50000, 28017],
    "infra": [21, 22, 23, 25, 53, 69, 161, 389, 636, 873, 2049, 2375, 6443, 8500, 10250],
    "top100": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
        162, 179, 389, 443, 445, 465, 514, 515, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521,
        1723, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376, 2379, 3000, 3128, 3306, 3389,
        3690, 4000, 4369, 5000, 5432, 5672, 5900, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 8000,
        8080, 8081, 8443, 8500, 8888, 9000, 9090, 9200, 9300, 9443, 9999, 10000, 10250, 11211,
        27017, 27018, 50000
    ]
}

PORT_DESCRIPTIONS: Dict[int, str] = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure Cleartext Terminal)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (Encrypted Web Server)",
    445: "SMB (Server Message Block)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis In-Memory Data Store",
    6443: "Kubernetes API Server",
    8080: "HTTP Alternate / Proxy / Tomcat",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database"
}

def get_ports_for_profile(profile_name: str) -> List[int]:
    """Retrieves port list by profile name (defaults to top20)."""
    return PORT_PROFILES.get(profile_name.lower(), PORT_PROFILES["top20"])
