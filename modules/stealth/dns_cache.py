"""
Thread-Safe In-Memory DNS Caching & TTL Manager
Caches DNS resolution results to accelerate multi-phase reconnaissance and prevent duplicate queries.
"""

import time
import socket
from typing import Dict, Optional, Tuple

class ThreadSafeDNSCache:
    """In-memory cache for resolved hostnames."""
    def __init__(self, default_ttl: int = 300):
        self._cache: Dict[str, Tuple[str, float]] = {}
        self.default_ttl = default_ttl

    def get(self, hostname: str) -> Optional[str]:
        """Retrieves cached IP if not expired."""
        clean = hostname.strip().lower()
        if clean in self._cache:
            ip, expire_at = self._cache[clean]
            if time.time() < expire_at:
                return ip
            del self._cache[clean]
        return None

    def put(self, hostname: str, ip: str, ttl: int = None):
        """Stores resolved IP in cache with expiration."""
        clean = hostname.strip().lower()
        expire = time.time() + (ttl if ttl else self.default_ttl)
        self._cache[clean] = (ip, expire)

    def resolve(self, hostname: str) -> Optional[str]:
        """Resolves hostname with cache lookup fallback."""
        cached = self.get(hostname)
        if cached:
            return cached
        try:
            ip = socket.gethostbyname(hostname)
            self.put(hostname, ip)
            return ip
        except Exception:
            return None
