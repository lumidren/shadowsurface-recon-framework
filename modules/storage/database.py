"""
SQLite-Based Persistent Asset Inventory Database
Maintains historical records of discovered domains, subdomains, open ports, and risk posture.
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

class AssetDatabase:
    """Manages SQLite storage for historical attack surface scans."""
    def __init__(self, db_path: str = "shadowsurface_inventory.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    score INTEGER,
                    grade TEXT,
                    raw_json TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    asset_value TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(domain, asset_type, asset_value)
                )
            """)
            conn.commit()

    def save_scan(self, domain: str, score: int, grade: str, data: Dict[str, Any]):
        """Persists scan snapshot and updates assets table."""
        now = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scans (domain, timestamp, score, grade, raw_json) VALUES (?, ?, ?, ?, ?)",
                (domain, now, score, grade, json.dumps(data))
            )
            # Save subdomains
            for sub in data.get("subdomains", []):
                cursor.execute("""
                    INSERT INTO assets (domain, asset_type, asset_value, first_seen, last_seen)
                    VALUES (?, 'subdomain', ?, ?, ?)
                    ON CONFLICT(domain, asset_type, asset_value) DO UPDATE SET last_seen=excluded.last_seen
                """, (domain, sub, now, now))
            # Save open ports
            for svc in data.get("services", []):
                if svc.get("state") == "open":
                    port_str = f"{svc.get('port')}/tcp"
                    cursor.execute("""
                        INSERT INTO assets (domain, asset_type, asset_value, first_seen, last_seen)
                        VALUES (?, 'port', ?, ?, ?)
                        ON CONFLICT(domain, asset_type, asset_value) DO UPDATE SET last_seen=excluded.last_seen
                    """, (domain, port_str, now, now))
            conn.commit()

    def get_latest_scans(self, domain: str, limit: int = 2) -> List[Dict[str, Any]]:
        """Returns the most recent N scans for comparison."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, domain, timestamp, score, grade, raw_json FROM scans WHERE domain = ? ORDER BY id DESC LIMIT ?",
                (domain, limit)
            )
            rows = cursor.fetchall()
            return [
                {"id": r[0], "domain": r[1], "timestamp": r[2], "score": r[3], "grade": r[4], "data": json.loads(r[5])}
                for r in rows
            ]
