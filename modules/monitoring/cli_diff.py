"""
CLI Report Diff Tool for Regression Tracking
Compares two local report JSON files and renders a clean terminal diff comparison.
"""

import json
from typing import Dict, Any
from modules.monitoring.diff_engine import compute_scan_diff

def compare_json_reports(file1: str, file2: str) -> Dict[str, Any]:
    """Loads two JSON scan reports and returns the computed diff."""
    with open(file1, "r", encoding="utf-8") as f:
        d1 = json.load(f)
    with open(file2, "r", encoding="utf-8") as f:
        d2 = json.load(f)
    return compute_scan_diff(d1, d2)
