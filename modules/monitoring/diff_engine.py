"""
Daily Drift & Diff Engine for Newly Exposed Assets
Compares two assessment results and identifies new subdomains, newly opened ports, and score changes.
"""

from typing import Dict, Any, List, Set

def compute_scan_diff(previous_scan: Dict[str, Any], current_scan: Dict[str, Any]) -> Dict[str, Any]:
    """Computes daily drift between past and present scans."""
    prev_subs: Set[str] = set(previous_scan.get("subdomains", []))
    curr_subs: Set[str] = set(current_scan.get("subdomains", []))

    new_subdomains = sorted(list(curr_subs - prev_subs))
    removed_subdomains = sorted(list(prev_subs - curr_subs))

    # Ports
    prev_ports: Set[int] = {s.get("port") for s in previous_scan.get("services", []) if s.get("state") == "open"}
    curr_ports: Set[int] = {s.get("port") for s in current_scan.get("services", []) if s.get("state") == "open"}

    new_ports = sorted(list(curr_ports - prev_ports))
    closed_ports = sorted(list(prev_ports - curr_ports))

    # Scores
    prev_score = previous_scan.get("risk_assessment", {}).get("posture_score", 100)
    curr_score = current_scan.get("risk_assessment", {}).get("posture_score", 100)
    score_delta = curr_score - prev_score

    has_drift = bool(new_subdomains or new_ports or score_delta != 0)

    return {
        "target": current_scan.get("target"),
        "has_drift": has_drift,
        "score_delta": score_delta,
        "new_subdomains": new_subdomains,
        "removed_subdomains": removed_subdomains,
        "new_open_ports": new_ports,
        "closed_ports": closed_ports,
        "summary": f"Detected {len(new_subdomains)} new subdomain(s), {len(new_ports)} new open port(s)." if has_drift else "No drift detected."
    }
