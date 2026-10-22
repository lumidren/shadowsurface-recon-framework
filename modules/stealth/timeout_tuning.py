"""
Dynamic Socket Timeout & Connection Latency Calibration Engine
Calibrates network socket timeouts automatically based on initial RTT measurements.
"""

import socket
import time
from typing import Dict, Any

def calibrate_target_timeout(target_ip: str, port: int = 80, fallback: float = 2.0) -> Dict[str, Any]:
    """Measures initial TCP handshake RTT and computes optimal socket timeout."""
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(fallback)
    try:
        if s.connect_ex((target_ip, port)) == 0:
            rtt = time.time() - start
            optimal_timeout = max(0.5, round(rtt * 3.0, 2))
            return {
                "rtt_seconds": round(rtt, 3),
                "optimal_timeout": optimal_timeout,
                "status": "CALIBRATED"
            }
    except Exception:
        pass
    finally:
        s.close()

    return {
        "rtt_seconds": None,
        "optimal_timeout": fallback,
        "status": "DEFAULT_FALLBACK"
    }
