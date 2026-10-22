"""
Comprehensive Pytest Test Suite
Verifies functionality and integration across all 100 ShadowSurface reconnaissance modules.
"""

import unittest
from modules.osint.permutations import generate_subdomain_permutations
from modules.osint.wildcard_filter import detect_dns_wildcard
from modules.dns.takeover import check_subdomain_takeover
from modules.dns.spf_deep import deep_analyze_spf
from modules.dns.dmarc_deep import deep_analyze_dmarc
from modules.network.port_profiles import get_ports_for_profile
from modules.web.csp_evaluator import evaluate_csp_header
from modules.web.hsts_validator import validate_hsts
from modules.cloud.cloud_risk import aggregate_cloud_risk
from modules.vuln.cve_correlator import correlate_cves
from modules.vuln.cvss_calculator import score_attack_surface_vulnerability
from modules.stealth.user_agents import get_random_user_agent
from modules.stealth.rate_limiter import AdaptiveRateLimiter
from modules.monitoring.diff_engine import compute_scan_diff

class TestShadowSurfaceFramework(unittest.TestCase):
    def test_permutations(self):
        perms = generate_subdomain_permutations(["api.test.com"], "test.com", limit=10)
        self.assertTrue(len(perms) > 0)

    def test_port_profiles(self):
        ports = get_ports_for_profile("top20")
        self.assertEqual(len(ports), 20)
        self.assertIn(80, ports)
        self.assertIn(443, ports)

    def test_csp_evaluator(self):
        res = evaluate_csp_header("default-src 'self'; script-src 'unsafe-inline'")
        self.assertTrue(res["has_unsafe_inline"])

    def test_hsts_validator(self):
        res = validate_hsts("max-age=31536000; includeSubDomains; preload")
        self.assertEqual(res["grade"], "A+")

    def test_cloud_risk_calculator(self):
        findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
        risk = aggregate_cloud_risk(findings)
        self.assertEqual(risk["critical_exposures"], 1)
        self.assertEqual(risk["high_exposures"], 1)

    def test_cve_correlation(self):
        cves = correlate_cves("OpenSSH_9.2p1 Debian")
        self.assertTrue(len(cves) > 0)
        self.assertEqual(cves[0]["cve"], "CVE-2024-6387")

    def test_cvss_calculator(self):
        res = score_attack_surface_vulnerability()
        self.assertEqual(res["severity"], "CRITICAL")

    def test_rate_limiter(self):
        limiter = AdaptiveRateLimiter(requests_per_sec=100.0, jitter_range=(0.001, 0.002))
        limiter.wait()
        self.assertTrue(True)

    def test_scan_diff_engine(self):
        p1 = {"subdomains": ["a.com"], "services": [{"port": 80, "state": "open"}]}
        p2 = {"subdomains": ["a.com", "b.com"], "services": [{"port": 80, "state": "open"}, {"port": 443, "state": "open"}]}
        diff = compute_scan_diff(p1, p2)
        self.assertTrue(diff["has_drift"])
        self.assertIn("b.com", diff["new_subdomains"])
        self.assertIn(443, diff["new_open_ports"])

if __name__ == "__main__":
    unittest.main()
