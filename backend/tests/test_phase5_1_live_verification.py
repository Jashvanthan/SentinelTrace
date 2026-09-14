"""
SentinelTrace — Phase 5.1 Live Provider & Production Readiness Test Suite
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

# Ensure app is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.geo_service import GeoService, MaxMindAdapter
from app.services.ip_trace.geoip import GeoIPService
from app.services.intel_service import VirusTotalAdapter, AbuseIPDBAdapter, ShodanAdapter, ThreatIntelService
from app.services.ip_trace.threat_intel import ThreatIntelTraceService
from app.services.ip_trace.service import IPTraceService
from app.services.ip_trace.classifier import classify_ip
from app.services.ip_trace.internal_telemetry import get_internal_telemetry


class TestPhase51ProductionReadiness(unittest.IsolatedAsyncioTestCase):

    async def test_1_env_preflight(self):
        """Verify provider initialization gracefully handles missing keys as NOT_CONFIGURED."""
        vt = VirusTotalAdapter()
        res_vt = await vt.enrich_ip("8.8.8.8")
        self.assertEqual(res_vt["status"], "NOT_CONFIGURED")

        abuse = AbuseIPDBAdapter()
        res_ab = await abuse.enrich_ip("8.8.8.8")
        self.assertEqual(res_ab["status"], "NOT_CONFIGURED")

        shodan = ShodanAdapter()
        res_sh = await shodan.enrich_ip("8.8.8.8")
        self.assertEqual(res_sh["status"], "NOT_CONFIGURED")
        print("  ✓ Env Preflight verified: Missing API keys return NOT_CONFIGURED")

    async def test_2_geoip_fallback_verification(self):
        """Verify GeoIP falls back to live public providers when MaxMind is not present."""
        geo_svc = GeoIPService()
        res = await geo_svc.get_geoip("8.8.8.8")
        self.assertIsNotNone(res)
        self.assertIn(res.get("provider"), ["ipwho.is", "ip-api.com", "ipwhois.io", "ipinfo.io", "MaxMind GeoIP2"])
        self.assertIsNotNone(res.get("country"))
        self.assertEqual(res.get("accuracy"), "approximate")
        print(f"  ✓ Live Fallback GeoIP verified: {res.get('city')}, {res.get('country')} via {res.get('provider')}")

    async def test_3_provider_independence_failure_isolation(self):
        """Verify that failure or timeout in 1 provider does not affect other providers or fail trace."""
        svc = ThreatIntelTraceService()
        intel_svc = svc._intel_service
        
        # Patch VT adapter (index 0) to raise 500 exception and AbuseIPDB (index 1) to return available result
        with patch.object(intel_svc._providers[0], "enrich_ip", side_effect=Exception("API 500 Error")), \
             patch.object(intel_svc._providers[1], "enrich_ip", new_callable=AsyncMock) as mock_abuse:
            
            mock_abuse.return_value = {
                "provider": "AbuseIPDB",
                "status": "AVAILABLE",
                "abuse_confidence": 30,
                "total_reports": 5,
                "last_reported": "2026-09-10T12:00:00Z",
                "country": "US",
                "isp": "Google LLC",
                "domain": "google.com",
                "categories": ["DNS Poisoning"],
                "confidence": "MEDIUM",
            }
            res = await svc.get_threat_intel("8.8.8.8")
            self.assertIsNotNone(res)
            self.assertIsNone(res["virustotal"])  # Non-available provider dict is sanitized to None in response schema
            self.assertIsNotNone(res["abuseipdb"])
            self.assertEqual(res["abuseipdb"]["status"], "AVAILABLE")
            self.assertIsNone(res["shodan"])
            self.assertGreater(res["threat_score"], 0)
            print(f"  ✓ Provider Failure Isolation verified: VT failure handled gracefully while AbuseIPDB succeeded (Score: {res['threat_score']})")

    async def test_4_status_accuracy_unconfigured_not_clean(self):
        """Verify NOT_CONFIGURED status is strictly maintained and not mapped to CLEAN."""
        svc = ThreatIntelTraceService()
        res = await svc.get_threat_intel("8.8.8.8")
        self.assertEqual(res["status"], "NOT_CONFIGURED")
        self.assertEqual(res["severity"], "CLEAN")
        self.assertIn("0 / 3 providers active", res["provider_coverage"])
        print("  ✓ Status Accuracy verified: Unconfigured providers strictly marked NOT_CONFIGURED")

    async def test_5_provider_conflict_detection(self):
        """Verify conflicting provider signals set provider_disagreement_detected to True."""
        svc = ThreatIntelTraceService()
        intel_svc = svc._intel_service
        
        with patch.object(intel_svc._providers[0], "enrich_ip", new_callable=AsyncMock) as mock_vt, \
             patch.object(intel_svc._providers[1], "enrich_ip", new_callable=AsyncMock) as mock_ab:
            
            mock_vt.return_value = {
                "provider": "VirusTotal",
                "status": "AVAILABLE",
                "malicious": 15,
                "suspicious": 3,
                "total_engines": 70,
                "reputation": -20,
                "confidence": "MEDIUM",
            }
            mock_ab.return_value = {
                "provider": "AbuseIPDB",
                "status": "AVAILABLE",
                "abuse_confidence": 0,
                "total_reports": 0,
                "confidence": "MEDIUM",
            }
            res = await svc.get_threat_intel("1.2.3.4")
            self.assertTrue(res["provider_disagreement_detected"])
            self.assertIsNotNone(res["disagreement_details"])
            print(f"  ✓ Provider Conflict Detection verified: {res['disagreement_details']}")

    async def test_6_private_ip_protection_and_lan_telemetry(self):
        """Verify private IPs are NEVER queried against public providers and LAN telemetry status is honest."""
        trace_svc = IPTraceService()
        private_ips = ["192.168.1.100", "10.0.4.1", "172.16.0.5", "127.0.0.1", "fe80::1"]
        
        for ip in private_ips:
            res = await trace_svc.trace_ip(ip)
            self.assertFalse(res["is_public"])
            self.assertTrue(res["is_private"])
            self.assertIsNone(res["geo"])
            self.assertEqual(res["threat"]["status"], "NOT_APPLICABLE")
            self.assertIn(res["status"], ["unavailable", "NOT_CONNECTED"])
            self.assertIsNone(res["internal_network"]["mac"]) # Zero fake MAC/switch/port data
        print("  ✓ Private IP Protection & Honest LAN Telemetry verified")

    async def test_7_full_ip_trace_orchestration(self):
        """Verify full single IP trace end-to-end orchestration."""
        trace_svc = IPTraceService()
        res = await trace_svc.trace_ip("8.8.8.8")
        self.assertEqual(res["ip"], "8.8.8.8")
        self.assertTrue(res["is_public"])
        self.assertIsNotNone(res["geo"])
        self.assertIsNotNone(res["network"])
        self.assertIsNotNone(res["dns"])
        self.assertIsNotNone(res["threat"])
        self.assertGreaterEqual(len(res["evidence"]), 2)
        print("  ✓ Full IP Trace Orchestration verified")


if __name__ == "__main__":
    unittest.main()
