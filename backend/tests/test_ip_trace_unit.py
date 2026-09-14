"""
SentinelTrace Backend — IP Trace Unit & Integration Tests

Covers:
1. IPv4 & IPv6 Classification matrix:
   - 8.8.8.8 -> PUBLIC
   - 192.168.1.1 -> PRIVATE
   - 10.0.0.1 -> PRIVATE
   - 172.16.0.1 -> PRIVATE
   - 172.31.255.254 -> PRIVATE
   - 127.0.0.1 -> LOOPBACK
   - 169.254.1.1 -> LINK_LOCAL
   - 224.0.0.1 -> MULTICAST
   - fc00::1 -> UNIQUE_LOCAL
   - fe80::1 -> LINK_LOCAL
   - ::1 -> LOOPBACK
2. Email Received hop chain parsing & NAT boundary detection
3. Private IP non-leakage & zero-fabrication internal telemetry
4. Public IP enrichment (GeoIP, ASN, Reverse DNS, Threat Intel)
"""
import asyncio
import os
import sys

# Ensure backend root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.ip_trace.classifier import IPClassification, classify_ip
from app.services.ip_trace.internal_telemetry import get_internal_telemetry, register_internal_telemetry
from app.services.ip_trace.service import IPTraceService


def test_ip_classification_matrix():
    cases = [
        ("8.8.8.8", IPClassification.PUBLIC, False, True, "approximate"),
        ("1.1.1.1", IPClassification.PUBLIC, False, True, "approximate"),
        ("192.168.1.1", IPClassification.PRIVATE, True, False, "internal-network"),
        ("192.168.100.45", IPClassification.PRIVATE, True, False, "internal-network"),
        ("10.0.0.1", IPClassification.PRIVATE, True, False, "internal-network"),
        ("10.254.254.254", IPClassification.PRIVATE, True, False, "internal-network"),
        ("172.16.0.1", IPClassification.PRIVATE, True, False, "internal-network"),
        ("172.31.255.254", IPClassification.PRIVATE, True, False, "internal-network"),
        ("127.0.0.1", IPClassification.LOOPBACK, True, False, "unknown"),
        ("169.254.1.1", IPClassification.LINK_LOCAL, True, False, "internal-network"),
        ("224.0.0.1", IPClassification.MULTICAST, True, False, "unknown"),
        ("fc00::1", IPClassification.UNIQUE_LOCAL, True, False, "internal-network"),
        ("fd12:3456:789a::1", IPClassification.UNIQUE_LOCAL, True, False, "internal-network"),
        ("fe80::1", IPClassification.LINK_LOCAL, True, False, "internal-network"),
        ("::1", IPClassification.LOOPBACK, True, False, "unknown"),
        ("2001:4860:4860::8888", IPClassification.PUBLIC, False, True, "approximate"),
    ]

    for ip, expected_cls, expected_priv, expected_geo, expected_acc in cases:
        res = classify_ip(ip)
        assert res.classification == expected_cls, f"{ip}: expected {expected_cls}, got {res.classification}"
        assert res.is_private == expected_priv, f"{ip}: expected is_private={expected_priv}, got {res.is_private}"
        assert res.is_geolocatable == expected_geo, f"{ip}: expected is_geolocatable={expected_geo}, got {res.is_geolocatable}"
        assert res.location_accuracy == expected_acc, f"{ip}: expected accuracy={expected_acc}, got {res.location_accuracy}"
        print(f"  [PASS] {ip:24} -> {res.classification.value:14} (is_private={res.is_private}, geolocatable={res.is_geolocatable})")

    print("=> 16 IP classification matrix test cases passed.")


async def test_trace_single_private_and_public_ip():
    tracer = IPTraceService()

    # 1. Test Private IP without registered telemetry
    priv_res = await tracer.trace_ip("192.168.1.45")
    assert priv_res["classification"] == "PRIVATE"
    assert priv_res["is_public"] is False
    assert priv_res["is_private"] is True
    assert priv_res["geo"] is None
    assert priv_res["status"] in ["unavailable", "internal_telemetry_required"]
    assert priv_res["internal_network"]["physical_location"] is None
    assert priv_res["internal_network"]["location_confidence"] == "UNKNOWN"
    print("  [PASS] Private IP zero-fabrication contract verified.")


    # 2. Test Private IP with verified enterprise telemetry
    ws_id = "test-workspace-001"
    register_internal_telemetry(ws_id, "192.168.1.45", {
        "mac": "00:1A:2B:3C:4D:5E",
        "hostname": "WS-045",
        "vlan": 10,
        "switch": "SW-F2-01",
        "port": "Gi1/0/22",
        "physical_location": {
            "building": "Engineering Block",
            "floor": "Floor 2",
            "room": "Lab 204",
        },
        "sources": ["DHCP", "SWITCH_PORT", "NAC"],
    })

    tel_res = await tracer.trace_ip("192.168.1.45", workspace_id=ws_id)
    assert tel_res["status"] == "RESOLVED"
    assert tel_res["internal_network"]["mac"] == "00:1A:2B:3C:4D:5E"
    assert tel_res["internal_network"]["switch"] == "SW-F2-01"
    assert tel_res["internal_network"]["port"] == "Gi1/0/22"
    assert tel_res["internal_network"]["physical_location"]["building"] == "Engineering Block"
    assert tel_res["internal_network"]["location_confidence"] == "HIGH"
    print("  [PASS] Enterprise internal telemetry resolution verified.")

    # 3. Test Public IP
    pub_res = await tracer.trace_ip("8.8.8.8")
    assert pub_res["classification"] == "PUBLIC"
    assert pub_res["is_public"] is True
    assert pub_res["is_private"] is False
    assert pub_res["location_accuracy"] == "approximate"
    assert pub_res["geo"] is not None
    assert pub_res["network"]["asn"] is not None or pub_res["network"]["organization"] is not None
    assert len(pub_res["evidence"]) > 0
    print("  [PASS] Public IP enrichment and evidence ledger verified.")


async def test_email_hop_chain_and_nat_boundary():
    tracer = IPTraceService()

    # Mock EmailAnalysis with Received hops from private to public
    class MockAnalysis:
        id = "00000000-0000-0000-0000-000000000001"
        workspace_id = "test-workspace-001"
        all_headers = {
            "X-Originating-IP": "[192.168.1.45]",
            "Message-ID": "<abc@example.com>",
        }
        received_headers = [
            # Top hop (Latest, Recipient Ingress)
            "from mail-relay.google.com (mail-relay.google.com [142.250.100.1]) by mx.recipient.com with ESMTP id xyz; Sun, 13 Sep 2026 10:00:05 +0000",
            # Intermediate hop (Public Egress Gateway)
            "from mail.corp.example.com (egress.corp.example.com [203.0.113.10]) by mail-relay.google.com with ESMTPS id uvw; Sun, 13 Sep 2026 10:00:03 +0000",
            # Bottom hop (Oldest, Internal Relay)
            "from workstation.corp.local ([10.0.0.5]) by mail.corp.example.com with ESMTP id rst; Sun, 13 Sep 2026 10:00:01 +0000",
        ]
        authentication_results = {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }

    mock_email = MockAnalysis()
    trace = await tracer.trace_email_analysis(mock_email, workspace_id=mock_email.workspace_id)

    assert trace["total_hops"] >= 3
    assert trace["has_nat_boundary"] is True
    assert len(trace["boundaries"]) >= 1
    assert trace["boundaries"][0]["boundary_type"] == "NAT_EGRESS_BOUNDARY"

    print("  [PASS] Email Received hop chain reconstructed:")
    for hop in trace["hops"]:
        print(f"    Hop #{hop['hop_number']}: {hop.get('ip') or 'Host'} ({hop['classification']}) -> {hop['network_role']}")

    print("  [PASS] NAT / Egress boundary correctly detected at transition.")
    print("  [PASS] Timeline events generated:", len(trace["timeline"]))
    print("  [PASS] Evidence ledger entries:", len(trace["evidence"]))


async def main():
    print("\n--- RUNNING SENTINELTRACE IP TRACE TEST SUITE ---")
    test_ip_classification_matrix()
    await test_trace_single_private_and_public_ip()
    await test_email_hop_chain_and_nat_boundary()
    print("\n=======================================================")
    print("ALL SENTINELTRACE IP TRACE & MAP BACKEND TESTS PASSED!")
    print("=======================================================\n")


if __name__ == "__main__":
    asyncio.run(main())
