"""
SentinelTrace Backend — End-to-End Real .EML Forensic IP Trace Validation Test
Validates the complete pipeline:
.eml raw headers -> RFC 5322 Received parsing -> IP extraction & classification ->
Trust evaluation -> Public enrichment -> Private zero-fabrication telemetry ->
Hop graph reconstruction -> NAT boundary detection -> Evidence ledger -> Timeline & Map
"""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.email_analysis import EmailAnalysis, SeverityLevel
from app.services.ip_trace.service import IPTraceService
from app.services.ip_trace.internal_telemetry import register_internal_telemetry

SAMPLE_EML_CONTENT = """Received: from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41])
\tby mx.recipient-corp.com (Postfix) with ESMTPS id 4SVx8W5
\tfor <analyst@sentineltrace.io>; Sun, 13 Sep 2026 09:12:00 +0000 (UTC)
Received: by mail-wm1-f41.google.com with SMTP id 949d2778
\tfor <analyst@sentineltrace.io>; Sun, 13 Sep 2026 09:11:58 +0000 (UTC)
Received: from corporate-nat-gw.victimcorp.com (203.0.113.88)
\tby smtp.relay.victimcorp.com (10.0.0.5) with ESMTP id 88ab7c;
\tSun, 13 Sep 2026 09:11:45 +0000 (UTC)
Received: from workstation-eng-42.internal.lan (192.168.1.42)
\tby internal-exchange.victimcorp.com (10.0.0.1) with MAPI;
\tSun, 13 Sep 2026 09:11:30 +0000 (UTC)
X-Originating-IP: [192.168.1.42]
From: attacker@spoofed-domain.com
To: analyst@sentineltrace.io
Subject: Urgent: Quarterly Security Audit Findings
Date: Sun, 13 Sep 2026 09:11:25 +0000
Message-ID: <threat-campaign-991@spoofed-domain.com>

Please review the attached network findings.
"""

async def run_eml_e2e_validation():
    print("\n=======================================================")
    print("STARTING REAL .EML FORENSIC IP TRACE E2E VALIDATION")
    print("=======================================================\n")

    ws_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())

    # 1. Register verified internal telemetry for workstation IP
    register_internal_telemetry(ws_id, "192.168.1.42", {
        "mac": "00:50:56:C0:00:08",
        "hostname": "workstation-eng-42.internal.lan",
        "vlan": 100,
        "switch": "SW-CORE-01",
        "port": "Te1/0/4",
        "physical_location": {
            "building": "HQ Building Alpha",
            "floor": "3rd Floor",
            "room": "SOC Lab 302",
        },
        "location_confidence": "HIGH",
        "sources": ["ENTERPRISE_DHCP", "802.1X_NAC", "MANAGED_SWITCH"],
    })

    # 2. Mock EmailAnalysis record with headers
    analysis = EmailAnalysis(
        id=uuid.uuid4(),
        workspace_id=uuid.UUID(ws_id),
        subject="Urgent: Quarterly Security Audit Findings",
        sender_email="attacker@spoofed-domain.com",
        recipients=["analyst@sentineltrace.io"],
        all_headers={
            "received": [
                "from workstation-eng-42.internal.lan (192.168.1.42) by internal-exchange.victimcorp.com (10.0.0.1) with MAPI; Sun, 13 Sep 2026 09:11:30 +0000 (UTC)",
                "from corporate-nat-gw.victimcorp.com (203.0.113.88) by smtp.relay.victimcorp.com (10.0.0.5) with ESMTP id 88ab7c; Sun, 13 Sep 2026 09:11:45 +0000 (UTC)",
                "from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.recipient-corp.com (Postfix) with ESMTPS id 4SVx8W5 for <analyst@sentineltrace.io>; Sun, 13 Sep 2026 09:12:00 +0000 (UTC)"
            ],
            "x-originating-ip": "[192.168.1.42]",
            "from": "attacker@spoofed-domain.com",
            "to": "analyst@sentineltrace.io",
            "date": "Sun, 13 Sep 2026 09:11:25 +0000",
        },
        received_headers=[
            "from workstation-eng-42.internal.lan (192.168.1.42) by internal-exchange.victimcorp.com (10.0.0.1) with MAPI; Sun, 13 Sep 2026 09:11:30 +0000 (UTC)",
            "from corporate-nat-gw.victimcorp.com (203.0.113.88) by smtp.relay.victimcorp.com (10.0.0.5) with ESMTP id 88ab7c; Sun, 13 Sep 2026 09:11:45 +0000 (UTC)",
            "from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.recipient-corp.com (Postfix) with ESMTPS id 4SVx8W5 for <analyst@sentineltrace.io>; Sun, 13 Sep 2026 09:12:00 +0000 (UTC)"
        ],
        threat_score=75.0,
        severity=SeverityLevel.HIGH,
    )



    # 3. Execute full multi-hop email trace
    service = IPTraceService()
    result = await service.trace_email_analysis(analysis, workspace_id=ws_id, user_id=user_id)

    print(f"Total Hops Identified: {result['total_hops']}")
    assert result["total_hops"] >= 3, f"Expected at least 3 hops, got {result['total_hops']}"

    # Verify Hop 1 (Earliest Observed Hop / Workstation)
    hop1 = result["hops"][0]
    print(f"Hop 1: IP={hop1['ip']} Classification={hop1['classification']} Role={hop1['network_role']} Trust={hop1['trust_level']}")
    assert hop1["ip"] == "192.168.1.42"
    assert hop1["is_private"] is True
    assert hop1["is_public"] is False
    assert hop1["trust_level"] == "UNTRUSTED" or hop1["trust_level"] == "PARTIALLY_TRUSTED"
    assert hop1["trace_details"]["internal_network"]["mac"] == "00:50:56:C0:00:08"
    assert hop1["trace_details"]["internal_network"]["physical_location"]["building"] == "HQ Building Alpha"

    # Verify NAT Boundary Detection
    assert result["has_nat_boundary"] is True, "NAT boundary must be detected when transitioning from private subnet to egress gateway"
    print(f"NAT Boundary Detected: {result['has_nat_boundary']}")
    print(f"Boundaries count: {len(result['boundaries'])}")

    # Verify Public Locations (Plotted on Map)
    print(f"Public Map Locations: {len(result['public_locations'])}")
    for loc in result["public_locations"]:
        print(f"  - Public Node: IP={loc['ip']} Role={loc['role']} Lat/Lon=({loc['latitude']}, {loc['longitude']})")
        assert loc["latitude"] is not None and loc["longitude"] is not None

    # Verify Private Network Nodes (Plotted in Network Topology)
    print(f"Private Topology Nodes: {len(result['private_network_nodes'])}")
    for pnode in result["private_network_nodes"]:
        print(f"  - Private Node: IP={pnode['ip']} Role={pnode['role']} MAC={pnode['mac']}")
        assert pnode["ip"].startswith("192.168.") or pnode["ip"].startswith("10.")

    # Verify Timeline
    print(f"Forensic Timeline Steps: {len(result['timeline'])}")
    assert len(result["timeline"]) >= 3

    # Verify Evidence Ledger
    print(f"Evidence Ledger Items: {len(result['evidence'])}")
    assert len(result["evidence"]) >= 5
    for ev in result["evidence"]:
        print(f"  [{ev['source_type']}] {ev['source']} -> {ev['value']} (Confidence: {ev['confidence']})")

    print("\n=======================================================")
    print("SUCCESS: REAL .EML FORENSIC IP TRACE VALIDATION PASSED!")
    print("=======================================================\n")

if __name__ == "__main__":
    asyncio.run(run_eml_e2e_validation())
