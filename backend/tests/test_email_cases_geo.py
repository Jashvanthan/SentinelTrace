"""
SentinelTrace — Case A, B, C Email IP Forensic & Geolocation Verification
Tests:
Case A: Email with private IP + public IP
Case B: Email with multiple public IPs
Case C: Email with only private/loopback IPs
"""
import uuid
import pytest
from app.models.email_analysis import EmailAnalysis, AnalysisStatus
from app.models.ioc import IOC, IOCType
from app.schemas.email_analysis import EmailObservedIPsResponse, ObservedIPItem
from app.api.v1.emails import _normalize_raw_ip, get_analysis_observed_ips
from app.services.geo_service import GeoService


def test_ip_normalization_canonical_cases():
    assert _normalize_raw_ip("08.25.10.35") == "8.25.10.35"
    assert _normalize_raw_ip("192.168.1.10") == "192.168.1.10"
    assert _normalize_raw_ip("203.0.113.50") == "203.0.113.50"


def test_case_a_private_and_public_ip():
    """Case A: Email contains private IP + public IP."""
    raw_received = [
        "from [192.168.1.10] by mail.local (Postfix) with ESMTP id ABC1234",
        "from [203.0.113.50] by relay.isp.net (Postfix) with ESMTP id DEF5678",
    ]
    
    import re, ipaddress
    observed_ips = []
    seen = set()
    for idx, header in enumerate(raw_received):
        raw_ips = re.findall(r'(?:\[|\b)((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,39})(?:\]|\b)', str(header))
        for rip in raw_ips:
            try:
                norm = _normalize_raw_ip(rip)
                ip_obj = ipaddress.ip_address(norm)
                ip_str = str(ip_obj)
                if ip_str not in seen:
                    seen.add(ip_str)
                    is_priv = GeoService._is_private(ip_str)
                    observed_ips.append(
                        ObservedIPItem(
                            ip_address=ip_str,
                            source="received_hop",
                            hop_number=idx + 1,
                            is_private=is_priv,
                            description=f"Received transit hop #{idx + 1}",
                        )
                    )
            except ValueError:
                continue

    public_candidates = [ip for ip in observed_ips if not ip.is_private]
    private_candidates = [ip for ip in observed_ips if ip.is_private]

    assert len(private_candidates) == 1
    assert private_candidates[0].ip_address == "192.168.1.10"
    assert len(public_candidates) == 1
    assert public_candidates[0].ip_address == "203.0.113.50"


def test_case_b_multiple_public_ips():
    """Case B: Email contains multiple public IPs."""
    raw_received = [
        "from [203.0.113.50] by relay1.isp.net with ESMTP id 111",
        "from [198.51.100.20] by relay2.isp.net with ESMTP id 222",
    ]

    import re, ipaddress
    observed_ips = []
    seen = set()
    for idx, header in enumerate(raw_received):
        raw_ips = re.findall(r'(?:\[|\b)((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,39})(?:\]|\b)', str(header))
        for rip in raw_ips:
            try:
                norm = _normalize_raw_ip(rip)
                ip_obj = ipaddress.ip_address(norm)
                ip_str = str(ip_obj)
                if ip_str not in seen:
                    seen.add(ip_str)
                    is_priv = GeoService._is_private(ip_str)
                    observed_ips.append(
                        ObservedIPItem(
                            ip_address=ip_str,
                            source="received_hop",
                            hop_number=idx + 1,
                            is_private=is_priv,
                            description=f"Received transit hop #{idx + 1}",
                        )
                    )
            except ValueError:
                continue

    public_candidates = [ip for ip in observed_ips if not ip.is_private]
    assert len(public_candidates) == 2
    assert public_candidates[0].ip_address == "203.0.113.50"
    assert public_candidates[1].ip_address == "198.51.100.20"


def test_case_c_only_private_ips():
    """Case C: Email contains only private/loopback IPs."""
    raw_received = [
        "from [192.168.1.10] by internal.lan with ESMTP",
        "from [10.0.0.1] by gateway.lan with ESMTP",
        "from [127.0.0.1] by localhost with ESMTP",
    ]

    import re, ipaddress
    observed_ips = []
    seen = set()
    for idx, header in enumerate(raw_received):
        raw_ips = re.findall(r'(?:\[|\b)((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,39})(?:\]|\b)', str(header))
        for rip in raw_ips:
            try:
                norm = _normalize_raw_ip(rip)
                ip_obj = ipaddress.ip_address(norm)
                ip_str = str(ip_obj)
                if ip_str not in seen:
                    seen.add(ip_str)
                    is_priv = GeoService._is_private(ip_str)
                    observed_ips.append(
                        ObservedIPItem(
                            ip_address=ip_str,
                            source="received_hop",
                            hop_number=idx + 1,
                            is_private=is_priv,
                            description=f"Received transit hop #{idx + 1}",
                        )
                    )
            except ValueError:
                continue

    public_candidates = [ip for ip in observed_ips if not ip.is_private]
    assert len(public_candidates) == 0
    assert len(observed_ips) == 3
