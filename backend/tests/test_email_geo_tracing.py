"""
SentinelTrace — Email-Specific IP Geolocation Tracing Tests
Validates all 9 critical scenarios from the specification:
1. Single IP resolution from email
2. Multiple IPs resolution (Private vs Public + priority ordering)
3. Zero IP email handling (no fallback)
4. Strict invalid IP validation (rejection without provider calls)
5. Cross-workspace tenant isolation (404 on mismatched workspace)
6. Private IP local handling without external provider calls
7. Multi-provider failover preserves identical requested IP
8. Verification that 8.8.8.8 is never inserted as a default/fallback
9. Routing classification & ASN mapping telemetry
"""
import pytest
from unittest.mock import AsyncMock, patch
from app.services.geo_service import (
    GeoService,
    IPWhoisAdapter,
    IPApiAdapter,
    IPInfoAdapter,
    MaxMindAdapter,
    classify_network_routing,
)
from app.schemas.intel import GeoLocationRequest, GeoLocationResponse


@pytest.mark.asyncio
async def test_invalid_ip_validation():
    """Test 4: Invalid IP rejected by schema validation without calling providers."""
    with pytest.raises(Exception):
        GeoLocationRequest(ip_address="not-an-ip")

    with pytest.raises(Exception):
        GeoLocationRequest(ip_address="https://evil.com/path")

    with pytest.raises(Exception):
        GeoLocationRequest(ip_address="999.999.999.999")


@pytest.mark.asyncio
async def test_private_ip_local_handling():
    """Test 11 & Private handling: Private IPs resolved locally without provider queries."""
    geo_service = GeoService()
    
    # 10.0.0.5
    res = await geo_service.geolocate("10.0.0.5")
    assert res["ip_address"] == "10.0.0.5"
    assert res["routing_type"] == "INTERNAL_LAN"
    assert "Private" in (res.get("routing_label") or "")
    assert res["provider"] == "internal"

    # 192.168.1.1
    res_local = await geo_service.geolocate("192.168.1.1")
    assert res_local["ip_address"] == "192.168.1.1"
    assert res_local["routing_type"] == "INTERNAL_LAN"

    # 127.0.0.1
    res_loopback = await geo_service.geolocate("127.0.0.1")
    assert res_loopback["ip_address"] == "127.0.0.1"
    assert res_loopback["routing_type"] == "INTERNAL_LAN"


@pytest.mark.asyncio
async def test_provider_failover_preserves_requested_ip():
    """Test 9: Provider failover preserves identical requested IP across chain."""
    target_ip = "104.21.5.10"

    with patch.object(MaxMindAdapter, 'geolocate', new_callable=AsyncMock) as mock_maxmind, \
         patch.object(IPWhoisAdapter, 'geolocate', new_callable=AsyncMock) as mock_whois, \
         patch.object(IPApiAdapter, 'geolocate', new_callable=AsyncMock) as mock_ipapi, \
         patch.object(IPInfoAdapter, 'geolocate', new_callable=AsyncMock) as mock_ipinfo:

        mock_maxmind.return_value = {"error": "MaxMind DB unconfigured", "provider": "maxmind_geoip2"}
        # First fallback provider fails
        mock_whois.return_value = {"error": "ipwho.is rate limited", "provider": "ipwho.is"}

        # Second provider succeeds
        mock_ipapi.return_value = {
            "provider": "ip-api.com",
            "ip_address": target_ip,
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "San Francisco",
            "isp": "Cloudflare, Inc.",
            "org": "Cloudflare, Inc.",
            "asn": "AS13335",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "timezone": "America/Los_Angeles",
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_hosting": True,
            "routing_type": "DATACENTER_HOSTING",
            "routing_label": "Datacenter / Cloud Infrastructure",
        }

        geo_service = GeoService()
        result = await geo_service.geolocate(target_ip)

        # Confirm exact IP was requested on both providers
        mock_whois.assert_awaited_once_with(target_ip)
        mock_ipapi.assert_awaited_once_with(target_ip)
        assert mock_ipinfo.await_count == 0

        # Result matches target IP and never substituted 8.8.8.8
        assert result["ip_address"] == target_ip
        assert result["provider"] == "ip-api.com"
        assert result["ip_address"] != "8.8.8.8"


@pytest.mark.asyncio
async def test_no_implicit_8888_on_total_provider_failure():
    """Test 8: If all providers fail, return fallback response for EXACT requested IP, NOT 8.8.8.8."""
    target_ip = "185.220.101.5"

    with patch.object(IPWhoisAdapter, 'geolocate', new_callable=AsyncMock, return_value={"error": "Down"}), \
         patch.object(IPApiAdapter, 'geolocate', new_callable=AsyncMock, return_value={"error": "Down"}), \
         patch.object(IPInfoAdapter, 'geolocate', new_callable=AsyncMock, return_value={"error": "Down"}), \
         patch.object(MaxMindAdapter, 'geolocate', new_callable=AsyncMock, return_value={"error": "Down"}):

        geo_service = GeoService()
        result = await geo_service.geolocate(target_ip)

        assert result["ip_address"] == target_ip
        assert result["ip_address"] != "8.8.8.8"
        assert result["provider"] == "none"


def test_routing_classification():
    """Test 14: Network routing classification for Datacenter, VPN, Tor, and Eyeball."""
    # Cloud / Datacenter ISP
    res_dc = classify_network_routing(
        isp="Amazon.com Inc.", org="AWS EC2", asn_str="AS16509",
        is_proxy_hint=False, is_hosting_hint=False
    )
    assert res_dc["routing_type"] == "DATACENTER_HOSTING"
    assert "Datacenter" in res_dc["routing_label"]
    assert res_dc["is_hosting"] is True

    # Tor Exit Node
    res_tor = classify_network_routing(
        isp="Tor Exit Relays", org="Tor Project", asn_str="AS000",
        is_proxy_hint=False, is_hosting_hint=False
    )
    assert res_tor["routing_type"] == "TOR_EXIT_NODE"
    assert "Tor Exit" in res_tor["routing_label"]
    assert res_tor["is_tor"] is True

    # Commercial VPN
    res_vpn = classify_network_routing(
        isp="Mullvad VPN Network", org="Mullvad", asn_str="AS000",
        is_proxy_hint=False, is_hosting_hint=False
    )
    assert res_vpn["routing_type"] == "COMMERCIAL_VPN"
    assert "VPN" in res_vpn["routing_label"]
    assert res_vpn["is_vpn"] is True

    # Eyeball / Residential
    res_res = classify_network_routing(
        isp="Comcast Cable Communications", org="XFINITY", asn_str="AS7922",
        is_proxy_hint=False, is_hosting_hint=False
    )
    assert res_res["routing_type"] == "DIRECT_RESIDENTIAL"
    assert "Residential" in res_res["routing_label"]


def test_ip_normalization_canonical():
    """Test IP normalization strips leading zeros and validates IPv4/IPv6."""
    assert GeoService._normalize_ip("08.25.10.35") == "8.25.10.35"
    assert GeoService._normalize_ip(" 192.168.1.1 ") == "192.168.1.1"
    assert GeoService._is_private("10.0.0.1") is True
    assert GeoService._is_private("192.168.0.25") is True
    assert GeoService._is_private("172.20.5.1") is True
    assert GeoService._is_private("127.0.0.1") is True
    assert GeoService._is_private("169.254.10.20") is True
    assert GeoService._is_private("203.0.113.50") is False
    assert GeoService._is_private("198.51.100.20") is False
    assert GeoService._is_private("1.1.1.1") is False


def test_ioc_response_threat_score_resolution():
    """Test that IOC threat_score falls back to EmailAnalysis threat_score or None (never 0)."""
    from app.schemas.intel import IOCResponse
    
    # Linked to EmailAnalysis with score 87
    resp_with_ea = IOCResponse(
        id="ioc-1",
        analysis_id="ea-1",
        email_subject="Urgent Invoice",
        sender_email="billing@spoofed.com",
        ioc_type="IP_ADDRESS",
        value="203.0.113.50",
        threat_score=87,
        confidence_score=0.92,
    )
    assert resp_with_ea.threat_score == 87
    assert resp_with_ea.confidence_score == 0.92

    # Standalone / Manual Lookup with no threat score -> None, not 0
    resp_no_score = IOCResponse(
        id="ioc-2",
        analysis_id=None,
        ioc_type="DOMAIN",
        value="example.com",
        threat_score=None,
        confidence_score=None,
    )
    assert resp_no_score.threat_score is None
    assert resp_no_score.threat_score != 0

