"""
SentinelTrace — MaxMind GeoIP2 Integration & Exact-IP Tracing Tests
Validates all requirements:
1. MaxMind GeoIP2 as primary authoritative offline source
2. Graceful fallback when MaxMind DB is missing/unconfigured
3. Exact-IP invariant: requested_ip == lookup_ip == response.ip_address
4. Accuracy radius, timezone, continent, and ASN extraction
5. Private & reserved IP local handling (RFC 1918) without external queries
6. Multi-provider comparison and disagreement detection
7. Absence of 8.8.8.8 runtime fallback
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.geo_service import (
    GeoService,
    MaxMindAdapter,
    IPWhoisAdapter,
    IPApiAdapter,
    IPInfoAdapter,
    classify_network_routing,
)
from app.schemas.intel import GeoLocationRequest, GeoLocationResponse


@pytest.mark.asyncio
async def test_maxmind_primary_successful_lookup():
    """Test 1 & 7: MaxMind GeoIP2 is primary source and returns complete normalized fields."""
    target_ip = "192.30.252.206"

    mock_city_resp = MagicMock()
    mock_city_resp.country.name = "United States"
    mock_city_resp.country.iso_code = "US"
    mock_city_resp.subdivisions.most_specific.name = "California"
    mock_city_resp.city.name = "San Francisco"
    mock_city_resp.postal.code = "94107"
    mock_city_resp.location.latitude = 37.7749
    mock_city_resp.location.longitude = -122.4194
    mock_city_resp.location.accuracy_radius = 50
    mock_city_resp.location.time_zone = "America/Los_Angeles"
    mock_city_resp.continent.name = "North America"
    mock_city_resp.traits.network = "192.30.252.0/24"
    mock_city_resp.traits.is_anonymous_proxy = False
    mock_city_resp.traits.is_public_proxy = False
    mock_city_resp.traits.is_tor_exit_node = False
    mock_city_resp.traits.is_hosting_provider = True
    mock_city_resp.traits.is_anonymous_vpn = False
    mock_city_resp.traits.isp = "GitHub, Inc."
    mock_city_resp.traits.organization = "GitHub, Inc."
    mock_city_resp.traits.autonomous_system_number = 36459

    with patch("os.path.exists", return_value=True), \
         patch("geoip2.database.Reader") as mock_reader_cls:
        
        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_city_resp
        mock_reader.__enter__.return_value = mock_reader
        mock_reader_cls.return_value = mock_reader

        geo_service = GeoService()
        result = await geo_service.geolocate(target_ip, include_comparison=False)

        # Assert Exact-IP invariant
        assert result["ip_address"] == target_ip
        assert result["provider"] == "maxmind_geoip2"
        assert result["country"] == "United States"
        assert result["country_code"] == "US"
        assert result["region"] == "California"
        assert result["city"] == "San Francisco"
        assert result["postal"] == "94107"
        assert result["latitude"] == 37.7749
        assert result["longitude"] == -122.4194
        assert result["accuracy_radius"] == 50
        assert result["timezone"] == "America/Los_Angeles"
        assert result["continent"] == "North America"
        assert result["asn"] == "AS36459"
        assert result["org"] == "GitHub, Inc."
        assert result["is_hosting"] is True
        assert result["location_status"] == "RESOLVED"
        assert result["location_confidence"] == "HIGH_CONFIDENCE"
        assert result["ip_address"] != "8.8.8.8"


@pytest.mark.asyncio
async def test_maxmind_missing_database_graceful_fallback():
    """Test 2: When MaxMind DB is missing/unconfigured, falls back gracefully to secondary provider."""
    target_ip = "185.220.101.5"

    with patch("os.path.exists", return_value=False), \
         patch.object(IPWhoisAdapter, "geolocate", new_callable=AsyncMock) as mock_whois:
        
        mock_whois.return_value = {
            "provider": "ipwho.is",
            "ip_address": target_ip,
            "country": "Germany",
            "country_code": "DE",
            "region": "Berlin",
            "city": "Berlin",
            "latitude": 52.52,
            "longitude": 13.405,
            "asn": "AS60729",
            "isp": "Stiftung Erneuerbare Freiheit",
            "org": "Tor Exit Node",
            "is_tor": True,
            "is_vpn": False,
            "is_proxy": True,
            "is_hosting": False,
            "routing_type": "TOR_EXIT_NODE",
            "routing_label": "Tor Exit Node",
        }

        geo_service = GeoService()
        result = await geo_service.geolocate(target_ip)

        assert result["ip_address"] == target_ip
        assert result["provider"] == "ipwho.is"
        assert result["country"] == "Germany"
        assert result["city"] == "Berlin"
        assert result["is_tor"] is True
        mock_whois.assert_awaited_once_with(target_ip)


@pytest.mark.asyncio
async def test_private_ip_local_handling_no_external_query():
    """Test 5: Private IPv4/IPv6 addresses intercepted locally without MaxMind or external lookups."""
    geo_service = GeoService()

    for priv_ip in ["10.0.0.1", "172.16.5.10", "192.168.1.20", "127.0.0.1", "169.254.1.1", "::1"]:
        res = await geo_service.geolocate(priv_ip)
        assert res["ip_address"] == priv_ip
        assert res["routing_type"] == "INTERNAL_LAN"
        assert res["location_status"] == "NOT_PUBLICLY_GEOLOCATABLE"
        assert res["country"] == "Local / Internal Network"
        assert res["latitude"] is None
        assert res["longitude"] is None
        assert res["provider"] == "internal"


@pytest.mark.asyncio
async def test_provider_disagreement_detection():
    """Test 6: Telemetry comparison flags provider disagreement when secondary differs."""
    target_ip = "198.51.100.99"

    mock_city_resp = MagicMock()
    mock_city_resp.country.name = "Romania"
    mock_city_resp.country.iso_code = "RO"
    mock_city_resp.subdivisions.most_specific.name = "Bucharest"
    mock_city_resp.city.name = "Bucharest"
    mock_city_resp.postal.code = "010000"
    mock_city_resp.location.latitude = 44.4323
    mock_city_resp.location.longitude = 26.1063
    mock_city_resp.location.accuracy_radius = 20
    mock_city_resp.location.time_zone = "Europe/Bucharest"
    mock_city_resp.continent.name = "Europe"
    mock_city_resp.traits.network = None
    mock_city_resp.traits.is_anonymous_proxy = False
    mock_city_resp.traits.is_public_proxy = False
    mock_city_resp.traits.is_tor_exit_node = False
    mock_city_resp.traits.is_hosting_provider = False
    mock_city_resp.traits.is_anonymous_vpn = False
    mock_city_resp.traits.isp = "Cyber Range Transit"
    mock_city_resp.traits.organization = "Cyber Range Transit"
    mock_city_resp.traits.autonomous_system_number = 64496

    with patch("os.path.exists", return_value=True), \
         patch("geoip2.database.Reader") as mock_reader_cls, \
         patch.object(IPWhoisAdapter, "geolocate", new_callable=AsyncMock) as mock_whois:

        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_city_resp
        mock_reader.__enter__.return_value = mock_reader
        mock_reader_cls.return_value = mock_reader

        # Secondary provider returns different country
        mock_whois.return_value = {
            "provider": "ipwho.is",
            "ip_address": target_ip,
            "country": "Germany",
            "region": "Frankfurt",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "asn": "AS64496",
            "isp": "Cyber Range Transit",
        }

        geo_service = GeoService()
        result = await geo_service.geolocate(target_ip, include_comparison=True)

        assert result["ip_address"] == target_ip
        assert result["provider"] == "maxmind_geoip2"
        assert result["country"] == "Romania"
        assert result["location_confidence"] == "PROVIDER_DISAGREEMENT"
        assert result["provider_comparison"] is not None
        assert len(result["provider_comparison"]) == 1
        assert result["provider_comparison"][0]["status"] == "DISAGREED"


@pytest.mark.asyncio
async def test_all_providers_fail_exact_ip_preserved():
    """Test 8: When all providers fail, exact IP is preserved with explicit UNAVAILABLE status."""
    target_ip = "198.51.100.40"

    with patch.object(MaxMindAdapter, "geolocate", new_callable=AsyncMock) as mock_maxmind, \
         patch.object(IPWhoisAdapter, "geolocate", new_callable=AsyncMock) as mock_whois, \
         patch.object(IPApiAdapter, "geolocate", new_callable=AsyncMock) as mock_ipapi, \
         patch.object(IPInfoAdapter, "geolocate", new_callable=AsyncMock) as mock_ipinfo:

        mock_maxmind.return_value = {"error": "DB unconfigured", "provider": "maxmind_geoip2"}
        mock_whois.return_value = {"error": "HTTP timeout", "provider": "ipwho.is"}
        mock_ipapi.return_value = {"error": "Rate limit exceeded", "provider": "ip-api.com"}
        mock_ipinfo.return_value = {"error": "Connection error", "provider": "ipinfo.io"}

        geo_service = GeoService()
        result = await geo_service.geolocate(target_ip)

        # Exact-IP guarantee check
        assert result["ip_address"] == target_ip
        assert result["provider"] == "none"
        assert result["location_status"] == "UNAVAILABLE"
        assert result["latitude"] is None
        assert result["longitude"] is None
        assert result["country"] is None
        assert result["ip_address"] != "8.8.8.8"
