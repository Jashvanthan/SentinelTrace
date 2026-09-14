"""
SentinelTrace Backend — IP Geolocation & Network Telemetry Service

Multi-provider resilient architecture with automatic failover:
- ipwho.is (Primary HTTPS, high accuracy with ASN, connection type, postal)
- ip-api.com (Secondary JSON endpoint)
- ipinfo.io (Tertiary fallback)
- MaxMind GeoLite2 (Offline database adapter)

Accurately classifies routing telemetry:
- Direct Routing (Residential / Eyeball ISP)
- Direct Routing (Enterprise / Corporate Network)
- Datacenter / Cloud Infrastructure (AWS, GCP, Azure, DigitalOcean, Hetzner, etc.)
- Commercial VPN Gateway (NordVPN, Mullvad, ExpressVPN, etc.)
- Tor Exit Node
- Proxy Relay
"""
from __future__ import annotations

from abc import ABC, abstractmethod
import os
import re
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("sentineltrace.geo")

# Known infrastructure signatures for accurate routing classification
VPN_SIGNATURES = [
    "mullvad", "nordvpn", "expressvpn", "surfshark", "protonvpn", "cyberghost",
    "private internet access", "pia", "windscribe", "ipvanish", "ovpn", "tunnelbear",
    "hide.me", "purevpn", "torguard", "vpn"
]

TOR_SIGNATURES = [
    "tor-exit", "torservers", "tor-node", "tor exit", "tornodes", "tor.exit", "onion",
    "zwiebelfreunde", "torservers.net", "privacyfoundation", "torproject", "relayon",
    "stiftung erneuerbare freiheit", "as60729", "as208323", "as205100"
]

HOSTING_SIGNATURES = [
    "amazon", "aws", "digitalocean", "linode", "akamai", "cloudflare", "ovh",
    "hetzner", "google cloud", "google llc", "microsoft", "azure", "vultr",
    "choopa", "leaseweb", "contabo", "oracle", "alibaba", "fastly", "datacamp",
    "m247", "packethub", "cogent", "cogentco", "hostinger", "rackspace"
]

RESIDENTIAL_SIGNATURES = [
    "comcast", "verizon", "at&t", "charter", "spectrum", "cox", "centurylink",
    "bt ", "british telecommunications", "deutsche telekom", "vodafone", "orange",
    "telefonica", "airtel", "jio", "bsnl", "reliance", "optimum", "telstra",
    "shaw", "rogers", "bell canada", "broadband", "telecom", "dsl", "cable"
]


def classify_network_routing(
    isp: str | None,
    org: str | None,
    asn_str: str | None,
    is_proxy_hint: bool = False,
    is_hosting_hint: bool = False,
) -> dict[str, Any]:
    """
    Deterministically analyze network parameters to identify true routing characteristics.
    """
    text = f"{isp or ''} {org or ''} {asn_str or ''}".lower()

    # 1. Tor Exit Node
    is_tor = any(sig in text for sig in TOR_SIGNATURES)
    if is_tor:
        return {
            "is_tor": True,
            "is_vpn": False,
            "is_proxy": True,
            "is_hosting": False,
            "routing_type": "TOR_EXIT_NODE",
            "routing_label": "Tor Exit Node",
        }

    # 2. Commercial VPN
    is_vpn = any(sig in text for sig in VPN_SIGNATURES)
    if is_vpn:
        return {
            "is_tor": False,
            "is_vpn": True,
            "is_proxy": True,
            "is_hosting": False,
            "routing_type": "COMMERCIAL_VPN",
            "routing_label": "Commercial VPN Gateway",
        }

    # 3. Datacenter / Cloud Infrastructure
    is_hosting = is_hosting_hint or any(sig in text for sig in HOSTING_SIGNATURES)
    if is_hosting:
        return {
            "is_tor": False,
            "is_vpn": False,
            "is_proxy": is_proxy_hint,
            "is_hosting": True,
            "routing_type": "DATACENTER_HOSTING",
            "routing_label": "Datacenter / Cloud Infrastructure",
        }

    # 4. Proxy Relay (explicit hint from provider without VPN/Tor signature)
    if is_proxy_hint:
        return {
            "is_tor": False,
            "is_vpn": False,
            "is_proxy": True,
            "is_hosting": False,
            "routing_type": "PROXY_RELAY",
            "routing_label": "Proxy Relay",
        }

    # 5. Direct Residential vs Direct Enterprise
    is_residential = any(sig in text for sig in RESIDENTIAL_SIGNATURES)
    if is_residential:
        return {
            "is_tor": False,
            "is_vpn": False,
            "is_proxy": False,
            "is_hosting": False,
            "routing_type": "DIRECT_RESIDENTIAL",
            "routing_label": "Direct Routing (Residential / Eyeball ISP)",
        }

    return {
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_hosting": False,
        "routing_type": "DIRECT_ENTERPRISE",
        "routing_label": "Direct Routing (Corporate / Direct ASN)",
    }


class GeoProvider(ABC):
    @abstractmethod
    async def geolocate(self, ip: str) -> dict[str, Any]: ...

    @property
    @abstractmethod
    def provider_name(self) -> str: ...


class IPWhoisAdapter(GeoProvider):
    """Primary HTTPS provider using ipwho.is with comprehensive telemetry."""
    BASE_URL = "https://ipwho.is"

    @property
    def provider_name(self) -> str:
        return "ipwho.is"

    async def geolocate(self, ip: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f"{self.BASE_URL}/{ip}")
                resp.raise_for_status()
                d = resp.json()

            if not d.get("success", False):
                return {"error": d.get("message", "ipwho.is query unsuccessful"), "provider": self.provider_name}

            conn = d.get("connection") or {}
            tz = d.get("timezone") or {}
            isp = conn.get("isp")
            org = conn.get("org") or conn.get("domain")
            asn = f"AS{conn.get('asn')}" if conn.get("asn") else None

            routing = classify_network_routing(
                isp=isp,
                org=org,
                asn_str=asn,
                is_proxy_hint=False,
                is_hosting_hint=False,
            )

            return {
                "provider": self.provider_name,
                "ip_address": ip,
                "country": d.get("country"),
                "country_code": d.get("country_code"),
                "region": d.get("region"),
                "city": d.get("city"),
                "postal": d.get("postal"),
                "latitude": float(d["latitude"]) if d.get("latitude") is not None else None,
                "longitude": float(d["longitude"]) if d.get("longitude") is not None else None,
                "timezone": tz.get("id") or tz.get("utc"),
                "isp": isp,
                "org": org,
                "asn": asn,
                **routing,
            }
        except Exception as e:
            logger.warning("geo_ipwhois_error", ip=ip, error=str(e))
            return {"error": str(e), "provider": self.provider_name}


class IPApiAdapter(GeoProvider):
    """Secondary provider using ip-api.com."""
    BASE_URL = "http://ip-api.com/json"

    @property
    def provider_name(self) -> str:
        return "ip-api.com"

    async def geolocate(self, ip: str) -> dict[str, Any]:
        try:
            params = {
                "fields": "status,message,country,countryCode,region,regionName,city,"
                          "zip,lat,lon,timezone,isp,org,as,query,proxy,hosting",
            }
            if settings.IPAPI_KEY:
                params["key"] = settings.IPAPI_KEY

            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f"{self.BASE_URL}/{ip}", params=params)
                resp.raise_for_status()
                d = resp.json()

            if d.get("status") == "fail":
                return {"error": d.get("message", "ip-api query failed"), "provider": self.provider_name}

            isp = d.get("isp")
            org = d.get("org")
            asn = d.get("as")
            is_proxy_raw = bool(d.get("proxy", False))
            is_hosting_raw = bool(d.get("hosting", False))

            routing = classify_network_routing(
                isp=isp,
                org=org,
                asn_str=asn,
                is_proxy_hint=is_proxy_raw,
                is_hosting_hint=is_hosting_raw,
            )

            return {
                "provider": self.provider_name,
                "ip_address": ip,
                "country": d.get("country"),
                "country_code": d.get("countryCode"),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "postal": d.get("zip"),
                "latitude": float(d["lat"]) if d.get("lat") is not None else None,
                "longitude": float(d["lon"]) if d.get("lon") is not None else None,
                "timezone": d.get("timezone"),
                "isp": isp,
                "org": org,
                "asn": asn,
                **routing,
            }
        except Exception as e:
            logger.warning("geo_ipapi_error", ip=ip, error=str(e))
            return {"error": str(e), "provider": self.provider_name}


class IPInfoAdapter(GeoProvider):
    """Tertiary fallback provider using ipinfo.io."""
    BASE_URL = "https://ipinfo.io"

    @property
    def provider_name(self) -> str:
        return "ipinfo.io"

    async def geolocate(self, ip: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f"{self.BASE_URL}/{ip}/json")
                resp.raise_for_status()
                d = resp.json()

            loc = d.get("loc", "")
            lat, lon = None, None
            if loc and "," in loc:
                try:
                    parts = loc.split(",")
                    lat, lon = float(parts[0]), float(parts[1])
                except (ValueError, IndexError):
                    lat, lon = None, None

            org = d.get("org")
            routing = classify_network_routing(
                isp=org,
                org=org,
                asn_str=org,
                is_proxy_hint=False,
                is_hosting_hint=False,
            )

            return {
                "provider": self.provider_name,
                "ip_address": ip,
                "country": d.get("country"),
                "country_code": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "postal": d.get("postal"),
                "latitude": lat,
                "longitude": lon,
                "timezone": d.get("timezone"),
                "isp": org,
                "org": org,
                "asn": org,
                **routing,
            }
        except Exception as e:
            logger.warning("geo_ipinfo_error", ip=ip, error=str(e))
            return {"error": str(e), "provider": self.provider_name}


class MaxMindAdapter(GeoProvider):
    """
    Authoritative Offline MaxMind GeoIP2 City & ASN adapter.
    Reads from local .mmdb files specified by MAXMIND_DB_PATH and MAXMIND_ASN_DB_PATH.
    """

    @property
    def provider_name(self) -> str:
        return "maxmind_geoip2"

    async def geolocate(self, ip: str) -> dict[str, Any]:
        db_path = settings.MAXMIND_CITY_DB_PATH or settings.MAXMIND_DB_PATH
        if not db_path:
            # Check default locations if not explicitly configured in env
            for default_loc in ["./data/GeoLite2-City.mmdb", "./data/GeoIP2-City.mmdb", "/app/data/GeoLite2-City.mmdb", "/app/data/GeoIP2-City.mmdb"]:
                if os.path.exists(default_loc):
                    db_path = default_loc
                    break


        if not db_path or not os.path.exists(db_path):
            return {
                "error": "MaxMind GeoIP2 database file not found or unconfigured",
                "provider": self.provider_name,
            }

        try:
            import geoip2.database
            from geoip2.errors import AddressNotFoundError

            with geoip2.database.Reader(db_path) as city_reader:
                try:
                    city_resp = city_reader.city(ip)
                except AddressNotFoundError:
                    return {
                        "error": f"Address {ip} not found in MaxMind database",
                        "provider": self.provider_name,
                    }

            country_name = city_resp.country.name
            country_code = city_resp.country.iso_code
            region_name = city_resp.subdivisions.most_specific.name if city_resp.subdivisions else None
            city_name = city_resp.city.name
            postal_code = city_resp.postal.code
            lat = float(city_resp.location.latitude) if city_resp.location.latitude is not None else None
            lon = float(city_resp.location.longitude) if city_resp.location.longitude is not None else None
            acc_radius = city_resp.location.accuracy_radius
            tz = city_resp.location.time_zone
            continent = city_resp.continent.name if city_resp.continent else None
            network_str = str(city_resp.traits.network) if hasattr(city_resp.traits, "network") and city_resp.traits.network else None

            # Extract trait flags safely
            is_proxy = bool(getattr(city_resp.traits, "is_anonymous_proxy", False) or getattr(city_resp.traits, "is_public_proxy", False))
            is_tor = bool(getattr(city_resp.traits, "is_tor_exit_node", False))
            is_hosting = bool(getattr(city_resp.traits, "is_hosting_provider", False))
            is_vpn = bool(getattr(city_resp.traits, "is_anonymous_vpn", False))
            isp = getattr(city_resp.traits, "isp", None)
            org = getattr(city_resp.traits, "organization", None)
            asn_num = getattr(city_resp.traits, "autonomous_system_number", None)
            asn = f"AS{asn_num}" if asn_num else None

            # Optional ASN database lookup if traits did not include ASN
            asn_db_path = settings.MAXMIND_ASN_DB_PATH
            if not asn and asn_db_path and os.path.exists(asn_db_path):
                try:
                    with geoip2.database.Reader(asn_db_path) as asn_reader:
                        asn_resp = asn_reader.asn(ip)
                        if asn_resp.autonomous_system_number:
                            asn = f"AS{asn_resp.autonomous_system_number}"
                        if not org and asn_resp.autonomous_system_organization:
                            org = asn_resp.autonomous_system_organization
                        if not isp and asn_resp.autonomous_system_organization:
                            isp = asn_resp.autonomous_system_organization
                except Exception as e:
                    logger.debug("maxmind_asn_lookup_error", ip=ip, error=str(e))

            routing = classify_network_routing(
                isp=isp,
                org=org,
                asn_str=asn,
                is_proxy_hint=is_proxy,
                is_hosting_hint=is_hosting,
            )

            return {
                "provider": self.provider_name,
                "ip_address": ip,
                "country": country_name,
                "country_code": country_code,
                "region": region_name,
                "city": city_name,
                "postal": postal_code,
                "latitude": lat,
                "longitude": lon,
                "accuracy_radius": acc_radius,
                "timezone": tz,
                "continent": continent,
                "network": network_str,
                "isp": isp,
                "org": org,
                "asn": asn,
                "location_status": "RESOLVED",
                "location_confidence": "HIGH_CONFIDENCE",
                **routing,
            }
        except Exception as e:
            logger.warning("geo_maxmind_error", ip=ip, error=str(e))
            return {"error": str(e), "provider": self.provider_name}


class GeoService:
    """
    Primary MaxMind GeoIP2 service with multi-provider fallback & comparison.
    MaxMind GeoIP2 acts as the authoritative primary source.
    Online providers (IPWho, ip-api, ipinfo) provide secondary telemetry, verification, and comparison.
    """

    def __init__(self) -> None:
        self._primary_provider: GeoProvider = MaxMindAdapter()
        self._fallback_providers: list[GeoProvider] = [
            IPWhoisAdapter(),
            IPApiAdapter(),
            IPInfoAdapter(),
        ]

    async def geolocate(self, ip: str, include_comparison: bool = True) -> dict[str, Any]:
        """Geolocate an IP address using MaxMind GeoIP2 as primary, with resilient fallback."""
        clean_ip = self._normalize_ip(ip)

        # 1. Intercept private/loopback/link-local/multicast/reserved addresses
        if self._is_private(clean_ip):
            return {
                "ip_address": clean_ip,
                "note": "Private RFC 1918 / Loopback address — local routing",
                "provider": "internal",
                "country": "Local / Internal Network",
                "country_code": "LAN",
                "region": "Internal Subnet",
                "city": None,
                "postal": None,
                "latitude": None,
                "longitude": None,
                "accuracy_radius": None,
                "timezone": None,
                "continent": None,
                "network": clean_ip,
                "isp": None,
                "org": None,
                "asn": None,
                "is_proxy": False,
                "is_vpn": False,
                "is_tor": False,
                "is_hosting": False,
                "routing_type": "INTERNAL_LAN",
                "routing_label": "Internal / Private Network (RFC 1918)",
                "location_status": "NOT_PUBLICLY_GEOLOCATABLE",
                "location_confidence": "HIGH_CONFIDENCE",
                "provider_comparison": None,
            }

        # 2. Try Authoritative Primary Source: MaxMind GeoIP2
        primary_result = await self._primary_provider.geolocate(clean_ip)
        if "error" not in primary_result and primary_result.get("country"):
            # MaxMind resolved successfully
            comparison_list = []
            if include_comparison:
                # Run secondary query for telemetry comparison
                try:
                    sec = await self._fallback_providers[0].geolocate(clean_ip)
                    if "error" not in sec:
                        comparison_list.append({
                            "provider": sec.get("provider", "secondary"),
                            "country": sec.get("country"),
                            "region": sec.get("region"),
                            "city": sec.get("city"),
                            "latitude": sec.get("latitude"),
                            "longitude": sec.get("longitude"),
                            "asn": sec.get("asn"),
                            "isp": sec.get("isp"),
                            "status": "AGREED" if sec.get("country") == primary_result.get("country") else "DISAGREED",
                        })
                        if sec.get("country") and primary_result.get("country") and sec.get("country") != primary_result.get("country"):
                            primary_result["location_confidence"] = "PROVIDER_DISAGREEMENT"
                except Exception as e:
                    logger.debug("geo_comparison_query_failed", ip=clean_ip, error=str(e))

            primary_result["provider_comparison"] = comparison_list if comparison_list else None
            return primary_result

        logger.info("geo_maxmind_primary_unavailable", error=primary_result.get("error"), trying="fallback_providers")

        # 3. Fallback to secondary online providers in sequence
        for provider in self._fallback_providers:
            result = await provider.geolocate(clean_ip)
            if "error" not in result and result.get("country"):
                result["location_status"] = "RESOLVED"
                result["location_confidence"] = "HIGH_CONFIDENCE"
                return result
            logger.info("geo_trying_next_provider", current=provider.provider_name, error=result.get("error"))

        # 4. All providers failed or unconfigured
        return {
            "ip_address": clean_ip,
            "error": "All geolocation providers unavailable",
            "provider": "none",
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "postal": None,
            "latitude": None,
            "longitude": None,
            "accuracy_radius": None,
            "timezone": None,
            "continent": None,
            "network": None,
            "isp": None,
            "org": None,
            "asn": None,
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_hosting": False,
            "routing_type": "UNKNOWN",
            "routing_label": "Routing Telemetry Unavailable",
            "location_status": "UNAVAILABLE",
            "location_confidence": "UNAVAILABLE",
            "provider_comparison": None,
        }

    @staticmethod
    def _normalize_ip(ip: str) -> str:
        clean = ip.strip()
        parts = clean.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            try:
                return ".".join(str(int(p)) for p in parts)
            except ValueError:
                pass
        return clean

    @classmethod
    def _is_private(cls, ip: str) -> bool:
        import ipaddress
        normalized = cls._normalize_ip(ip)
        try:
            addr = ipaddress.ip_address(normalized)
            if isinstance(addr, ipaddress.IPv4Address):
                if (
                    addr in ipaddress.ip_network("192.0.2.0/24")
                    or addr in ipaddress.ip_network("198.51.100.0/24")
                    or addr in ipaddress.ip_network("203.0.113.0/24")
                ):
                    return False
            return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_reserved
        except ValueError:
            return False

