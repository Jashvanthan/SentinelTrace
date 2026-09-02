"""
SentinelTrace Backend — IP Geolocation Service

Abstract interface with adapters:
- ip-api.com (free tier with rate limits)
- MaxMind GeoLite2 (offline, higher accuracy)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("sentineltrace.geo")


class GeoProvider(ABC):
    @abstractmethod
    async def geolocate(self, ip: str) -> dict[str, Any]: ...

    @property
    @abstractmethod
    def provider_name(self) -> str: ...


class IPApiAdapter(GeoProvider):
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

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.BASE_URL}/{ip}", params=params)
                resp.raise_for_status()
                d = resp.json()

            if d.get("status") == "fail":
                return {"error": d.get("message", "ip-api query failed"), "provider": self.provider_name}

            return {
                "provider": self.provider_name,
                "ip_address": ip,
                "country": d.get("country"),
                "country_code": d.get("countryCode"),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "postal": d.get("zip"),
                "latitude": d.get("lat"),
                "longitude": d.get("lon"),
                "timezone": d.get("timezone"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "asn": d.get("as"),
                "is_proxy": d.get("proxy", False),
                "is_vpn": d.get("proxy", False),
                "is_tor": False,  # ip-api doesn't distinguish TOR
                "is_hosting": d.get("hosting", False),
            }
        except Exception as e:
            logger.error("geo_ipapi_error", ip=ip, error=str(e))
            return {"error": str(e), "provider": self.provider_name}


class MaxMindAdapter(GeoProvider):
    """Offline MaxMind GeoLite2 adapter. Requires a local .mmdb database file."""

    @property
    def provider_name(self) -> str:
        return "maxmind"

    async def geolocate(self, ip: str) -> dict[str, Any]:
        if not settings.MAXMIND_DB_PATH:
            return {"error": "MaxMind DB path not configured", "provider": self.provider_name}
        try:
            import geoip2.database  # type: ignore
            with geoip2.database.Reader(settings.MAXMIND_DB_PATH) as reader:
                response = reader.city(ip)
                return {
                    "provider": self.provider_name,
                    "ip_address": ip,
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                    "city": response.city.name,
                    "postal": response.postal.code,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "timezone": response.location.time_zone,
                    "isp": None,
                    "org": None,
                    "asn": None,
                    "is_proxy": False,
                    "is_vpn": False,
                    "is_tor": False,
                }
        except Exception as e:
            logger.error("geo_maxmind_error", ip=ip, error=str(e))
            return {"error": str(e), "provider": self.provider_name}


class GeoService:
    """Geolocation service that tries providers in order."""

    def __init__(self) -> None:
        self._providers: list[GeoProvider] = [IPApiAdapter(), MaxMindAdapter()]

    async def geolocate(self, ip: str) -> dict[str, Any]:
        """Geolocate an IP address using the first available provider."""
        # Skip private/loopback addresses
        if self._is_private(ip):
            return {
                "ip_address": ip,
                "note": "Private/loopback IP address",
                "provider": "none",
                "latitude": None,
                "longitude": None,
            }

        for provider in self._providers:
            result = await provider.geolocate(ip)
            if "error" not in result:
                return result
            logger.warning("geo_provider_failed", provider=provider.provider_name, error=result.get("error"))

        return {"ip_address": ip, "error": "All geolocation providers failed", "provider": "none"}

    @staticmethod
    def _is_private(ip: str) -> bool:
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False
