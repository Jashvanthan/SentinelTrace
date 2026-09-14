"""
SentinelTrace Backend — Public GeoIP Enrichment Service
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.geo_service import GeoService
from app.services.ip_trace.classifier import classify_ip

logger = get_logger("sentineltrace.ip_trace.geoip")


class GeoIPService:
    """Enriches public IPs with geographic coordinates, city, country, and timezone."""

    def __init__(self) -> None:
        self._geo_service = GeoService()

    async def get_geoip(self, ip: str) -> dict[str, Any]:
        """
        Geolocate a public IP address.
        Guarantees that private, loopback, or non-routable IPs are intercepted locally.
        """
        classification = classify_ip(ip)
        if not classification.is_geolocatable:
            return {
                "ip": classification.ip,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "accuracy": classification.location_accuracy,
                "timezone": None,
                "provider": "internal_classifier",
                "is_geolocatable": False,
                "status": "NOT_APPLICABLE",
                "reason": classification.reason,
            }

        try:
            raw_geo = await self._geo_service.geolocate(classification.ip)
            lat = raw_geo.get("latitude")
            lon = raw_geo.get("longitude")

            has_coords = lat is not None and lon is not None
            has_country = bool(raw_geo.get("country") and raw_geo.get("country") != "Unknown")

            return {
                "ip": classification.ip,
                "country": raw_geo.get("country"),
                "country_code": raw_geo.get("country_code"),
                "region": raw_geo.get("region"),
                "city": raw_geo.get("city"),
                "postal": raw_geo.get("postal"),
                "latitude": float(lat) if has_coords else None,
                "longitude": float(lon) if has_coords else None,
                "accuracy": "approximate" if has_coords else "unknown",
                "accuracy_radius": raw_geo.get("accuracy_radius"),
                "timezone": raw_geo.get("timezone"),
                "continent": raw_geo.get("continent"),
                "provider": raw_geo.get("provider", "maxmind_or_fallback"),
                "is_geolocatable": True,
                "status": "RESOLVED" if (has_coords or has_country) else "UNAVAILABLE",
                "reason": "Approximate public GeoIP location" if has_coords else "Geographic coordinates not advertised for network block",
            }
        except Exception as e:
            logger.warning("geoip_enrichment_failed", ip=ip, error=str(e))
            return {
                "ip": classification.ip,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "accuracy": "unknown",
                "timezone": None,
                "provider": "none",
                "is_geolocatable": True,
                "status": "ERROR",
                "reason": f"GeoIP lookup failed: {e}",
            }
