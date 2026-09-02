"""MCP Tool: IP Geolocation"""
from __future__ import annotations

import os
from typing import Any

import httpx


async def geolocate_ip(ip_address: str) -> dict[str, Any]:
    """Geolocate an IP address using ip-api.com."""
    try:
        api_key = os.getenv("IPAPI_KEY", "")
        params = {
            "fields": "status,country,countryCode,region,city,lat,lon,timezone,isp,org,as,proxy",
        }
        if api_key:
            params["key"] = api_key

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip_address}", params=params)
            resp.raise_for_status()
            d = resp.json()

        if d.get("status") == "fail":
            return {"ip_address": ip_address, "error": d.get("message"), "provider": "ip-api.com"}

        return {
            "ip_address": ip_address,
            "country": d.get("country"),
            "country_code": d.get("countryCode"),
            "region": d.get("region"),
            "city": d.get("city"),
            "latitude": d.get("lat"),
            "longitude": d.get("lon"),
            "timezone": d.get("timezone"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "asn": d.get("as"),
            "is_proxy": d.get("proxy", False),
            "provider": "ip-api.com",
        }
    except Exception as e:
        return {"ip_address": ip_address, "error": str(e), "provider": "ip-api.com"}
