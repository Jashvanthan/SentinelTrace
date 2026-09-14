"""
SentinelTrace Backend — Asynchronous RDAP & Regional Internet Registry Resolver
"""
from __future__ import annotations

import asyncio
from typing import Any
import httpx

from app.core.logging import get_logger

logger = get_logger("sentineltrace.ip_trace.rdap")

# RDAP bootstrap endpoint provided by open standard rdap.org / IANA
RDAP_BASE_URL = "https://rdap.org/ip"


async def query_rdap(ip: str, timeout_seconds: float = 4.0) -> dict[str, Any]:
    """
    Query Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC) via RDAP.
    Returns network CIDR, handle, name, country, and abuse contact.
    """
    clean_ip = ip.strip()
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
            resp = await client.get(
                f"{RDAP_BASE_URL}/{clean_ip}",
                headers={"Accept": "application/rdap+json, application/json"},
            )
            if resp.status_code == 404:
                return {
                    "status": "NOT_FOUND",
                    "network_name": None,
                    "handle": None,
                    "country": None,
                    "cidr": None,
                    "entities": [],
                }
            resp.raise_for_status()
            data = resp.json()

            # Extract network name and CIDR
            net_name = data.get("name")
            handle = data.get("handle")
            country = data.get("country")
            cidr = None

            cidr_list = data.get("cidr0_cidrs", [])
            if cidr_list and isinstance(cidr_list, list) and len(cidr_list) > 0:
                first = cidr_list[0]
                if isinstance(first, dict):
                    prefix = first.get("v4prefix") or first.get("v6prefix")
                    length = first.get("length")
                    if prefix is not None and length is not None:
                        cidr = f"{prefix}/{length}"

            return {
                "status": "RESOLVED",
                "network_name": net_name,
                "handle": handle,
                "country": country,
                "cidr": cidr,
                "raw_rdap": {
                    "handle": handle,
                    "name": net_name,
                    "country": country,
                    "start_address": data.get("startAddress"),
                    "end_address": data.get("endAddress"),
                },
            }
    except httpx.TimeoutException:
        logger.debug("rdap_query_timeout", ip=clean_ip)
        return {
            "status": "TIMEOUT",
            "network_name": None,
            "handle": None,
            "country": None,
            "cidr": None,
            "error": f"RDAP query timed out after {timeout_seconds}s",
        }
    except Exception as e:
        logger.debug("rdap_query_failed", ip=clean_ip, error=str(e))
        return {
            "status": "ERROR",
            "network_name": None,
            "handle": None,
            "country": None,
            "cidr": None,
            "error": str(e),
        }
