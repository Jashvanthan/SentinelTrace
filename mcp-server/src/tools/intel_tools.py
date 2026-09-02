"""MCP Tool: Threat Intelligence Enrichment"""
from __future__ import annotations

import os
from typing import Any

import httpx


async def enrich_indicator(indicator: str, indicator_type: str) -> dict[str, Any]:
    """Enrich an IOC against VirusTotal and AbuseIPDB."""
    results: dict[str, Any] = {"indicator": indicator, "indicator_type": indicator_type}

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    abip_key = os.getenv("ABUSEIPDB_API_KEY", "")

    # VirusTotal
    if vt_key:
        try:
            vt_result = await _virustotal_lookup(indicator, indicator_type, vt_key)
            results["virustotal"] = vt_result
        except Exception as e:
            results["virustotal"] = {"error": str(e)}

    # AbuseIPDB (IP only)
    if abip_key and indicator_type == "ip":
        try:
            abip_result = await _abuseipdb_lookup(indicator, abip_key)
            results["abuseipdb"] = abip_result
        except Exception as e:
            results["abuseipdb"] = {"error": str(e)}

    # Compute aggregate score
    score = 0
    vt = results.get("virustotal", {})
    if "malicious_count" in vt and vt.get("total_engines", 0) > 0:
        score = int((vt["malicious_count"] / vt["total_engines"]) * 100)
    abip = results.get("abuseipdb", {})
    if "abuse_confidence_score" in abip:
        score = max(score, abip["abuse_confidence_score"])

    results["aggregate_threat_score"] = score
    results["is_malicious"] = score >= 50

    return results


async def _virustotal_lookup(indicator: str, itype: str, api_key: str) -> dict:
    path_map = {"ip": f"/ip_addresses/{indicator}", "domain": f"/domains/{indicator}",
                 "hash": f"/files/{indicator}", "url": f"/urls/{_vt_url_id(indicator)}"}
    path = path_map.get(itype, f"/ip_addresses/{indicator}")

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3{path}",
            headers={"x-apikey": api_key},
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious_count": stats.get("malicious", 0),
            "total_engines": sum(stats.values()),
            "reputation": attrs.get("reputation"),
        }


async def _abuseipdb_lookup(ip: str, api_key: str) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
        }


def _vt_url_id(url: str) -> str:
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
