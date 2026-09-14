"""
SentinelTrace Backend — Unified IP Network Trace & Forensic Hop Chain Service
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import re
from typing import Any
import uuid

from app.core.logging import get_logger
from app.models.email_analysis import EmailAnalysis
from app.services.ip_trace.asn import ASNService
from app.services.ip_trace.cache import (
    DEFAULT_CACHE_TTL_SECONDS,
    get_cached_trace,
    set_cached_trace,
)
from app.services.ip_trace.classifier import (
    IPClassification,
    NormalizedIPInfo,
    classify_ip,
    normalize_ip_string,
)
from app.services.ip_trace.geoip import GeoIPService
from app.services.ip_trace.internal_telemetry import get_internal_telemetry
from app.services.ip_trace.rdap import query_rdap
from app.services.ip_trace.rdns import resolve_reverse_dns
from app.services.ip_trace.threat_intel import ThreatIntelTraceService

logger = get_logger("sentineltrace.ip_trace.service")

# Regex pattern for IPv4 and IPv6 extraction
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)


class IPTraceService:
    """Master orchestrator for single-IP and multi-hop email forensic tracing."""

    def __init__(self) -> None:
        self.geoip_service = GeoIPService()
        self.asn_service = ASNService()
        self.threat_service = ThreatIntelTraceService()

    async def trace_ip(
        self,
        ip: str,
        workspace_id: uuid.UUID | str | None = None,
        user_id: uuid.UUID | str | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Trace a single IP address with full classification, evidence ledger,
        and privacy-aware branch execution.
        """
        clean_ip = normalize_ip_string(ip)
        now_iso = datetime.now(UTC).isoformat()
        info = classify_ip(clean_ip)

        # Cache key with workspace isolation for private network data
        cache_key = f"pub:{clean_ip}" if info.is_public else f"priv:{workspace_id or 'none'}:{clean_ip}"

        # Check Cache
        if use_cache:
            cached = get_cached_trace(cache_key)
            if cached:
                return cached

        evidence_ledger: list[dict[str, Any]] = [
            {
                "source_type": "CLASSIFIER",
                "source": "SentinelTrace IP Classifier",
                "timestamp": now_iso,
                "value": f"{info.ip} -> {info.classification.value} (IPv{info.version})",
                "confidence": "HIGH",
            }
        ]

        if not info.is_public:
            # ── Private / LAN Path ───────────────────────────────────────────
            internal_telemetry = await get_internal_telemetry(workspace_id, info.ip)
            rdns_res = await resolve_reverse_dns(info.ip)

            if rdns_res.get("reverse_dns"):
                evidence_ledger.append({
                    "source_type": "REVERSE_DNS",
                    "source": "Local DNS Resolver",
                    "timestamp": now_iso,
                    "value": f"{info.ip} -> PTR {rdns_res['reverse_dns']}",
                    "confidence": "HIGH",
                })

            for src in internal_telemetry.get("sources", []):
                evidence_ledger.append({
                    "source_type": src,
                    "source": "Enterprise Network Inventory",
                    "timestamp": now_iso,
                    "value": f"Verified MAC: {internal_telemetry.get('mac')} | VLAN: {internal_telemetry.get('vlan')}",
                    "confidence": internal_telemetry.get("location_confidence", "HIGH"),
                })

            result = {
                "ip": info.ip,
                "version": info.version,
                "classification": info.classification.value,
                "is_public": False,
                "is_private": True,
                "is_geolocatable": False,
                "routing_role": info.routing_role,
                "geo": None,
                "network": {
                    "asn": None,
                    "organization": "Internal Network",
                    "isp": "Local Private Subnet",
                    "routing_type": "INTERNAL_LAN",
                    "routing_label": info.routing_role,
                },
                "dns": {
                    "reverse_dns": rdns_res.get("reverse_dns"),
                    "status": rdns_res.get("status"),
                },
                "threat": {
                    "score": 0,
                    "status": "NOT_APPLICABLE",
                    "is_malicious": False,
                },
                "internal_network": {
                    "mac": internal_telemetry.get("mac"),
                    "hostname": internal_telemetry.get("hostname") or rdns_res.get("reverse_dns"),
                    "vlan": internal_telemetry.get("vlan"),
                    "switch": internal_telemetry.get("switch"),
                    "port": internal_telemetry.get("port"),
                    "access_point": internal_telemetry.get("access_point"),
                    "ssid": internal_telemetry.get("ssid"),
                    "physical_location": internal_telemetry.get("physical_location"),
                    "location_confidence": internal_telemetry.get("location_confidence", "UNKNOWN"),
                    "reason": internal_telemetry.get("reason"),
                },
                "status": internal_telemetry.get("status", "unavailable"),
                "location_accuracy": info.location_accuracy,
                "retrieved_at": now_iso,
                "evidence": evidence_ledger,
            }
            if use_cache:
                set_cached_trace(cache_key, result, ttl_seconds=600)
            return result


        # ── Public IP Path (Concurrent enrichment) ───────────────────────────
        geo_task = self.geoip_service.get_geoip(info.ip)
        asn_task = self.asn_service.get_asn(info.ip)
        rdap_task = query_rdap(info.ip)
        rdns_task = resolve_reverse_dns(info.ip)
        threat_task = self.threat_service.get_threat_intel(info.ip)

        geo_res, asn_res, rdap_res, rdns_res, threat_res = await asyncio.gather(
            geo_task, asn_task, rdap_task, rdns_task, threat_task, return_exceptions=True
        )

        # Fallback safe dicts
        geo = geo_res if isinstance(geo_res, dict) else {"country": None, "latitude": None, "longitude": None, "accuracy": "unknown"}
        asn = asn_res if isinstance(asn_res, dict) else {"asn": None, "organization": None, "isp": None}
        rdap = rdap_res if isinstance(rdap_res, dict) else {"network_name": None, "cidr": None}
        rdns = rdns_res if isinstance(rdns_res, dict) else {"reverse_dns": None, "status": "ERROR"}
        threat = threat_res if isinstance(threat_res, dict) else {"threat_score": 0, "status": "UNAVAILABLE", "is_malicious": False}

        if geo.get("country"):
            evidence_ledger.append({
                "source_type": "GEOIP",
                "source": geo.get("provider", "MaxMind GeoIP2"),
                "timestamp": now_iso,
                "value": f"{info.ip} -> {geo.get('city') or ''} {geo.get('country')} (Lat: {geo.get('latitude')}, Lon: {geo.get('longitude')})",
                "confidence": "MEDIUM" if geo.get("latitude") else "LOW",
            })

        if asn.get("asn") or asn.get("organization") or rdap.get("network_name"):
            net_name = rdap.get("network_name") or asn.get("organization") or asn.get("isp")
            evidence_ledger.append({
                "source_type": "ASN",
                "source": "Autonomous System Registry (BGP/RDAP)",
                "timestamp": now_iso,
                "value": f"{info.ip} -> {asn.get('asn') or 'AS-Direct'} ({net_name})",
                "confidence": "HIGH",
            })

        if rdns.get("reverse_dns"):
            evidence_ledger.append({
                "source_type": "REVERSE_DNS",
                "source": "DNS PTR Query",
                "timestamp": now_iso,
                "value": f"{info.ip} -> PTR {rdns['reverse_dns']}",
                "confidence": "HIGH",
            })

        if threat.get("evidence_items"):
            for item in threat["evidence_items"]:
                evidence_ledger.append(item)
        elif threat.get("virustotal") or threat.get("abuseipdb") or threat.get("shodan"):
            evidence_ledger.append({
                "source_type": "THREAT_INTEL",
                "source": "Multi-Provider Threat Intelligence",
                "timestamp": now_iso,
                "value": f"Threat Score: {threat.get('threat_score')}/100 ({threat.get('status')})",
                "confidence": "HIGH",
            })

        result = {
            "ip": info.ip,
            "version": info.version,
            "classification": info.classification.value,
            "is_public": True,
            "is_private": False,
            "is_geolocatable": True,
            "routing_role": asn.get("routing_label") or info.routing_role,
            "geo": {
                "country": geo.get("country"),
                "country_code": geo.get("country_code"),
                "region": geo.get("region"),
                "city": geo.get("city"),
                "postal": geo.get("postal"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "accuracy": "approximate" if geo.get("latitude") else "unknown",
                "accuracy_radius": geo.get("accuracy_radius"),
                "timezone": geo.get("timezone"),
                "continent": geo.get("continent"),
                "provider": geo.get("provider"),
            },
            "network": {
                "asn": asn.get("asn"),
                "organization": asn.get("organization") or rdap.get("network_name"),
                "isp": asn.get("isp") or rdap.get("network_name"),
                "cidr": rdap.get("cidr"),
                "routing_type": asn.get("routing_type", "DIRECT_ENTERPRISE"),
                "routing_label": asn.get("routing_label", "Direct Public Routing"),
                "is_hosting": asn.get("is_hosting", False),
                "is_vpn": asn.get("is_vpn", False),
                "is_tor": asn.get("is_tor", False),
                "is_proxy": asn.get("is_proxy", False),
            },
            "dns": {
                "reverse_dns": rdns.get("reverse_dns"),
                "status": rdns.get("status"),
            },
            "threat": {
                "score": threat.get("threat_score", 0),
                "severity": threat.get("severity", "CLEAN"),
                "status": threat.get("status", "CLEAN"),
                "is_malicious": threat.get("is_malicious", False),
                "provider_coverage": threat.get("provider_coverage"),
                "score_explanation": threat.get("score_explanation", []),
                "provider_disagreement_detected": threat.get("provider_disagreement_detected", False),
                "disagreement_details": threat.get("disagreement_details"),
                "virustotal": threat.get("virustotal"),
                "abuseipdb": threat.get("abuseipdb"),
                "shodan": threat.get("shodan"),
            },
            "internal_network": None,
            "status": "RESOLVED" if geo.get("country") else "PARTIAL",
            "location_accuracy": "approximate",
            "retrieved_at": now_iso,
            "evidence": evidence_ledger,
        }


        if use_cache:
            set_cached_trace(cache_key, result, ttl_seconds=DEFAULT_CACHE_TTL_SECONDS)

        return result


    async def trace_email_analysis(
        self,
        analysis: EmailAnalysis,
        workspace_id: uuid.UUID | str | None = None,
        user_id: uuid.UUID | str | None = None,
    ) -> dict[str, Any]:
        """
        Construct a complete forensic trace graph from an email's Received transit
        chain, origin headers, and authentication telemetry.
        """
        ws_id = workspace_id or getattr(analysis, "workspace_id", None)
        received_raw: list[str] = list(getattr(analysis, "received_headers", []) or [])
        all_headers: dict[str, str] = dict(getattr(analysis, "all_headers", {}) or {})
        auth_results: dict[str, Any] = dict(getattr(analysis, "authentication_results", {}) or {})

        # Parse hops in chronological sequence (Earliest submission MTA at Hop 1 -> Latest recipient MTA)
        chronological_received = list(reversed(received_raw)) if received_raw else []

        hop_records: list[dict[str, Any]] = []

        # 1. Inspect Origin Custom Headers for Client Workstation IP (e.g. X-Originating-IP)
        origin_ip = None
        origin_header_name = None
        for h_name in ("x-originating-ip", "x-sender-ip", "x-client-ip", "x-forwarded-for"):
            val = all_headers.get(h_name) or all_headers.get(h_name.title())
            if val:
                match = IP_PATTERN.search(val) or IPV6_PATTERN.search(val)
                if match:
                    origin_ip = match.group(0)
                    origin_header_name = h_name
                    break

        if origin_ip:
            norm_orig = normalize_ip_string(origin_ip)
            hop_records.append({
                "raw_header": f"{origin_header_name}: [{norm_orig}]",
                "extracted_ip": norm_orig,
                "header_name": origin_header_name,
                "hop_position": 0,
                "trust_level": "UNTRUSTED",
                "trust_reason": "Client-supplied/custom header; cannot independently establish origin without MTA cryptographic signature.",
                "role": "Earliest Observed Hop (Custom Origin Header)",
            })

        # 2. Extract IPs from chronological Received hops
        for idx, rec in enumerate(chronological_received):
            hop_ips = IP_PATTERN.findall(rec) + IPV6_PATTERN.findall(rec)
            cleaned_hop_ips = [normalize_ip_string(h) for h in hop_ips]

            # Determine hop trust level based on position and auth
            is_first_hop = (idx == 0 and not origin_ip)
            is_last_hop = (idx == len(chronological_received) - 1)

            if is_last_hop:
                trust = "TRUSTED"
                trust_reason = "Final recipient gateway under corporate/destination domain control."
            elif is_first_hop:
                trust = "PARTIALLY_TRUSTED"
                trust_reason = "Initial submission MTA recorded in received chain."
            else:
                trust = "PARTIALLY_TRUSTED"
                trust_reason = "Intermediate relay in transit sequence."

            # Extract hostname if present
            host_match = re.search(r"from\s+([a-zA-Z0-9.-]+)", rec, re.IGNORECASE)
            by_match = re.search(r"by\s+([a-zA-Z0-9.-]+)", rec, re.IGNORECASE)
            timestamp_match = re.search(r";\s*([A-Za-z0-9,:\s+-]+)$", rec)

            extracted_host = host_match.group(1) if host_match else None
            by_host = by_match.group(1) if by_match else None
            hop_time = timestamp_match.group(1).strip() if timestamp_match else None

            if cleaned_hop_ips:
                for hip in cleaned_hop_ips:
                    hop_records.append({
                        "raw_header": rec,
                        "extracted_ip": hip,
                        "header_name": "Received",
                        "hop_position": idx + 1,
                        "trust_level": trust,
                        "trust_reason": trust_reason,
                        "role": "Transit Relay",
                        "hostname": extracted_host,
                        "by_host": by_host,
                        "timestamp": hop_time,
                    })
            elif extracted_host:
                hop_records.append({
                    "raw_header": rec,
                    "extracted_ip": None,
                    "header_name": "Received",
                    "hop_position": idx + 1,
                    "trust_level": trust,
                    "trust_reason": trust_reason,
                    "role": "Transit Relay",
                    "hostname": extracted_host,
                    "by_host": by_host,
                    "timestamp": hop_time,
                })

        # Trace all extracted unique IPs concurrently
        unique_ips = list(dict.fromkeys([h["extracted_ip"] for h in hop_records if h.get("extracted_ip")]))
        ip_trace_results: dict[str, dict[str, Any]] = {}

        if unique_ips:
            trace_coros = [self.trace_ip(ip, workspace_id=ws_id, user_id=user_id, use_cache=True) for ip in unique_ips]
            trace_outputs = await asyncio.gather(*trace_coros, return_exceptions=True)
            for ip, res in zip(unique_ips, trace_outputs, strict=False):
                if isinstance(res, dict):
                    ip_trace_results[ip] = res

        # Build enriched hop chain with NAT boundary detection
        hops: list[dict[str, Any]] = []
        timeline: list[dict[str, Any]] = []
        public_locations: list[dict[str, Any]] = []
        private_network_nodes: list[dict[str, Any]] = []
        boundaries: list[dict[str, Any]] = []
        evidence_ledger: list[dict[str, Any]] = []

        seen_private = False
        nat_boundary_detected = False

        for i, h in enumerate(hop_records):
            hop_num = i + 1
            ip = h.get("extracted_ip")
            trace = ip_trace_results.get(ip) if ip else None

            classification_val = trace.get("classification") if trace else "UNKNOWN"
            is_priv = trace.get("is_private") if trace else (True if not ip else False)
            is_pub = trace.get("is_public") if trace else False

            # Assign accurate network role based on transit sequence
            if is_priv:
                seen_private = True
                if hop_num == 1 or "Origin" in h.get("role", ""):
                    role = "Earliest Observed Hop (Private LAN)"
                else:
                    role = "Internal Mail Relay"
            elif is_pub:
                if seen_private and not nat_boundary_detected:
                    nat_boundary_detected = True
                    role = "NAT / Perimeter Egress Boundary"
                    boundaries.append({
                        "boundary_type": "NAT_EGRESS_BOUNDARY",
                        "label": "NAT / Egress Boundary",
                        "from_hop": hop_num - 1,
                        "to_hop": hop_num,
                        "ip": ip,
                        "description": "Perimeter network boundary: transition from internal private subnet to public WAN egress address",
                    })
                elif hop_num == len(hop_records):
                    role = "Recipient Mail Ingress (Destination)"
                else:
                    role = "Public Transit MTA"
            else:
                role = h.get("role", "Transit Relay")

            geo = trace.get("geo") if trace else None
            has_coords = geo and geo.get("latitude") is not None and geo.get("longitude") is not None

            if has_coords:
                public_locations.append({
                    "hop_number": hop_num,
                    "ip": ip,
                    "latitude": geo["latitude"],
                    "longitude": geo["longitude"],
                    "city": geo.get("city"),
                    "country": geo.get("country"),
                    "country_code": geo.get("country_code"),
                    "asn": trace.get("network", {}).get("asn"),
                    "isp": trace.get("network", {}).get("isp"),
                    "threat_score": trace.get("threat", {}).get("score", 0),
                    "threat_status": trace.get("threat", {}).get("status", "CLEAN"),
                    "role": role,
                })
            elif is_priv and ip:
                internal_data = trace.get("internal_network") if trace else {}
                private_network_nodes.append({
                    "hop_number": hop_num,
                    "ip": ip,
                    "classification": classification_val,
                    "hostname": h.get("hostname") or (internal_data.get("hostname") if internal_data else None),
                    "mac": internal_data.get("mac") if internal_data else None,
                    "vlan": internal_data.get("vlan") if internal_data else None,
                    "switch": internal_data.get("switch") if internal_data else None,
                    "port": internal_data.get("port") if internal_data else None,
                    "access_point": internal_data.get("access_point") if internal_data else None,
                    "physical_location": internal_data.get("physical_location") if internal_data else None,
                    "role": role,
                    "status": trace.get("status") if trace else "unavailable",
                })

            hop_node = {
                "hop_number": hop_num,
                "ip": ip,
                "classification": classification_val,
                "is_public": is_pub,
                "is_private": is_priv,
                "network_role": role,
                "trust_level": h.get("trust_level", "UNKNOWN"),
                "trust_reason": h.get("trust_reason"),
                "hostname": h.get("hostname") or (trace.get("dns", {}).get("reverse_dns") if trace else None),
                "by_host": h.get("by_host"),
                "timestamp": h.get("timestamp"),
                "header_name": h.get("header_name"),
                "raw_header": h.get("raw_header"),
                "trace_details": trace,
            }
            hops.append(hop_node)

            timeline.append({
                "step": hop_num,
                "timestamp": h.get("timestamp") or f"Transit Hop #{hop_num}",
                "ip": ip or "Hostname Relay",
                "classification": classification_val,
                "role": role,
                "hostname": hop_node["hostname"],
                "trust_level": h.get("trust_level", "UNKNOWN"),
                "header_source": h.get("header_name"),
                "geo_summary": f"{geo.get('city')}, {geo.get('country')}" if (geo and geo.get("country")) else ("Internal LAN" if is_priv else "No GeoIP"),
            })

            if trace and trace.get("evidence"):
                for ev in trace["evidence"]:
                    evidence_ledger.append({
                        **ev,
                        "hop_number": hop_num,
                    })

        # Append email header evidence
        if auth_results.get("spf"):
            evidence_ledger.append({
                "source_type": "EMAIL_HEADER",
                "source": "Authentication-Results / SPF",
                "timestamp": datetime.now(UTC).isoformat(),
                "value": f"SPF Result: {auth_results['spf']}",
                "confidence": "HIGH",
            })
        if auth_results.get("dkim"):
            evidence_ledger.append({
                "source_type": "EMAIL_HEADER",
                "source": "Authentication-Results / DKIM",
                "timestamp": datetime.now(UTC).isoformat(),
                "value": f"DKIM Result: {auth_results['dkim']}",
                "confidence": "HIGH",
            })

        return {
            "analysis_id": str(getattr(analysis, "id", "")),
            "total_hops": len(hops),
            "hops": hops,
            "timeline": timeline,
            "public_locations": public_locations,
            "private_network_nodes": private_network_nodes,
            "boundaries": boundaries,
            "has_nat_boundary": nat_boundary_detected,
            "evidence": evidence_ledger,
        }
