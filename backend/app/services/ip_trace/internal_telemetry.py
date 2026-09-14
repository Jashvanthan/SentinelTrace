"""
SentinelTrace Backend — Internal LAN & Network Telemetry Service

Provides an extensible, production-ready adapter architecture for enterprise
network inventory integrations (DHCP servers, 802.1X NAC, Managed Switches,
WLC Access Points, CMDBs, EDR telemetry).

Strict zero-fabrication contract:
If an enterprise telemetry adapter is not configured or an asset is not found,
the system honestly reports:
  internal_telemetry_status: "unavailable"
  physical_location: None
  reason: "Internal network telemetry unavailable"
  confidence: "UNKNOWN"
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
import uuid

from app.core.logging import get_logger

logger = get_logger("sentineltrace.ip_trace.internal_telemetry")


class InternalTelemetryProvider(ABC):
    """Abstract interface for enterprise network telemetry integrations."""

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @abstractmethod
    async def lookup_ip(self, ip: str, workspace_id: str | None = None) -> dict[str, Any] | None:
        """Lookup private IP in enterprise infrastructure telemetry."""
        ...


class RegistryTelemetryProvider(InternalTelemetryProvider):
    """
    In-memory / workspace inventory provider allowing authenticated workspaces
    to register verified network assets without fabricating data.
    """

    def __init__(self) -> None:
        self._inventory: dict[str, dict[str, Any]] = {}

    @property
    def provider_name(self) -> str:
        return "enterprise_registry"

    def register_asset(self, workspace_id: str, ip: str, telemetry: dict[str, Any]) -> None:
        key = f"{workspace_id}:{ip.strip()}"
        self._inventory[key] = telemetry

    async def lookup_ip(self, ip: str, workspace_id: str | None = None) -> dict[str, Any] | None:
        if not workspace_id:
            return None
        key = f"{workspace_id}:{ip.strip()}"
        return self._inventory.get(key)


class ZeroFabricationTelemetryProvider(InternalTelemetryProvider):
    """Default provider that guarantees no fake data is generated when unconfigured."""

    @property
    def provider_name(self) -> str:
        return "zero_fabrication_default"

    async def lookup_ip(self, ip: str, workspace_id: str | None = None) -> dict[str, Any] | None:
        return None


# Global active provider registry
_REGISTRY_PROVIDER = RegistryTelemetryProvider()
_ACTIVE_PROVIDERS: list[InternalTelemetryProvider] = [_REGISTRY_PROVIDER, ZeroFabricationTelemetryProvider()]


def register_internal_telemetry(workspace_id: str, ip: str, telemetry: dict[str, Any]) -> None:
    """Register verified internal network asset telemetry for a workspace."""
    _REGISTRY_PROVIDER.register_asset(workspace_id, ip, telemetry)


async def get_internal_telemetry(workspace_id: uuid.UUID | str | None, ip: str) -> dict[str, Any]:
    """
    Retrieve internal network telemetry for a private/LAN IP.
    Enforces workspace isolation and honest reporting.
    """
    clean_ip = ip.strip()
    ws_str = str(workspace_id) if workspace_id else None

    for provider in _ACTIVE_PROVIDERS:
        try:
            asset = await provider.lookup_ip(clean_ip, ws_str)
            if asset:
                return {
                    "ip": clean_ip,
                    "status": "RESOLVED",
                    "mac": asset.get("mac"),
                    "hostname": asset.get("hostname"),
                    "vlan": asset.get("vlan"),
                    "switch": asset.get("switch"),
                    "port": asset.get("port"),
                    "access_point": asset.get("access_point"),
                    "ssid": asset.get("ssid"),
                    "physical_location": asset.get("physical_location"),  # { building, floor, room }
                    "location_confidence": asset.get("location_confidence", "HIGH"),
                    "sources": asset.get("sources", [provider.provider_name.upper()]),
                    "reason": "Internal network infrastructure telemetry verified",
                }
        except Exception as e:
            logger.debug("internal_telemetry_provider_error", provider=provider.provider_name, ip=clean_ip, error=str(e))

    # Default strictly honest response: NO fabricated data
    return {
        "ip": clean_ip,
        "status": "unavailable",
        "mac": None,
        "hostname": None,
        "vlan": None,
        "switch": None,
        "port": None,
        "access_point": None,
        "ssid": None,
        "physical_location": None,
        "location_confidence": "UNKNOWN",
        "sources": [],
        "reason": "Internal network telemetry unavailable",
    }
