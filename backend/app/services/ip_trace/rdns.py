"""
SentinelTrace Backend — Asynchronous Reverse DNS Resolver
"""
from __future__ import annotations

import asyncio
import socket
from typing import Any

from app.core.logging import get_logger

logger = get_logger("sentineltrace.ip_trace.rdns")


async def resolve_reverse_dns(ip: str, timeout_seconds: float = 3.0) -> dict[str, Any]:
    """
    Perform a non-blocking asynchronous reverse DNS (PTR) lookup for an IP address.

    Returns:
        dict with keys:
            - reverse_dns: hostname or None
            - status: "RESOLVED" | "NO_PTR_RECORD" | "TIMEOUT" | "ERROR"
            - error: error message if any
    """
    clean_ip = ip.strip()

    loop = asyncio.get_running_loop()
    try:
        # Run socket.getnameinfo in thread pool with strict timeout
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getnameinfo, (clean_ip, 0), 0),
            timeout=timeout_seconds,
        )
        hostname, _ = result
        if hostname and hostname != clean_ip:
            return {
                "reverse_dns": hostname,
                "status": "RESOLVED",
                "error": None,
            }
        return {
            "reverse_dns": None,
            "status": "NO_PTR_RECORD",
            "error": None,
        }
    except TimeoutError:
        logger.debug("rdns_timeout", ip=clean_ip)
        return {
            "reverse_dns": None,
            "status": "TIMEOUT",
            "error": f"Reverse DNS lookup timed out after {timeout_seconds}s",
        }
    except socket.herror as he:
        return {
            "reverse_dns": None,
            "status": "NO_PTR_RECORD",
            "error": str(he),
        }
    except Exception as e:
        logger.debug("rdns_error", ip=clean_ip, error=str(e))
        return {
            "reverse_dns": None,
            "status": "ERROR",
            "error": str(e),
        }
