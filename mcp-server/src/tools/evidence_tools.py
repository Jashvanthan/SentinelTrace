"""MCP Tool: Evidence Integrity Verification"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any


def verify_file_integrity(file_b64: str, expected_sha256: str) -> dict[str, Any]:
    """Verify file integrity by comparing SHA-256 hashes."""
    try:
        data = base64.b64decode(file_b64)
        computed = hashlib.sha256(data).hexdigest()
        match = computed.lower() == expected_sha256.lower()
        return {
            "integrity_verified": match,
            "computed_sha256": computed,
            "expected_sha256": expected_sha256.lower(),
            "size_bytes": len(data),
            "verified_at": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "integrity_verified": False}


def generate_evidence_manifest(
    analysis_id: str,
    file_hashes: list[dict],
    analyst_id: str | None = None,
) -> dict[str, Any]:
    """Generate a cryptographic evidence manifest for chain-of-custody."""
    timestamp = datetime.now(UTC).isoformat()

    # Build manifest content
    manifest_content = {
        "analysis_id": analysis_id,
        "generated_at": timestamp,
        "analyst_id": analyst_id or "system",
        "files": file_hashes,
        "protocol": "SentinelTrace Evidence Manifest v1.0",
    }

    # Hash the manifest itself for integrity
    manifest_json = json.dumps(manifest_content, sort_keys=True)
    manifest_hash = hashlib.sha256(manifest_json.encode()).hexdigest()

    return {
        "manifest": manifest_content,
        "manifest_sha256": manifest_hash,
        "chain_of_custody": [
            {
                "event": "MANIFEST_CREATED",
                "timestamp": timestamp,
                "actor": analyst_id or "system",
                "manifest_hash": manifest_hash,
            }
        ],
    }
