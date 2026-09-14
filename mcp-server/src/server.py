"""
SentinelTrace MCP Server

Exposes security analysis tools to AI agents via the Model Context Protocol.
Tools are stateless, credential-free, and return structured JSON.

Transport: stdio (can be upgraded to SSE)
"""
from __future__ import annotations

import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from tools.email_tools import (
    parse_email_headers,
    compute_file_hash,
    extract_iocs_from_text,
)
from tools.intel_tools import enrich_indicator
from tools.geo_tools import geolocate_ip
from tools.ai_tools import classify_threat_context
from tools.evidence_tools import verify_file_integrity, generate_evidence_manifest
from tools.gmail_tools import gmail_list_messages, gmail_get_message, gmail_get_raw_message
from tools.investigation_tools import (
    search_threats,
    get_email_analysis,
    search_iocs,
    get_campaign,
    search_campaigns,
    get_campaign_graph,
    get_threat_summary,
)

app = Server("sentineltrace-mcp")


# ── Tool Registry ──────────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    Tool(
        name="parse_email_headers",
        description=(
            "Parse raw email headers from an .eml file or header string. "
            "Extracts sender, recipient, subject, Received chain, SPF/DKIM/DMARC results, "
            "and authentication indicators."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "raw_headers": {
                    "type": "string",
                    "description": "Raw email header string (not full body)",
                },
            },
            "required": ["raw_headers"],
        },
    ),
    Tool(
        name="compute_file_hash",
        description="Compute SHA-256 and MD5 hashes of a file provided as base64-encoded bytes.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {
                    "type": "string",
                    "description": "Base64-encoded file bytes",
                },
                "filename": {
                    "type": "string",
                    "description": "Original filename for context",
                },
            },
            "required": ["file_b64"],
        },
    ),
    Tool(
        name="extract_iocs",
        description=(
            "Extract Indicators of Compromise (IOCs) from free-form text. "
            "Detects IP addresses, domains, URLs, email addresses, and file hashes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to extract IOCs from (e.g., email body)",
                    "maxLength": 50000,
                },
            },
            "required": ["text"],
        },
    ),
    Tool(
        name="enrich_indicator",
        description=(
            "Look up an IOC (IP, domain, URL, or file hash) against threat intelligence databases. "
            "Returns maliciousness verdict and threat score."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The indicator value to enrich",
                },
                "indicator_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "url", "hash"],
                    "description": "Type of indicator",
                },
            },
            "required": ["indicator", "indicator_type"],
        },
    ),
    Tool(
        name="geolocate_ip",
        description="Geolocate an IP address and return country, city, ISP, and coordinates.",
        inputSchema={
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IPv4 or IPv6 address",
                },
            },
            "required": ["ip_address"],
        },
    ),
    Tool(
        name="classify_threat",
        description=(
            "Classify the threat category and severity of an email based on sanitized metadata. "
            "IMPORTANT: Do not pass credentials, passwords, or API keys as input."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "subject": {"type": "string"},
                "sender_email": {"type": "string"},
                "sender_domain": {"type": "string"},
                "spf_result": {"type": "string"},
                "dkim_result": {"type": "string"},
                "dmarc_result": {"type": "string"},
                "extracted_urls": {"type": "array", "items": {"type": "string"}},
                "extracted_ips": {"type": "array", "items": {"type": "string"}},
                "body_snippet": {"type": "string", "maxLength": 2000},
            },
            "required": ["sender_email"],
        },
    ),
    Tool(
        name="verify_file_integrity",
        description=(
            "Verify the SHA-256 hash of a file against an expected hash. "
            "Returns whether the file is intact (chain-of-custody check)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {
                    "type": "string",
                    "description": "Base64-encoded file bytes",
                },
                "expected_sha256": {
                    "type": "string",
                    "description": "Expected SHA-256 hash in hex",
                },
            },
            "required": ["file_b64", "expected_sha256"],
        },
    ),
    Tool(
        name="generate_evidence_manifest",
        description=(
            "Generate a cryptographic evidence manifest (chain-of-custody record) "
            "for a set of file hashes and metadata."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "analysis_id": {"type": "string"},
                "file_hashes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "filename": {"type": "string"},
                            "sha256": {"type": "string"},
                            "size_bytes": {"type": "integer"},
                        },
                    },
                },
                "analyst_id": {"type": "string"},
            },
            "required": ["analysis_id", "file_hashes"],
        },
    ),
    Tool(
        name="system_health",
        description="Returns the health status of the MCP server and its registered tools.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="gmail_list_messages",
        description="Securely list Gmail messages for a given workspace and connection.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "gmail_connection_id": {"type": "string"},
                "max_results": {"type": "integer"}
            },
            "required": ["workspace_id", "gmail_connection_id"],
        },
    ),
    Tool(
        name="gmail_get_message",
        description="Securely get a Gmail message payload for a given workspace and connection.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "gmail_connection_id": {"type": "string"},
                "message_id": {"type": "string"}
            },
            "required": ["workspace_id", "gmail_connection_id", "message_id"],
        },
    ),
    Tool(
        name="gmail_get_raw_message",
        description="Securely get a raw MIME Gmail message for a given workspace and connection.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "gmail_connection_id": {"type": "string"},
                "message_id": {"type": "string"}
            },
            "required": ["workspace_id", "gmail_connection_id", "message_id"],
        },
    ),
    Tool(
        name="search_threats",
        description="Search threat detections within an authorized SentinelTrace workspace. Results are limited and workspace-scoped.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string", "description": "The target workspace ID"},
                "threat_category": {"type": "string", "description": "Filter by threat category (e.g. PHISHING, MALWARE)"},
                "is_malicious": {"type": "boolean", "description": "Filter by malicious status"},
                "limit": {"type": "integer", "description": "Pagination limit (max 100)"}
            },
            "required": ["workspace_id"]
        }
    ),
    Tool(
        name="get_email_analysis",
        description="Get secure email analysis details within a workspace. Returns analysis metadata, threat scores, and verdicts without exposing raw unredacted emails or credentials.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "email_id": {"type": "string"}
            },
            "required": ["workspace_id", "email_id"]
        }
    ),
    Tool(
        name="search_iocs",
        description="Search Indicators of Compromise (IOCs) within an authorized SentinelTrace workspace.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "search": {"type": "string", "description": "Search text for IOC value"},
                "ioc_type": {"type": "string", "description": "Filter by IOC type (ip, domain, url, hash)"},
                "is_malicious": {"type": "boolean", "description": "Filter by malicious status"},
                "limit": {"type": "integer", "description": "Pagination limit (max 100)"}
            },
            "required": ["workspace_id"]
        }
    ),
    Tool(
        name="search_campaigns",
        description="Search active threat campaigns within a workspace.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "status": {"type": "string", "description": "Filter by campaign status (e.g., ACTIVE, CONTAINED)"},
                "limit": {"type": "integer", "description": "Pagination limit (max 100)"}
            },
            "required": ["workspace_id"]
        }
    ),
    Tool(
        name="get_campaign",
        description="Get detailed metadata for a specific threat campaign within a workspace.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "campaign_id": {"type": "string"}
            },
            "required": ["workspace_id", "campaign_id"]
        }
    ),
    Tool(
        name="get_campaign_graph",
        description="Retrieve a bounded campaign correlation graph showing relationships between emails, senders, and IOCs.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "campaign_id": {"type": "string", "description": "Target campaign ID"},
                "analysis_id": {"type": "string", "description": "Target analysis ID (provide either campaign_id or analysis_id)"},
                "depth": {"type": "integer", "description": "Traversal depth (max 4)"}
            },
            "required": ["workspace_id"]
        }
    ),
    Tool(
        name="get_threat_summary",
        description="Get a high-level summary of workspace threat statistics and risk metrics.",
        inputSchema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"}
            },
            "required": ["workspace_id"]
        }
    ),
]


# ── Request Handlers ──────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Route tool calls to their implementations."""
    try:
        if name == "parse_email_headers":
            result = parse_email_headers(arguments["raw_headers"])
        elif name == "compute_file_hash":
            result = compute_file_hash(
                arguments["file_b64"],
                arguments.get("filename", "unknown"),
            )
        elif name == "extract_iocs":
            result = extract_iocs_from_text(arguments["text"])
        elif name == "enrich_indicator":
            result = await enrich_indicator(
                arguments["indicator"],
                arguments["indicator_type"],
            )
        elif name == "geolocate_ip":
            result = await geolocate_ip(arguments["ip_address"])
        elif name == "classify_threat":
            result = await classify_threat_context(arguments)
        elif name == "verify_file_integrity":
            result = verify_file_integrity(
                arguments["file_b64"],
                arguments["expected_sha256"],
            )
        elif name == "generate_evidence_manifest":
            result = generate_evidence_manifest(
                arguments["analysis_id"],
                arguments["file_hashes"],
                arguments.get("analyst_id"),
            )
        elif name == "gmail_list_messages":
            result = await gmail_list_messages(
                arguments["workspace_id"],
                arguments["gmail_connection_id"],
                arguments.get("max_results", 10)
            )
        elif name == "gmail_get_message":
            result = await gmail_get_message(
                arguments["workspace_id"],
                arguments["gmail_connection_id"],
                arguments["message_id"]
            )
        elif name == "gmail_get_raw_message":
            result = await gmail_get_raw_message(
                arguments["workspace_id"],
                arguments["gmail_connection_id"],
                arguments["message_id"]
            )
        elif name == "search_threats":
            result = await search_threats(
                arguments["workspace_id"],
                arguments.get("threat_category"),
                arguments.get("is_malicious"),
                arguments.get("limit", 20)
            )
        elif name == "get_email_analysis":
            result = await get_email_analysis(
                arguments["workspace_id"],
                arguments["email_id"]
            )
        elif name == "search_iocs":
            result = await search_iocs(
                arguments["workspace_id"],
                arguments.get("search"),
                arguments.get("ioc_type"),
                arguments.get("is_malicious"),
                arguments.get("limit", 20)
            )
        elif name == "search_campaigns":
            result = await search_campaigns(
                arguments["workspace_id"],
                arguments.get("status"),
                arguments.get("limit", 20)
            )
        elif name == "get_campaign":
            result = await get_campaign(
                arguments["workspace_id"],
                arguments["campaign_id"]
            )
        elif name == "get_campaign_graph":
            result = await get_campaign_graph(
                arguments["workspace_id"],
                arguments.get("campaign_id"),
                arguments.get("analysis_id"),
                arguments.get("depth", 2)
            )
        elif name == "get_threat_summary":
            result = await get_threat_summary(
                arguments["workspace_id"]
            )
        elif name == "system_health":
            result = {
                "service": "sentineltrace-mcp",
                "status": "healthy",
                "tools_registered": [t.name for t in TOOLS],
            }
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as e:
        result = {"error": str(e), "tool": name}

    return [TextContent(type="text", text=json.dumps(result, default=str, indent=2))]


# ── Entry Point ───────────────────────────────────────────────────────────────

async def main() -> None:
    async with stdio_server() as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
