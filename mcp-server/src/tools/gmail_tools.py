"""
Gmail tools for MCP
"""
import os
from typing import Any
from .api import _call_backend_api

async def _call_backend_gateway(endpoint: str, workspace_id: str, connection_id: str, params: dict = None) -> dict[str, Any]:
    """Route Gmail calls through the authenticated API utility."""
    if not params:
        params = {}
    return await _call_backend_api("GET", f"/workspaces/{workspace_id}/integrations/gmail/{endpoint}", params=params)

async def gmail_list_messages(workspace_id: str, gmail_connection_id: str, max_results: int = 10) -> dict[str, Any]:
    return await _call_backend_gateway("messages", workspace_id, gmail_connection_id, {"max_results": max_results})

async def gmail_get_message(workspace_id: str, gmail_connection_id: str, message_id: str) -> dict[str, Any]:
    return await _call_backend_gateway(f"messages/{message_id}", workspace_id, gmail_connection_id)

async def gmail_get_raw_message(workspace_id: str, gmail_connection_id: str, message_id: str) -> dict[str, Any]:
    return await _call_backend_gateway(f"messages/{message_id}/raw", workspace_id, gmail_connection_id)
