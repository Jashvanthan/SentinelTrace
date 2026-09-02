"""
Gmail tools for MCP
"""
import httpx
import os
import json
from typing import Any

BACKEND_URL = os.environ.get("SENTINELTRACE_API_URL", "http://localhost:8000")

async def _call_backend_gateway(endpoint: str, workspace_id: str, connection_id: str, params: dict = None) -> dict[str, Any]:
    url = f"{BACKEND_URL}/api/v1/workspaces/{workspace_id}/integrations/gmail/{endpoint}"
    # Assuming internal authentication or the backend validates workspace_id and connection_id
    # Note: In a real production deployment, this would include an internal service token.
    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params, headers={"X-Internal-MCP-Request": "true"})
        if response.status_code != 200:
            return {"error": f"Backend gateway error: {response.status_code}", "detail": response.text}
        return response.json()

async def gmail_list_messages(workspace_id: str, gmail_connection_id: str, max_results: int = 10) -> dict[str, Any]:
    return await _call_backend_gateway("messages", workspace_id, gmail_connection_id, {"max_results": max_results})

async def gmail_get_message(workspace_id: str, gmail_connection_id: str, message_id: str) -> dict[str, Any]:
    return await _call_backend_gateway(f"messages/{message_id}", workspace_id, gmail_connection_id)

async def gmail_get_raw_message(workspace_id: str, gmail_connection_id: str, message_id: str) -> dict[str, Any]:
    return await _call_backend_gateway(f"messages/{message_id}/raw", workspace_id, gmail_connection_id)
