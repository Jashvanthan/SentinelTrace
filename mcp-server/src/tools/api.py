"""
Centralized API utilities for SentinelTrace MCP Tools.
Ensures that all backend calls enforce authentication and tenant isolation.
"""
import httpx
import os
import json
from typing import Any, Dict

BACKEND_URL = os.environ.get("SENTINELTRACE_API_URL", "http://localhost:8000")

def _get_auth_headers() -> Dict[str, str]:
    """Retrieve auth headers from environment.
    
    The MCP server relies on the environment to provide the credentials.
    This guarantees that the AI agent acts on behalf of the specific authenticated user.
    """
    token = os.environ.get("SENTINELTRACE_ACCESS_TOKEN")
    if not token:
        raise ValueError(
            "Authentication required: SENTINELTRACE_ACCESS_TOKEN environment variable is missing. "
            "Please configure the MCP server environment with a valid access token."
        )
    return {"Authorization": f"Bearer {token}"}

async def _call_backend_api(
    method: str,
    endpoint: str,
    params: dict = None,
    json_data: dict = None
) -> dict[str, Any]:
    """
    Make an authenticated API call to the SentinelTrace Backend.
    """
    # Ensure endpoint doesn't start with double slash if BACKEND_URL ends with one
    base = BACKEND_URL.rstrip('/')
    path = endpoint.lstrip('/')
    url = f"{base}/api/v1/{path}"
    
    headers = _get_auth_headers()
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                timeout=30.0
            )
            
            # If the backend denies access, return safe error without stack traces
            if response.status_code == 401:
                return {"error": "Unauthorized: The provided access token is invalid or expired."}
            elif response.status_code == 403:
                return {"error": "Forbidden: You do not have the necessary permissions for this workspace or resource."}
            elif response.status_code == 404:
                return {"error": "Not Found: The resource does not exist or you do not have permission to view it."}
            elif response.status_code >= 400:
                # Attempt to parse detail safely
                try:
                    err_json = response.json()
                    detail = err_json.get("detail", response.text)
                except Exception:
                    detail = response.text
                return {"error": f"Backend API Error ({response.status_code})", "detail": detail}
                
            return response.json()
        except httpx.RequestError as e:
            return {"error": f"Failed to connect to SentinelTrace API: {str(e)}"}
