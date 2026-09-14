"""
Investigation tools for SentinelTrace MCP.
These tools wrap the existing FastAPI backend endpoints to guarantee strict
workspace isolation, RBAC, and bounded response schemas.
"""
from typing import Any
from .api import _call_backend_api

async def search_threats(
    workspace_id: str,
    threat_category: str = None,
    is_malicious: bool = None,
    limit: int = 20
) -> dict[str, Any]:
    """Search threats within a workspace."""
    limit = max(1, min(limit, 100)) # Bound the limit
    params = {"page": 1, "page_size": limit}
    
    if threat_category:
        params["threat_category"] = threat_category
    if is_malicious is not None:
        params["is_malicious"] = str(is_malicious).lower()
        
    return await _call_backend_api("GET", f"/workspaces/{workspace_id}/emails", params=params)

async def get_email_analysis(
    workspace_id: str,
    email_id: str
) -> dict[str, Any]:
    """Get email analysis details within a workspace."""
    return await _call_backend_api("GET", f"/workspaces/{workspace_id}/emails/{email_id}")

async def search_iocs(
    workspace_id: str,
    search: str = None,
    ioc_type: str = None,
    is_malicious: bool = None,
    limit: int = 20
) -> dict[str, Any]:
    """Search IOCs within a workspace."""
    limit = max(1, min(limit, 100))
    params = {"workspace_id": workspace_id, "page": 1, "page_size": limit}
    
    if search:
        params["search"] = search
    if ioc_type:
        params["ioc_type"] = ioc_type
    if is_malicious is not None:
        params["is_malicious"] = str(is_malicious).lower()
        
    return await _call_backend_api("GET", "/intel/iocs", params=params)

async def get_campaign(
    workspace_id: str,
    campaign_id: str
) -> dict[str, Any]:
    """Get campaign details within a workspace."""
    return await _call_backend_api("GET", f"/workspaces/{workspace_id}/campaigns/{campaign_id}")

async def search_campaigns(
    workspace_id: str,
    status: str = None,
    limit: int = 20
) -> dict[str, Any]:
    """Search campaigns within a workspace."""
    limit = max(1, min(limit, 100))
    params = {"page": 1, "page_size": limit}
    if status:
        params["status"] = status
        
    return await _call_backend_api("GET", f"/workspaces/{workspace_id}/campaigns", params=params)

async def get_campaign_graph(
    workspace_id: str,
    campaign_id: str = None,
    analysis_id: str = None,
    depth: int = 2
) -> dict[str, Any]:
    """Get bounded campaign correlation graph."""
    depth = max(1, min(depth, 4)) # Bound depth between 1 and 4
    params = {"depth": depth, "workspace_id": workspace_id}
    if campaign_id:
        params["campaign_id"] = campaign_id
    if analysis_id:
        params["analysis_id"] = analysis_id
        
    # The graph API must be passed the workspace_id for tenant filtering
    return await _call_backend_api("GET", "/graph/campaign", params=params)

async def get_threat_summary(
    workspace_id: str
) -> dict[str, Any]:
    """Get a high-level summary of workspace threat statistics."""
    return await _call_backend_api("GET", f"/workspaces/{workspace_id}/stats")
