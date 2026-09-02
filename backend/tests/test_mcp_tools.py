import sys
import os
import pytest

# Add mcp-server/src to path so we can import it
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../mcp-server/src")))

from tools.intel_tools import enrich_indicator
from tools.geo_tools import geolocate_ip

@pytest.mark.asyncio
async def test_enrich_indicator_missing_keys():
    """
    Test that enrichment gracefully degrades if API keys are missing.
    """
    # Using dummy indicator, should return valid dict but without actual enrichment
    # or should indicate API key is missing.
    result = await enrich_indicator("1.1.1.1", "ip")
    
    # Assuming the implementation handles missing keys by logging and returning defaults
    assert "error" not in result or "missing" in result["error"].lower()
    
@pytest.mark.asyncio
async def test_geolocate_ip_graceful():
    """
    Test that IP geolocation works or fails gracefully depending on free-tier limits.
    """
    result = await geolocate_ip("8.8.8.8")
    assert isinstance(result, dict)
    
    if "error" not in result:
        # Assuming it reached the free IP-API service successfully
        assert result.get("country") == "United States" or result.get("countryCode") == "US"
