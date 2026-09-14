import asyncio
import traceback
from app.services.intel_service import ThreatIntelService
from app.schemas.intel import EnrichmentResponse

async def main():
    try:
        service = ThreatIntelService()
        result = await service.enrich("8.8.8.8", "ip")
        print("Enrich result:", result)
        
        providers = result.get("providers", {})
        vt = providers.get("virustotal")
        ab = providers.get("abuseipdb")
        sh = providers.get("shodan")

        resp = EnrichmentResponse(
            indicator=result["indicator"],
            indicator_type=result["indicator_type"],
            virustotal=vt if (vt and "error" not in vt) else None,
            abuseipdb=ab if (ab and "error" not in ab) else None,
            shodan=sh if (sh and "error" not in sh) else None,
            aggregate_threat_score=int(result.get("aggregate_threat_score", 0)),
            is_malicious=bool(result.get("is_malicious", False)),
            errors={k: v.get("error", "") for k, v in providers.items() if isinstance(v, dict) and "error" in v},
        )
        print("EnrichmentResponse success:", resp)
    except Exception as e:
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
