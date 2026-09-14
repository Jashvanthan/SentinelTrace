import asyncio
import traceback
from app.services.neo4j_service import get_neo4j_service

async def test():
    try:
        neo = get_neo4j_service()
        print("Testing neo4j get_campaign_graph...")
        res = await neo.get_campaign_graph(workspace_id="03fc2996-0abb-4872-aa1d-df1b18dc3523", depth=2)
        print("Campaign graph result:", res)
    except Exception as e:
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
