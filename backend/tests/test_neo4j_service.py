import pytest
import uuid
from app.services.neo4j_service import Neo4jService

@pytest.mark.asyncio
async def test_neo4j_idempotency_and_creation():
    service = Neo4jService()
    if not await service.health_check():
        pytest.skip("Neo4j is not available. Skipping integration test.")

    analysis_id = str(uuid.uuid4())
    workspace_id = str(uuid.uuid4())

    # First ingestion
    await service.upsert_email_analysis(
        workspace_id=workspace_id,
        analysis_id=analysis_id,
        sender_email="attacker@evil.com",
        sender_domain="evil.com",
        subject="Test Phishing",
        threat_category="PHISHING",
        severity="HIGH",
        iocs=[{"value": "http://malicious.com", "ioc_type": "URL", "is_malicious": True, "threat_score": 90}],
        received_ips=["198.51.100.2"]
    )

    # Second ingestion (should be idempotent due to MERGE)
    await service.upsert_email_analysis(
        workspace_id=workspace_id,
        analysis_id=analysis_id,
        sender_email="attacker@evil.com",
        sender_domain="evil.com",
        subject="Test Phishing",
        threat_category="PHISHING",
        severity="HIGH",
        iocs=[{"value": "http://malicious.com", "ioc_type": "URL", "is_malicious": True, "threat_score": 90}],
        received_ips=["198.51.100.2"]
    )

    # Verify graph structure and counts
    async with service._driver.session() as session:
        res_sender = await session.run("MATCH (s:Sender {email: $email}) RETURN s", email="attacker@evil.com")
        senders = await res_sender.data()
        
        res_domain = await session.run("MATCH (d:Domain {name: $name}) RETURN d", name="evil.com")
        domains = await res_domain.data()
        
        res_ioc = await session.run("MATCH (i:IOC {value: $value}) RETURN i", value="http://malicious.com")
        iocs = await res_ioc.data()
        
        res_ip = await session.run("MATCH (ip:IPAddress {address: $ip}) RETURN ip", ip="198.51.100.2")
        ips = await res_ip.data()

    assert len(senders) == 1
    assert len(domains) == 1
    assert len(iocs) == 1
    assert len(ips) == 1

    # Cleanup graph data specifically for this test
    async with service._driver.session() as session:
        await session.run("""
        MATCH (e:Email {analysis_id: $aid, workspace_id: $wid})
        OPTIONAL MATCH (e)-[*]-(connected)
        DETACH DELETE e, connected
        """, aid=analysis_id, wid=workspace_id)

    await service.close()
