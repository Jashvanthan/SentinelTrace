"""
SentinelTrace Backend — Neo4j Graph Service

Manages campaign correlation using a property graph:
  (Sender)-[:SENT]->(Email)-[:CONTAINS]->(IOC)
  (Email)-[:ORIGINATED_FROM]->(IPAddress)
  (Domain)-[:RESOLVES_TO]->(IPAddress)
  (Email)-[:PART_OF]->(Campaign)

Cypher queries link entities across analyses to detect coordinated attack campaigns.
"""
from __future__ import annotations

from typing import Any

from neo4j import AsyncGraphDatabase, AsyncSession as Neo4jSession
from neo4j.exceptions import ServiceUnavailable

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("sentineltrace.neo4j")


class Neo4jService:
    """Async Neo4j service for campaign correlation graph operations."""

    def __init__(self) -> None:
        self._driver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD),
            database=settings.NEO4J_DATABASE,
            max_connection_pool_size=10,
            connection_timeout=1.0,
            max_transaction_retry_time=1.0,
        )

    async def close(self) -> None:
        await self._driver.close()

    async def health_check(self) -> bool:
        try:
            async with self._driver.session() as session:
                await session.run("RETURN 1")
            return True
        except ServiceUnavailable:
            return False

    # ── Write Operations ──────────────────────────────────────────────────────

    async def upsert_email_analysis(
        self,
        workspace_id: str,
        analysis_id: str,
        sender_email: str | None,
        sender_domain: str | None,
        subject: str | None,
        threat_category: str | None,
        severity: str | None,
        iocs: list[dict[str, Any]],
        received_ips: list[str],
    ) -> None:
        """
        Write an email analysis into the graph, creating/merging all related nodes.
        """
        import asyncio
        try:
            await asyncio.wait_for(self._driver.verify_connectivity(), timeout=0.5)
        except Exception as conn_err:
            logger.debug(f"Neo4j is unavailable, skipping graph write: {conn_err}")
            return

        try:
            async with self._driver.session() as session:
                await session.execute_write(
                    self._write_analysis,
                    workspace_id, analysis_id, sender_email, sender_domain,
                    subject, threat_category, severity,
                    iocs, received_ips,
                )
        except Exception as err:
            logger.warning(f"Neo4j write failed: {err}")

    @staticmethod
    async def _write_analysis(
        tx,
        workspace_id: str,
        analysis_id: str,
        sender_email: str | None,
        sender_domain: str | None,
        subject: str | None,
        threat_category: str | None,
        severity: str | None,
        iocs: list[dict],
        received_ips: list[str],
    ) -> None:
        # Create/merge the Email node
        await tx.run(
            """
            MERGE (e:Email {analysis_id: $analysis_id})
            SET e.workspace_id = $workspace_id,
                e.subject = $subject,
                e.threat_category = $threat_category,
                e.severity = $severity,
                e.updated_at = datetime()
            """,
            workspace_id=workspace_id,
            analysis_id=analysis_id,
            subject=subject,
            threat_category=threat_category,
            severity=severity,
        )

        # Create/merge Sender node and relationship
        if sender_email:
            await tx.run(
                """
                MERGE (s:Sender {email: $sender_email})
                SET s.domain = $sender_domain
                WITH s
                MATCH (e:Email {analysis_id: $analysis_id})
                MERGE (s)-[:SENT]->(e)
                """,
                sender_email=sender_email,
                sender_domain=sender_domain,
                analysis_id=analysis_id,
            )

        if sender_domain:
            await tx.run(
                """
                MERGE (d:Domain {name: $domain})
                WITH d
                MATCH (e:Email {analysis_id: $analysis_id})
                MERGE (e)-[:FROM_DOMAIN]->(d)
                """,
                domain=sender_domain,
                analysis_id=analysis_id,
            )

        # Create IOC nodes
        for ioc in iocs:
            await tx.run(
                """
                MERGE (ioc:IOC {value: $value, type: $ioc_type})
                SET ioc.is_malicious = $is_malicious,
                    ioc.threat_score = $threat_score
                WITH ioc
                MATCH (e:Email {analysis_id: $analysis_id})
                MERGE (e)-[:CONTAINS]->(ioc)
                """,
                value=ioc.get("value", ""),
                ioc_type=ioc.get("ioc_type", "UNKNOWN"),
                is_malicious=ioc.get("is_malicious"),
                threat_score=ioc.get("threat_score"),
                analysis_id=analysis_id,
            )

        # Create infrastructure IP nodes
        for ip in received_ips:
            await tx.run(
                """
                MERGE (ip:IPAddress {address: $ip})
                WITH ip
                MATCH (e:Email {analysis_id: $analysis_id})
                MERGE (e)-[:ROUTED_THROUGH]->(ip)
                """,
                ip=ip,
                analysis_id=analysis_id,
            )

    # ── Campaign Detection ────────────────────────────────────────────────────

    async def find_related_campaigns(
        self,
        sender_domain: str | None,
        ioc_values: list[str],
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Find email analyses that share infrastructure or IOCs —
        indicating a coordinated attack campaign.
        """
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (e:Email)-[:FROM_DOMAIN]->(d:Domain {name: $domain})
                RETURN e.analysis_id AS analysis_id, e.threat_category AS category,
                       e.severity AS severity, 'shared_domain' AS correlation_type
                LIMIT $limit
                UNION
                MATCH (e:Email)-[:CONTAINS]->(ioc:IOC)
                WHERE ioc.value IN $ioc_values
                RETURN e.analysis_id AS analysis_id, e.threat_category AS category,
                       e.severity AS severity, 'shared_ioc' AS correlation_type
                LIMIT $limit
                """,
                domain=sender_domain or "",
                ioc_values=ioc_values,
                limit=limit,
            )
            return [dict(record) async for record in result]

    async def get_campaign_graph(
        self,
        workspace_id: str,
        campaign_id: str | None = None,
        analysis_id: str | None = None,
        depth: int = 2,
    ) -> dict[str, Any]:
        """
        Return a subgraph suitable for frontend visualization.
        """
        safe_depth = max(1, min(int(depth), 5))
        async with self._driver.session() as session:
            if analysis_id:
                query = f"""
                MATCH path = (e:Email {{analysis_id: $analysis_id, workspace_id: $workspace_id}})-[*1..{safe_depth}]-(n)
                WHERE NOT (n:Email AND n.workspace_id <> $workspace_id)
                RETURN nodes(path) AS nodes, relationships(path) AS rels
                """
                params: dict = {"analysis_id": analysis_id, "workspace_id": workspace_id}
            else:
                query = f"""
                MATCH path = (e:Email {{workspace_id: $workspace_id}})-[*1..{safe_depth}]-(n)
                WHERE NOT (n:Email AND n.workspace_id <> $workspace_id)
                RETURN nodes(path) AS nodes, relationships(path) AS rels
                LIMIT 200
                """
                params = {"workspace_id": workspace_id}

            result = await session.run(query, **params)
            nodes: dict[str, dict] = {}
            edges: list[dict] = []
            seen_edges: set[tuple[str, str, str]] = set()

            async for record in result:
                for node in (record.get("nodes") or []):
                    nid = str(node.id)
                    if nid not in nodes:
                        nodes[nid] = {
                            "id": nid,
                            "node_type": list(node.labels)[0] if node.labels else "Unknown",
                            "label": self._node_label(node),
                            "properties": self._clean_props(dict(node)),
                        }
                for rel in (record.get("rels") or []):
                    source_id = str(rel.start_node.id)
                    target_id = str(rel.end_node.id)
                    edge_key = (source_id, target_id, rel.type)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append({
                            "source": source_id,
                            "target": target_id,
                            "relationship_type": rel.type,
                            "properties": self._clean_props(dict(rel)),
                        })

            return {
                "campaign_id": campaign_id,
                "nodes": list(nodes.values()),
                "edges": edges,
                "analysis_count": len([n for n in nodes.values() if n["node_type"] == "Email"]),
            }

    @staticmethod
    def _clean_props(props: dict[str, Any]) -> dict[str, Any]:
        """Convert non-serializable Neo4j types (like DateTime) to JSON-safe primitives."""
        cleaned: dict[str, Any] = {}
        for k, v in props.items():
            if hasattr(v, "iso_format"):
                cleaned[k] = v.iso_format()
            elif hasattr(v, "isoformat"):
                cleaned[k] = v.isoformat()
            elif isinstance(v, (str, int, float, bool, type(None))):
                cleaned[k] = v
            elif isinstance(v, (list, tuple, set)):
                cleaned[k] = [
                    x.iso_format() if hasattr(x, "iso_format") else (x.isoformat() if hasattr(x, "isoformat") else x)
                    for x in v
                ]
            elif isinstance(v, dict):
                cleaned[k] = Neo4jService._clean_props(v)
            else:
                cleaned[k] = str(v)
        return cleaned

    @staticmethod
    def _node_label(node) -> str:
        labels = list(node.labels)
        node_type = labels[0] if labels else "Unknown"
        props = dict(node)
        if node_type == "Email":
            return props.get("subject") or (props.get("analysis_id", "")[:8]) or "Email"
        return (
            props.get("subject") or
            props.get("email") or
            props.get("name") or
            props.get("address") or
            props.get("value", "")[:32] or
            (props.get("analysis_id", "")[:8]) or
            node_type
        )

    async def setup_constraints(self) -> None:
        """Create uniqueness constraints on first startup."""
        async with self._driver.session() as session:
            constraints = [
                "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Email) REQUIRE e.analysis_id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Sender) REQUIRE s.email IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",
            ]
            for constraint in constraints:
                await session.run(constraint)
        logger.info("neo4j_constraints_created")


# ── Singleton ─────────────────────────────────────────────────────────────────
_neo4j_service: Neo4jService | None = None


def get_neo4j_service() -> Neo4jService:
    global _neo4j_service
    if _neo4j_service is None:
        _neo4j_service = Neo4jService()
    return _neo4j_service
