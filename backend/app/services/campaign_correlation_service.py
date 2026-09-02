"""
SentinelTrace Backend — Campaign Correlation Engine
"""
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict
from datetime import datetime, timezone, timedelta

from app.services.neo4j_service import get_neo4j_service

logger = logging.getLogger(__name__)

class CampaignCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    email_analysis_id: str
    campaign_id: Optional[str] = None
    correlation_score: int
    confidence: float
    matched_indicator_types: List[str]
    reasons: List[str]

class CampaignCorrelationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    workspace_id: str
    email_analysis_id: str
    candidates: List[CampaignCandidate]
    status: str

class CampaignCorrelationService:
    """
    Service to correlate email indicators securely within a workspace.
    """
    
    # Base configuration
    TIME_WINDOW_HOURS = 72
    MIN_CORRELATION_SCORE = 30
    
    # Weighting Model
    WEIGHTS = {
        "malicious_hash": 40,
        "malicious_url": 35,
        "malicious_ioc": 35,
        "malicious_sender": 25,
        "suspicious_domain": 15,
        "originating_ip": 15,
        "generic_domain": 5,
        "display_name": 5,
    }

    def __init__(self, neo4j_service=None):
        self.neo4j = neo4j_service or get_neo4j_service()

    async def correlate_email(
        self,
        workspace_id: str,
        email_analysis_id: str,
        evidence: Dict[str, Any]
    ) -> CampaignCorrelationResult:
        logger.info(f"campaign_correlation_started for workspace {workspace_id} email {email_analysis_id}")
        
        # In a real implementation, we would extract specific indicators from the `evidence` parameter
        # such as exact URLs, hashes, and domains. For now we mock the graph lookup based on the indicators.
        
        # 1. Extract indicators
        malicious_urls = evidence.get("malicious_urls", [])
        malicious_hashes = evidence.get("malicious_hashes", [])
        malicious_iocs = evidence.get("malicious_iocs", [])
        suspicious_domains = evidence.get("suspicious_domains", [])
        originating_ips = evidence.get("originating_ips", [])
        
        # 2. Build targeted Neo4j queries scoping securely by workspace_id
        # We find other emails IN THE SAME WORKSPACE that share these indicators.
        # To avoid an N+1 explosion, we run a unified query or a targeted matching function.
        candidates_raw = await self._find_candidates_in_graph(
            workspace_id=workspace_id,
            email_analysis_id=email_analysis_id,
            malicious_urls=malicious_urls,
            malicious_hashes=malicious_hashes,
            malicious_iocs=malicious_iocs,
            suspicious_domains=suspicious_domains,
            originating_ips=originating_ips
        )
        
        candidates: List[CampaignCandidate] = []
        for candidate_id, match_data in candidates_raw.items():
            score, reasons, matched_types = self._score_candidate(match_data)
            
            # temporal penalty
            time_diff_hours = match_data.get("time_diff_hours", 0)
            if time_diff_hours > self.TIME_WINDOW_HOURS:
                score -= 15
                reasons.append(f"Temporal penalty: occurred {time_diff_hours}h apart")
                
            # Single IOC false positive prevention
            if len(matched_types) == 1 and score < 30:
                logger.debug(f"campaign_correlation_rejected for {candidate_id} due to single weak indicator")
                continue
                
            if score >= self.MIN_CORRELATION_SCORE:
                # Confidence calculation based on strength and multiplicity
                base_confidence = min(1.0, score / 100.0)
                if len(matched_types) >= 2:
                    base_confidence = min(1.0, base_confidence + 0.1)
                    
                candidates.append(CampaignCandidate(
                    email_analysis_id=candidate_id,
                    campaign_id=match_data.get("existing_campaign_id"),
                    correlation_score=score,
                    confidence=base_confidence,
                    matched_indicator_types=matched_types,
                    reasons=reasons
                ))
        
        # Sort candidates by score descending
        candidates.sort(key=lambda x: x.correlation_score, reverse=True)
        
        logger.info(f"campaign_correlation_completed found {len(candidates)} candidates")
        
        return CampaignCorrelationResult(
            workspace_id=workspace_id,
            email_analysis_id=email_analysis_id,
            candidates=candidates,
            status="COMPLETED"
        )

    def _score_candidate(self, match_data: Dict[str, Any]) -> tuple[int, List[str], List[str]]:
        score = 0
        reasons = []
        matched_types = []
        
        for ind_type in match_data.get("shared_indicators", []):
            weight = self.WEIGHTS.get(ind_type, 0)
            if weight > 0:
                score += weight
                reasons.append(f"Shared {ind_type} (+{weight})")
                matched_types.append(ind_type)
                
        return score, reasons, matched_types
        
    async def _find_candidates_in_graph(
        self,
        workspace_id: str,
        email_analysis_id: str,
        malicious_urls: List[str],
        malicious_hashes: List[str],
        malicious_iocs: List[str],
        suspicious_domains: List[str],
        originating_ips: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Interacts with the Neo4j graph using explicit Workspace scoping.
        """
        # This is a stub for the actual Neo4j queries.
        # In a real environment, we'd run:
        # MATCH (e1:Email {analysis_id: $analysis_id, workspace_id: $workspace_id})-[:CONTAINS]->(ioc)<-[:CONTAINS]-(e2:Email {workspace_id: $workspace_id})
        # WHERE e1 <> e2
        # RETURN e2.analysis_id, collect(ioc.type)
        return {}
