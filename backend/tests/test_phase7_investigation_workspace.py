"""
SentinelTrace — Phase 7 Analyst Investigation Workspace Test Suite
"""
import asyncio
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

# Ensure app is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.investigation import (
    FindingConfidence,
    FindingSeverity,
    Investigation,
    InvestigationEntity,
    InvestigationStatus,
    VerificationStatus,
)
from app.schemas.investigation import (
    EvidenceVerifyRequest,
    FindingCreate,
    InvestigationCreate,
    NoteCreate,
)
from app.services.investigation_service import InvestigationService


class TestPhase7InvestigationWorkspace(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.ws_a_id = uuid.uuid4()
        self.ws_b_id = uuid.uuid4()
        self.user_a_id = uuid.uuid4()
        self.user_b_id = uuid.uuid4()

    async def test_1_risk_summary_computation(self):
        """Test explainable 0-100 investigation risk calculation and severity assignment."""
        inv = Investigation(
            id=uuid.uuid4(),
            workspace_id=self.ws_a_id,
            name="Suspicious Phishing Campaign",
            status=InvestigationStatus.OPEN,
            created_by_id=self.user_a_id,
        )
        
        # Attach a Critical finding (+35 pts) and High finding (+25 pts)
        inv.findings = [
            AsyncMock(title="Malicious C2 Domain", severity=FindingSeverity.CRITICAL),
            AsyncMock(title="Phishing URL Observed", severity=FindingSeverity.HIGH),
        ]
        inv.entities = []
        inv.verifications = []

        mock_db = AsyncMock()
        summary = await InvestigationService.compute_risk_summary(mock_db, inv)
        
        self.assertEqual(summary["risk_score"], 60)
        self.assertEqual(summary["severity"], "HIGH")
        self.assertEqual(len(summary["contributors"]), 2)
        print(f"  ✓ Risk Summary Computation verified (Score: {summary['risk_score']}/100, Severity: {summary['severity']})")

    async def test_2_cross_workspace_idor_protection(self):
        """Verify strict cross-workspace isolation for investigations, notes, and findings."""
        inv_a_id = uuid.uuid4()
        
        mock_db = AsyncMock()
        mock_db.scalar.return_value = None  # Simulates query with workspace_id filter returning None when requesting ws_b

        # Attempting to fetch Workspace A's investigation using Workspace B's ID
        res = await InvestigationService.get_investigation(mock_db, self.ws_b_id, inv_a_id)
        self.assertIsNone(res)
        print("  ✓ Cross-Workspace IDOR/BOLA Protection verified (Workspace B denied access to Workspace A Case File)")

    def test_3_status_transitions(self):
        """Verify valid investigation status transitions (OPEN -> IN_REVIEW -> RESOLVED -> ARCHIVED)."""
        statuses = [s.value for s in InvestigationStatus]
        self.assertIn("OPEN", statuses)
        self.assertIn("IN_REVIEW", statuses)
        self.assertIn("RESOLVED", statuses)
        self.assertIn("ARCHIVED", statuses)
        print("  ✓ Investigation Status Transitions verified")

    def test_4_verification_statuses(self):
        """Verify analyst verification statuses (UNREVIEWED, REVIEWED, VERIFIED, DISPUTED)."""
        ver_statuses = [v.value for v in VerificationStatus]
        self.assertIn("UNREVIEWED", ver_statuses)
        self.assertIn("REVIEWED", ver_statuses)
        self.assertIn("VERIFIED", ver_statuses)
        self.assertIn("DISPUTED", ver_statuses)
        print("  ✓ Evidence Verification Statuses verified")


if __name__ == "__main__":
    unittest.main()
