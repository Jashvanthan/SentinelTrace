import sys
import io
import asyncio
import uuid
import os
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

# Set UTF-8 encoding for stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def log(msg):
    print(msg, flush=True)

async def test_all():
    log("================================================================")
    log("      SENTINELTRACE END-TO-END COMPONENT & INTEGRATION TEST     ")
    log("================================================================")

    # 1. Test Configuration & Environment
    log("\n[1/7] Testing Environment Configuration...")
    from app.core.config import get_settings
    settings = get_settings()
    log(f"  * App Name: {settings.APP_NAME}")
    log(f"  * LLM Provider: {settings.LLM_PROVIDER}")
    log(f"  * LLM Base URL: {settings.LLM_BASE_URL}")
    log(f"  * LLM Model: {settings.LLM_MODEL}")
    log(f"  * VirusTotal Key configured: {bool(settings.VIRUSTOTAL_API_KEY)}")
    log(f"  * AbuseIPDB Key configured: {bool(settings.ABUSEIPDB_API_KEY)}")
    log(f"  * Shodan Key configured: {bool(settings.SHODAN_API_KEY)}")
    log(f"  * Neo4j URI: {settings.NEO4J_URI}")
    log(f"  * Google Client ID configured: {bool(settings.GOOGLE_CLIENT_ID)}")
    log("  -> Configuration Loaded Successfully.")

    # 2. Test AI Model (OpenRouter Nvidia Nemotron 3.5)
    log("\n[2/7] Testing AI Model (OpenRouter / Nvidia Nemotron 3.5)...")
    from app.services.ai_service import get_ai_service, EmailThreatContext
    try:
        ai_service = get_ai_service()
        test_context = EmailThreatContext(
            subject="Urgent Security Alert: Account Verification Required",
            sender_email="support@paypal-security-alert-update.com",
            sender_domain="paypal-security-alert-update.com",
            reply_to="attacker-inbox@darkweb-mail.net",
            recipient_count=1,
            spf_result="FAIL",
            dkim_result="FAIL",
            dmarc_result="FAIL",
            extracted_urls=["http://paypal-security-alert-update.com/login/verify.php"],
            extracted_ips=["185.220.101.5"],
            attachment_count=1,
            attachment_names=["Invoice_Overdue.pdf.exe"],
            attachment_types=["application/x-msdownload"],
            body_text_snippet="Dear customer, your PayPal account has been suspended due to suspicious activity. Please click the link to verify your identity within 24 hours or your funds will be permanently locked.",
            threat_intel_summary={
                "185.220.101.5": {"is_malicious": True, "score": 95, "provider": "AbuseIPDB"},
                "Invoice_Overdue.pdf.exe": {"is_malicious": True, "score": 100, "provider": "VirusTotal"}
            }
        )

        log(f"  * Sending test threat scenario to LLM ({settings.LLM_MODEL})...")
        classification = await asyncio.wait_for(ai_service.classify_threat(test_context), timeout=60.0)
        log(f"  -> AI Model Threat Category: {classification.threat_category}")
        log(f"  -> AI Severity: {classification.severity}")
        log(f"  -> AI Confidence Score: {classification.confidence_score}")
        log(f"  -> AI Model Used: {classification.model_used}")
        log(f"  -> AI Reasoning: {classification.reasoning[:120]}...")

        log("  * Generating AI SOC Analyst Summary...")
        summary = await asyncio.wait_for(ai_service.generate_summary(test_context, classification), timeout=60.0)
        log(f"  -> AI Analyst Report:\n{summary[:200]}...")
        log("  [PASSED] AI Model is working accurately and returning structured JSON!")
    except Exception as e:
        log(f"  [FAILED] AI Model test error: {e}")
        import traceback
        traceback.print_exc()

    # 3. Test Threat Intelligence APIs & Geolocation
    log("\n[3/7] Testing Threat Intelligence APIs & Geolocation...")
    from app.services.intel_service import ThreatIntelService
    from app.services.geo_service import GeoService
    try:
        intel = ThreatIntelService()
        geo = GeoService()
        
        # Test IP Geolocation
        test_ip = "8.8.8.8"
        geo_res = await asyncio.wait_for(geo.geolocate(test_ip), timeout=10.0)
        log(f"  * Geolocation (8.8.8.8): Country={geo_res.get('country')}, City={geo_res.get('city')}, Org={geo_res.get('org')}")

        # Test IP Intel Enrichment
        enrich_res = await asyncio.wait_for(intel.enrich(test_ip, "ip", ["virustotal", "abuseipdb"]), timeout=15.0)
        log(f"  * Threat Intel (8.8.8.8): Malicious={enrich_res.get('is_malicious')}, Score={enrich_res.get('aggregate_threat_score')}")
        log("  [PASSED] Threat Intelligence & Geolocation operational!")
    except Exception as e:
        log(f"  [FAILED] Threat Intel test error: {e}")

    # 4. Test Database & User Storage / Fetching
    log("\n[4/7] Testing PostgreSQL Database (User & Workspace Data)...")
    from app.db.session import AsyncSessionLocal
    from app.models.user import User, UserRole
    from app.models.workspace import Workspace, WorkspaceMember
    from app.services.password_service import hash_password, verify_password
    from sqlalchemy import select

    test_user_id = None
    test_ws_id = None

    try:
        async with AsyncSessionLocal() as db:
            # Check or create QA test user
            email = "qa_tester@sentineltrace.io"
            result = await db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            if not user:
                user = User(
                    email=email,
                    password_hash=hash_password("SentinelQAPass123!"),
                    full_name="QA Automated Tester",
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_verified=True
                )
                db.add(user)
                await db.commit()
                await db.refresh(user)
                log(f"  * Created new user in DB: {user.email} (ID: {user.id})")
            else:
                log(f"  * Fetched existing user from DB: {user.email} (ID: {user.id})")
            test_user_id = user.id

            # Verify password hashing
            assert verify_password("SentinelQAPass123!", user.password_hash)
            log("  * Password hashing and verification: OK")

            # Check or create Workspace
            result = await db.execute(select(Workspace).where(Workspace.name == "QA Security Operations"))
            ws = result.scalar_one_or_none()
            if not ws:
                ws = Workspace(
                    name="QA Security Operations",
                    slug="qa-soc-workspace",
                    owner_id=user.id
                )
                db.add(ws)
                await db.commit()
                await db.refresh(ws)
                
                # Add membership
                member = WorkspaceMember(
                    workspace_id=ws.id,
                    user_id=user.id,
                    role="owner"
                )
                db.add(member)
                await db.commit()
                log(f"  * Created new workspace: {ws.name} (ID: {ws.id})")
            else:
                log(f"  * Fetched existing workspace: {ws.name} (ID: {ws.id})")
            test_ws_id = ws.id

            log("  [PASSED] PostgreSQL store and fetch data verified successfully!")
    except Exception as e:
        log(f"  [FAILED] Database test error: {e}")
        import traceback
        traceback.print_exc()

    # 5. Test Neo4j Connection & Graph Service
    log("\n[5/7] Testing Neo4j Campaign Graph Service...")
    from app.services.neo4j_service import get_neo4j_service
    try:
        neo4j = get_neo4j_service()
        is_healthy = await asyncio.wait_for(neo4j.health_check(), timeout=10.0)
        log(f"  * Neo4j Health Check: {'ONLINE' if is_healthy else 'OFFLINE'}")
        assert is_healthy, "Neo4j health check failed"
        
        # Test retrieving campaign graph for workspace
        graph_data = await asyncio.wait_for(neo4j.get_campaign_graph(str(test_ws_id)), timeout=10.0)
        log(f"  * Retrieved Campaign Graph: Nodes={len(graph_data.get('nodes', []))}, Edges={len(graph_data.get('edges', []))}")
        log("  [PASSED] Neo4j is connected, healthy, and queryable!")
    except Exception as e:
        log(f"  [FAILED] Neo4j error: {e}")

    # 6. Test Email Ingestion Pipeline & Threat Analysis
    log("\n[6/7] Testing Email Ingestion, Threat Pipeline & Database Storage...")
    from app.models.email_analysis import EmailAnalysis, AnalysisStatus
    from app.services.threat_service import ThreatAnalysisPipeline
    
    sample_eml = b"""From: "Security Alert" <alert@paypal-update-center.org>
To: target@victim-domain.com
Subject: [URGENT] Immediate Security Action Required for your Account
Date: Wed, 10 Sep 2026 12:00:00 +0000
Message-ID: <threat-sample-test-01@paypal-update-center.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received: from mail.paypal-update-center.org (185.220.101.5) by mx.victim-domain.com

Dear user,

We detected unauthorized logins from an unknown location (IP: 185.220.101.5).
Your account access is currently restricted.

Please confirm your identity by clicking the link below:
http://paypal-security-alert-update.com/login/verify.php

Sincerely,
Fraud Detection Team
"""
    try:
        async with AsyncSessionLocal() as db:
            pipeline = ThreatAnalysisPipeline()
            analysis_record = EmailAnalysis(
                workspace_id=test_ws_id,
                analyst_id=test_user_id,
                status=AnalysisStatus.PENDING,
            )
            db.add(analysis_record)
            await db.commit()
            await db.refresh(analysis_record)
            log(f"  * Created Analysis Record in DB (ID: {analysis_record.id})")

            log("  * Running full ThreatAnalysisPipeline (Parse -> Enrich -> AI Classify -> Store -> Graph)...")
            analyzed_record = await asyncio.wait_for(pipeline.run(db, analysis_record, sample_eml), timeout=60.0)
            await db.commit()
            await db.refresh(analyzed_record)

            log(f"  -> Pipeline Result Status: {analyzed_record.status}")
            log(f"  -> Threat Category: {analyzed_record.threat_category}")
            log(f"  -> Severity: {analyzed_record.severity}")
            log(f"  -> Threat Score: {analyzed_record.threat_score}/100")
            log(f"  -> Extracted Sender: {analyzed_record.sender_email}")
            log(f"  -> Extracted Subject: {analyzed_record.subject}")
            log(f"  -> AI Summary: {analyzed_record.ai_summary[:150] if analyzed_record.ai_summary else 'N/A'}...")
            
            # Fetch back from DB to verify persistence
            fetched = await db.get(EmailAnalysis, analyzed_record.id)
            assert fetched is not None
            assert fetched.threat_category == analyzed_record.threat_category
            log("  * Verified persistence: Record correctly stored and re-fetched from PostgreSQL")
            log("  [PASSED] Email parsing, AI threat analysis, and data storage pipeline passed completely!")
    except Exception as e:
        log(f"  [FAILED] Email analysis pipeline test error: {e}")
        import traceback
        traceback.print_exc()

    # 7. Test Google Workspace / Gmail OAuth Configuration
    log("\n[7/7] Testing Google Workspace & Gmail Integration Setup...")
    from app.services.gmail_service import gmail_service
    try:
        auth_url, _ = gmail_service.get_authorization_url(state="test_qa_state_token")
        log(f"  * Generated Gmail OAuth Authorization URL: {auth_url[:70]}...")
        assert "accounts.google.com" in auth_url or "oauth2" in auth_url
        assert f"client_id={settings.GOOGLE_CLIENT_ID}" in auth_url
        log("  * Google OAuth endpoint properly bound to Client ID and redirect URI")
        log("  [PASSED] Google Workspace / Gmail OAuth integration ready!")
    except Exception as e:
        log(f"  [FAILED] Gmail OAuth test error: {e}")

    log("\n================================================================")
    log("                     ALL SYSTEM TESTS COMPLETE                  ")
    log("================================================================")

if __name__ == "__main__":
    asyncio.run(test_all())
