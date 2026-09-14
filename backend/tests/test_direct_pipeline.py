import asyncio
from app.db.session import AsyncSessionLocal
from app.models.email_analysis import EmailAnalysis, AnalysisStatus
from app.services.threat_service import ThreatAnalysisPipeline

async def direct_test():
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        res = await db.execute(select(EmailAnalysis).order_by(EmailAnalysis.created_at.desc()).limit(1))
        analysis = res.scalar_one_or_none()
        print('Latest analysis:', analysis.id, analysis.status)
        
        eml_content = b'''From: attacker@evil-corp.com
To: victim@company.com
Subject: Urgent: Verify your payroll account
Date: Thu, 10 Sep 2026 10:00:00 +0000
Content-Type: text/plain

Please click here to verify: http://phishing-site.xyz/login
'''
        pipeline = ThreatAnalysisPipeline()
        try:
            print('Running pipeline directly...')
            await pipeline.run(db, analysis, eml_content)
            await db.commit()
            print('Pipeline finished! Status:', analysis.status, 'Severity:', analysis.severity, 'Threat:', analysis.threat_category, 'Score:', analysis.threat_score)
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    asyncio.run(direct_test())
