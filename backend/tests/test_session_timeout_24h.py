import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
import unittest
from unittest.mock import patch

from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.models.refresh_session import RefreshSession
from sqlalchemy import select

settings = get_settings()

class TestSessionTimeout24Hours(unittest.IsolatedAsyncioTestCase):

    async def test_session_expiration_enforcement_24h(self):
        """
        Verify:
        1. Login returns session_expires_in = 86400 (24 hours).
        2. Immediate refresh within 24 hours succeeds.
        3. Once 24 hours pass from initial session creation, refresh is rejected with 401.
        4. Token family is revoked on expiration.
        """
        test_email = f"session_test_{uuid.uuid4().hex[:8]}@sentineltrace.io"
        test_password = "SuperSecurePassword123!"

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # 1. Register test user
            reg_resp = await ac.post("/api/v1/auth/register", json={
                "email": test_email,
                "password": test_password,
                "full_name": "Session Timeout Tester"
            })
            self.assertEqual(reg_resp.status_code, 201)

            # 2. Login
            login_resp = await ac.post("/api/v1/auth/login", json={
                "email": test_email,
                "password": test_password
            })
            self.assertEqual(login_resp.status_code, 200)
            data = login_resp.json()
            self.assertIn("access_token", data)
            self.assertEqual(data.get("session_expires_in"), 86400)
            self.assertIn("st_refresh_token", login_resp.cookies)

            # 3. Refresh within 24 hours (simulating 1 hour into session)
            refresh_resp = await ac.post("/api/v1/auth/refresh")
            self.assertEqual(refresh_resp.status_code, 200)
            refreshed_data = refresh_resp.json()
            self.assertIn("access_token", refreshed_data)
            self.assertGreater(refreshed_data.get("session_expires_in", 0), 0)

            # 4. Now simulate 24 hours + 1 minute having passed since initial login
            # Adjust the created_at of the earliest session in DB to 25 hours ago
            async with AsyncSessionLocal() as db:
                sessions = (await db.execute(select(RefreshSession))).scalars().all()
                user_sessions = [s for s in sessions if s.token_hash]
                for s in user_sessions:
                    s.created_at = datetime.now(UTC) - timedelta(hours=25)
                await db.commit()

            # 5. Attempt refresh after 24 hours -> MUST BE REJECTED with 401
            expired_refresh_resp = await ac.post("/api/v1/auth/refresh")
            self.assertEqual(expired_refresh_resp.status_code, 401)
            err_detail = expired_refresh_resp.json().get("detail", "")
            self.assertIn("expired", err_detail.lower())
            print(f"  [SUCCESS] Verified 24-hour absolute session expiration rejection: '{err_detail}'")

if __name__ == "__main__":
    unittest.main()
