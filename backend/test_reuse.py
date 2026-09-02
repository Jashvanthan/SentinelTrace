import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.session import engine
from sqlalchemy import text
from app.db.base import Base

from fastapi_limiter.depends import RateLimiter
from fastapi import Request, Response
async def mock_rate_limiter(self, request: Request, response: Response):
    pass
RateLimiter.__call__ = mock_rate_limiter

async def run():
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(text(f"TRUNCATE {table.name} CASCADE;"))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": "testreuse@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Test Reuse User"
        })
        
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": "testreuse@test.com",
            "password": "SuperSecretPassword123"
        })
        
        old_cookie = login_resp.cookies.get("st_refresh_token")
        print(f"Old cookie: {old_cookie}")
        
        refresh_resp = await ac.post("/api/v1/auth/refresh")
        new_cookie = refresh_resp.cookies.get("st_refresh_token")
        print(f"New cookie: {new_cookie}")
        
        print(f"Are they equal? {old_cookie == new_cookie}")
        
        # Now try to reuse old cookie
        ac.cookies.set("st_refresh_token", old_cookie)
        reuse_resp = await ac.post("/api/v1/auth/refresh")
        print(f"Reuse resp status: {reuse_resp.status_code}")
        if reuse_resp.status_code != 401:
            print(f"Reuse resp body: {reuse_resp.text}")

if __name__ == "__main__":
    asyncio.run(run())
