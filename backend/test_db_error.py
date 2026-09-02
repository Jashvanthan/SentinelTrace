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
    # Truncate
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(text(f"TRUNCATE {table.name} CASCADE;"))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        print("Registering...")
        resp = await ac.post("/api/v1/auth/register", json={
            "email": "testdb@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Test DB User"
        })
        print(f"Register status: {resp.status_code}")
        if resp.status_code != 201:
            print(resp.json())
        
        print("Logging in...")
        try:
            resp = await ac.post("/api/v1/auth/login", json={
                "email": "testdb@test.com",
                "password": "SuperSecretPassword123"
            })
            print(f"Login status: {resp.status_code}")
            if resp.status_code != 200:
                print(resp.json())
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(run())
