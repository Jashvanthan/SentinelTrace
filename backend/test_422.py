import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from fastapi_limiter.depends import RateLimiter

RateLimiter.__call__ = lambda *a, **k: None

async def main():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/auth/register", json={
            "email": "test1@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Test User"
        })
        print("Status:", resp.status_code)
        print("Body:", resp.json())

if __name__ == "__main__":
    asyncio.run(main())
