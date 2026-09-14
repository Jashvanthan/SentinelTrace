import pytest
import pytest_asyncio
from app.main import app
from fastapi_limiter.depends import RateLimiter

from fastapi import Request, Response

async def mock_rate_limiter(self, request: Request, response: Response):
    pass

RateLimiter.__call__ = mock_rate_limiter

from sqlalchemy import text
from app.db.session import engine
from app.db.base import Base
# ensure models are registered
from app.models import *

@pytest_asyncio.fixture(scope="function", autouse=True)
async def lifespan_fixture():
    yield
