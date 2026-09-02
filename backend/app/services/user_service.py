"""
SentinelTrace Backend — User Service
"""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await db.get(User, user_id)


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    return await db.scalar(select(User).where(User.email == email.lower()))


async def list_users(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[User], int]:
    offset = (page - 1) * page_size
    total = await db.scalar(select(func.count()).select_from(User))
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).offset(offset).limit(page_size)
    )
    return list(result.scalars()), total or 0
