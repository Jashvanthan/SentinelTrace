import asyncio
import uuid
import logging
from typing import AsyncGenerator
from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.dependencies import redis_manager
from app.core.deps import get_db_session
from app.models.workspace import WorkspaceMember
from sqlalchemy import select

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/workspaces", tags=["Real-time Events"])
settings = get_settings()


async def get_user_from_ticket(ticket: str) -> uuid.UUID:
    """Validate the short-lived SSE ticket and return the user ID."""
    try:
        payload = jwt.decode(ticket, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "sse":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ticket type")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ticket payload")
        return uuid.UUID(user_id)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired ticket")


@router.get("/{workspace_id}/events/stream")
async def event_stream(
    workspace_id: uuid.UUID,
    request: Request,
    ticket: str = Query(..., description="Short-lived SSE authentication ticket"),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Server-Sent Events endpoint for real-time workspace threat feed.
    """
    user_id = await get_user_from_ticket(ticket)

    # Enforce workspace isolation manually since we can't use standard auth Depends with ticket in query param
    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user_id,
        )
    )
    if not member:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")

    async def event_generator() -> AsyncGenerator[str, None]:
        channel_name = f"workspace:{workspace_id}:events"
        pubsub = redis_manager.client.pubsub()
        await pubsub.subscribe(channel_name)
        
        logger.info(f"SSE connected for user {user_id} on {channel_name}")
        
        try:
            while True:
                if await request.is_disconnected():
                    break

                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    data = message["data"]
                    # Format as Server-Sent Event
                    yield f"event: message\ndata: {data}\n\n"
                
                # Send a heartbeat every 15 seconds to keep connection alive
                yield ": heartbeat\n\n"
                
        except asyncio.CancelledError:
            logger.info(f"SSE request cancelled for user {user_id}")
        except Exception as e:
            logger.error(f"SSE stream error: {e}")
        finally:
            await pubsub.unsubscribe(channel_name)
            await pubsub.close()
            logger.info(f"SSE disconnected for user {user_id} on {channel_name}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable proxy buffering for Nginx
        }
    )
