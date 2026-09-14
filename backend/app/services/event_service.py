import json
import logging
import uuid
from typing import Any

from app.core.dependencies import redis_manager
from app.schemas.events import RealTimeEvent, RealTimeEventType

logger = logging.getLogger(__name__)

async def publish_workspace_event(workspace_id: uuid.UUID, event: RealTimeEvent) -> None:
    """
    Serialize and publish a real-time event to the workspace-specific Redis channel.
    PostgreSQL remains the source of truth; this is fire-and-forget notification.
    """
    try:
        # Ensure workspace ID matches
        event.workspace_id = workspace_id
        
        channel = f"workspace:{workspace_id}:events"
        # Serialize with Pydantic to ensure safety and date formatting
        payload = event.model_dump_json()
        
        await redis_manager.client.publish(channel, payload)
    except Exception as e:
        # Safely log failure without disrupting the primary database operation
        logger.error(f"Failed to publish workspace event {event.event_type} to {workspace_id}: {e}")
