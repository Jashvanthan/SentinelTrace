"""
SentinelTrace Backend — FastAPI Application Entry Point
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.auth import router as auth_router
from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.emails import router as emails_router
from app.api.v1.workspaces import router as workspaces_router
from app.api.v1.integrations import router as integrations_router
from app.api.v1.intel import (
    intel_router,
    geo_router,
    graph_router,
    reports_router,
)
from app.core.config import get_settings
from app.core.logging import RequestLoggingMiddleware, configure_logging, get_logger

settings = get_settings()
configure_logging()
logger = get_logger("sentineltrace.main")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    logger.info(
        "sentineltrace_starting",
        env=settings.APP_ENV,
        version="0.1.0",
    )

    # Initialize Neo4j constraints
    try:
        from app.services.neo4j_service import get_neo4j_service
        neo4j = get_neo4j_service()
        await neo4j.setup_constraints()
        logger.info("neo4j_ready")
    except Exception as e:
        logger.warning("neo4j_unavailable", error=str(e), msg="Continuing without Neo4j")

    # Initialize Redis rate limiter
    try:
        from fastapi_limiter import FastAPILimiter
        from app.core.dependencies import redis_manager
        await FastAPILimiter.init(redis_manager.client)
        logger.info("rate_limiter_ready")
    except Exception as e:
        logger.warning("rate_limiter_unavailable", error=str(e))

    yield

    # Shutdown
    try:
        from app.db.session import engine
        await engine.dispose()
        logger.info("postgres_disconnected")
    except Exception as e:
        logger.warning("postgres_disconnect_error", error=str(e))
        
    try:
        from app.core.dependencies import redis_manager
        await redis_manager.close()
    except Exception:
        pass
    try:
        from app.services.neo4j_service import get_neo4j_service
        await get_neo4j_service().close()
    except Exception:
        pass
    logger.info("sentineltrace_stopped")


# ── App Factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelTrace API",
        description=(
            "AI-Assisted Email Threat Detection, Digital Forensics & "
            "Threat Intelligence Platform"
        ),
        version="0.1.0",
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        lifespan=lifespan,
    )

    # ── Middleware ─────────────────────────────────────────────────────────────
    app.add_middleware(RequestLoggingMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID"],
    )

    if settings.is_production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["your-domain.com", "*.your-domain.com"],
        )

    # ── Routers ────────────────────────────────────────────────────────────────
    API_PREFIX = "/api/v1"

    app.include_router(auth_router, prefix=API_PREFIX)
    app.include_router(workspaces_router, prefix=API_PREFIX)
    app.include_router(emails_router, prefix=API_PREFIX)
    app.include_router(campaigns_router, prefix=API_PREFIX)
    app.include_router(integrations_router, prefix=API_PREFIX, tags=["integrations"])
    app.include_router(intel_router, prefix=API_PREFIX)
    app.include_router(geo_router, prefix=API_PREFIX)
    app.include_router(graph_router, prefix=API_PREFIX)
    app.include_router(reports_router, prefix=API_PREFIX)

    # ── Health Check ──────────────────────────────────────────────────────────
    @app.get("/health", tags=["Health"])
    async def health():
        return {"status": "healthy", "service": "sentineltrace-api"}

    @app.get("/health/dependencies", tags=["Health"])
    async def health_dependencies():
        deps = {
            "api": "healthy",
            "postgres": "unknown",
            "neo4j": "unknown",
            "redis": "unknown",
            "mcp": "unknown"
        }
        
        # Postgres
        try:
            from app.db.session import engine
            from sqlalchemy import text
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            deps["postgres"] = "healthy"
        except Exception:
            deps["postgres"] = "unhealthy"
            
        # Neo4j
        try:
            from app.services.neo4j_service import get_neo4j_service
            is_healthy = await get_neo4j_service().health_check()
            deps["neo4j"] = "healthy" if is_healthy else "unhealthy"
        except Exception:
            deps["neo4j"] = "unhealthy"
            
        # Redis
        try:
            from app.core.dependencies import redis_manager
            is_healthy = await redis_manager.ping()
            deps["redis"] = "healthy" if is_healthy else "unhealthy"
        except Exception:
            deps["redis"] = "unhealthy"
            
        # MCP (Spawned on demand via stdio, check if path exists or configured)
        deps["mcp"] = "healthy" if settings.MCP_SERVER_URL else "unavailable"
            
        return deps

    @app.get("/", tags=["Health"])
    async def root():
        return {
            "name": "SentinelTrace API",
            "version": "0.1.0",
            "docs": "/docs",
        }

    return app


app = create_app()
