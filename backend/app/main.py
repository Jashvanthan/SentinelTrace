"""
SentinelTrace Backend — FastAPI Application Entry Point
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import JSONResponse

from app.api.v1.auth import router as auth_router
from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.emails import router as emails_router
from app.api.v1.workspaces import router as workspaces_router
from app.api.v1.integrations import router as integrations_router
from app.api.v1.events import router as events_router
from app.api.v1.activity import router as activity_router
from app.api.v1.intel import (
    intel_router,
    geo_router,
    graph_router,
    reports_router as intel_reports_router,
)
from app.api.v1.ip_trace import router as ip_trace_router
from app.api.v1.investigation import router as investigation_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.reports import router as investigation_reports_router
from app.api.v1.support import router as support_router
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

    # Initialize Database tables
    try:
        from app.db.session import engine
        from app.db.base import Base
        import app.models  # noqa: F401
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("database_tables_ready")

        # Storage cleanup: purge expired sessions
        try:
            from app.db.session import cleanup_expired_sessions
            purged = await cleanup_expired_sessions()
            if purged > 0:
                logger.info("expired_sessions_purged", count=purged)
        except Exception as purge_err:
            logger.warning("cleanup_sessions_error", error=str(purge_err))
    except Exception as e:
        logger.warning("database_tables_init_error", error=str(e))

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
    try:
        from app.core.http_client import close_http_client
        await close_http_client()
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
    # Network performance: gzip compress responses > 1KB
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(RequestLoggingMiddleware)

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        # 1. Reject oversized requests early to prevent memory exhaustion DoS (max 50MB)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 52428800:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Payload too large. Maximum request size is 50MB."}
                    )
            except ValueError:
                pass

        response = await call_next(request)

        # 2. Hardened Enterprise Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # 3. HSTS when running on HTTPS / production
        is_https = request.headers.get("x-forwarded-proto") == "https" or settings.is_production
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)(:\d+)?|https://.*\.vercel\.app)$",
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID"],
    )

    if settings.is_production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"],
        )

    # ── Exception Handlers ─────────────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc: Exception):
        logger.error("unhandled_server_exception", error=str(exc), path=request.url.path)
        origin = request.headers.get("origin")
        headers = {}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "*"
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred. Please verify database connection."},
            headers=headers,
        )

    # ── Routers ────────────────────────────────────────────────────────────────
    API_PREFIX = "/api/v1"

    app.include_router(auth_router, prefix=API_PREFIX)
    app.include_router(workspaces_router, prefix=API_PREFIX)
    app.include_router(events_router, prefix=API_PREFIX)
    app.include_router(emails_router, prefix=API_PREFIX)
    app.include_router(campaigns_router, prefix=API_PREFIX)
    app.include_router(integrations_router, prefix=API_PREFIX, tags=["integrations"])
    app.include_router(intel_router, prefix=API_PREFIX)
    app.include_router(geo_router, prefix=API_PREFIX)
    app.include_router(ip_trace_router, prefix=API_PREFIX)
    app.include_router(graph_router, prefix=API_PREFIX)
    app.include_router(intel_reports_router, prefix=API_PREFIX)
    app.include_router(activity_router, prefix=API_PREFIX)
    app.include_router(investigation_router, prefix=API_PREFIX)
    app.include_router(investigations_router, prefix=API_PREFIX)
    app.include_router(investigation_reports_router, prefix=API_PREFIX)
    app.include_router(support_router, prefix=API_PREFIX)

    # Alias route for /api/v1/analyses/{analysis_id}/ip-trace
    app.include_router(ip_trace_router, prefix=f"{API_PREFIX}/analyses")

    # ── Health Check ──────────────────────────────────────────────────────────
    @app.get("/health", tags=["Health"])
    @app.get(f"{API_PREFIX}/health", tags=["Health"])
    async def health():
        return {"status": "healthy", "service": "sentineltrace-api"}

    @app.get("/health/dependencies", tags=["Health"])
    @app.get(f"{API_PREFIX}/health/dependencies", tags=["Health"])
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
        except Exception as e:
            deps["postgres"] = "unhealthy"
            db_host = getattr(engine.url, "host", "unknown") if "engine" in locals() else "unknown"
            deps["postgres_error"] = f"{str(e)} (host={db_host})"
            
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
