"""
SentinelTrace Backend — Application Configuration

All settings are loaded from environment variables (via .env file).
Pydantic Settings validates and coerces all values at startup.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "SentinelTrace"
    APP_ENV: Literal["development", "staging", "production"] = "development"
    APP_DEBUG: bool = False
    APP_SECRET_KEY: str = Field("sentineltrace-default-super-secure-secret-key-32chars", min_length=32)
    ALLOWED_ORIGINS: str | list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    FRONTEND_URL: str = "http://localhost:5173"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentineltrace.db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, v: str | None) -> str:
        if not v or "://" not in str(v) or "your_postgresql" in str(v) or "placeholder" in str(v):
            return "sqlite+aiosqlite:///./sentineltrace.db"
        v_str = str(v).strip().strip("'\"")
        if v_str.startswith("postgres://"):
            return v_str.replace("postgres://", "postgresql+asyncpg://", 1)
        if v_str.startswith("postgresql://") and not v_str.startswith("postgresql+asyncpg://"):
            return v_str.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v_str

    # ── Neo4j ────────────────────────────────────────────────────────────────
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USERNAME: str = "neo4j"
    NEO4J_PASSWORD: str = ""
    NEO4J_DATABASE: str = "neo4j"

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ──────────────────────────────────────────────────────────────────
    JWT_SECRET: str = Field("sentineltrace-jwt-secret-key-must-be-32-chars-long", min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Google OAuth ─────────────────────────────────────────────────────────
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/google/callback"
    GOOGLE_SCOPES: str = "openid email profile"

    # ── Gmail API Integration ────────────────────────────────────────────────
    GMAIL_CLIENT_ID: str = ""
    GMAIL_CLIENT_SECRET: str = ""
    GMAIL_REDIRECT_URI: str = "http://localhost:8000/api/v1/integrations/gmail/callback"
    GMAIL_SCOPES: str = "https://www.googleapis.com/auth/gmail.readonly openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
    GMAIL_ENCRYPTION_KEY: str = ""

    # ── Gmail API ────────────────────────────────────────────────────────────
    GMAIL_SERVICE_ACCOUNT_JSON: str = ""

    # ── Threat Intelligence ──────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""

    # ── IP Geolocation ───────────────────────────────────────────────────────
    IPAPI_KEY: str = ""
    MAXMIND_DB_PATH: str = ""
    MAXMIND_CITY_DB_PATH: str = ""
    MAXMIND_ASN_DB_PATH: str = ""



    # ── AI / LLM ─────────────────────────────────────────────────────────────
    LLM_PROVIDER: Literal["openai", "anthropic", "local"] = "openai"
    LLM_BASE_URL: str = "https://api.openai.com/v1"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4o"
    LLM_MAX_TOKENS: int = 4096
    LLM_TEMPERATURE: float = 0.1
    CLASSIFIER_MODEL: str = "gpt-4o-mini"

    # ── MCP Server ───────────────────────────────────────────────────────────
    MCP_SERVER_URL: str = "http://localhost:8001"
    MCP_SERVER_SECRET: str = ""

    # ── Google Cloud Storage ─────────────────────────────────────────────────
    GCS_BUCKET_NAME: str = ""
    GCS_PROJECT_ID: str = ""
    GCS_CREDENTIALS_JSON: str = ""
    GCS_SIGNED_URL_EXPIRE_MINUTES: int = 60

    # ── Encryption ───────────────────────────────────────────────────────────
    FILE_ENCRYPTION_KEY: str = Field("", min_length=0)

    # ── SMTP (Free Gmail SMTP & Custom HTML Emails) ──────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 465
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_NAME: str = "SentinelTrace SOC Alert Desk"
    SUPPORT_RECEIVER_EMAIL: str = "jashvan467@gmail.com"

    # ── Resend HTTP API (for Cloud Deployments e.g. Render) ─────────────────────
    RESEND_API_KEY: str = ""
    RESEND_FROM_EMAIL: str = "onboarding@resend.dev"

    # ── Rate Limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10

    # ── SMTP / Email Service ───────────────────────────────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 465
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_FROM_NAME: str = "SentinelTrace SOC Alert Desk"
    SUPPORT_RECEIVER_EMAIL: str = "jashvan467@gmail.com"

    # ── Logging ──────────────────────────────────────────────────────────────
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "json"

    @property
    def is_production(self) -> bool:
        return self.APP_ENV in ["production", "staging"]

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance. Call once at app startup."""
    return Settings()
