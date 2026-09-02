"""
SentinelTrace Backend — Pydantic Schemas: Auth & Users
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import AuthProvider, UserRole


# ── Request Schemas ───────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=256)
    password: str = Field(..., min_length=12, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class RefreshTokenRequest(BaseModel):
    """Used when refresh token is passed in body (alternative to cookie)."""
    refresh_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)


# ── Response Schemas ──────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    is_verified: bool
    auth_provider: AuthProvider
    avatar_url: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserResponse


class GoogleOAuthURLResponse(BaseModel):
    authorization_url: str
    state: str


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class UserUpdateRequest(BaseModel):
    full_name: str | None = Field(None, min_length=2, max_length=256)
    role: UserRole | None = None
    is_active: bool | None = None


class UserListResponse(BaseModel):
    model_config = {"from_attributes": True}

    items: list[UserResponse]
    total: int
    page: int
    page_size: int
