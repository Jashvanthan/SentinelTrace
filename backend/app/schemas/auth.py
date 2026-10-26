"""
SentinelTrace Backend — Pydantic Schemas: Auth & Users
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import AuthProvider, UserRole


from app.services.password_service import validate_password_strength


# ── Request Schemas ───────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=256)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        valid, msg = validate_password_strength(v)
        if not valid:
            raise ValueError(msg)
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class RefreshTokenRequest(BaseModel):
    """Used when refresh token is passed in body (alternative to cookie)."""
    refresh_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def check_new_password_strength(cls, v: str) -> str:
        valid, msg = validate_password_strength(v)
        if not valid:
            raise ValueError(msg)
        return v


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def check_reset_password_strength(cls, v: str) -> str:
        valid, msg = validate_password_strength(v)
        if not valid:
            raise ValueError(msg)
        return v


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
    expires_in: int  # access token expiry in seconds
    session_expires_in: int = 86400  # absolute session expiry in seconds (24 hours)
    user: UserResponse


class GoogleOAuthURLResponse(BaseModel):
    authorization_url: str
    state: str


class GooglePendingResponse(BaseModel):
    """Response when Google OAuth succeeds but user has no SentinelTrace account yet."""
    pending_token: str
    email: str
    full_name: str
    picture: str | None = None


class GoogleRegistrationRequest(BaseModel):
    """Request body for POST /auth/google/complete-registration."""
    pending_token: str = Field(..., min_length=10)


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class UserProfileUpdateRequest(BaseModel):
    full_name: str | None = Field(None, min_length=1, max_length=256)
    avatar_url: str | None = None


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


# ── Multi-Device Session Schemas ──────────────────────────────────────────────

class DeviceSessionResponse(BaseModel):
    id: str
    family_id: str
    device_type: str  # "mobile", "desktop", "tablet", "unknown"
    device_name: str  # e.g. "iPhone (Mobile Safari)", "Windows PC (Chrome)"
    browser: str
    os: str
    ip_address: str | None = None
    created_at: datetime
    last_used_at: datetime | None = None
    expires_at: datetime
    is_current: bool = False


class DeviceSessionListResponse(BaseModel):
    sessions: list[DeviceSessionResponse]
    total_active: int

