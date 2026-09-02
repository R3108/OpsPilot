from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.enums import TenantPlan, UserRole
from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_slug: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class SignupRequest(BaseModel):
    """Creates a tenant and its first OWNER in one step."""

    organization_name: Annotated[str, Field(min_length=2, max_length=200)]
    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]
    full_name: Annotated[str, Field(max_length=200)] = ""

    @field_validator("password")
    @classmethod
    def _strength(cls, v: str) -> str:
        if v.isdigit() or v.isalpha():
            raise ValueError("password must mix letters and at least one number or symbol")
        return v


class UserCreate(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]
    full_name: Annotated[str, Field(max_length=200)] = ""
    role: UserRole = UserRole.RESPONDER


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    external_ids: dict[str, str] | None = None


class UserOut(ORMModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class TenantOut(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: TenantPlan
    is_active: bool
    created_at: datetime


class SessionOut(BaseModel):
    user: UserOut
    tenant: TenantOut


class ApiKeyCreate(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    role: UserRole = UserRole.RESPONDER
    expires_in_days: Annotated[int, Field(ge=1, le=730)] | None = None


class ApiKeyOut(ORMModel):
    id: uuid.UUID
    name: str
    prefix: str
    role: UserRole
    is_active: bool
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    """The only time the plaintext key is ever returned."""

    key: str
