from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid

from app.models.base import (
    Base,
    JSONColumn,
    TenantScopedMixin,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import TenantPlan, UserRole

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.integration import Integration


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An organisation. The isolation boundary for every other table."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    plan: Mapped[TenantPlan] = mapped_column(
        Enum(TenantPlan, native_enum=False, length=32), default=TenantPlan.FREE, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Per-tenant overrides of the global safety knobs. Read by the policy engine;
    # see app.services.policy.TenantPolicy for the recognised keys.
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    users: Mapped[list[User]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", lazy="noload"
    )
    integrations: Mapped[list[Integration]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", lazy="noload"
    )
    incidents: Mapped[list[Incident]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", lazy="noload"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Tenant {self.slug}>"


class User(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False, length=32), default=UserRole.RESPONDER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Slack user id, GitHub login, ... so approvals can be attributed to the
    # right human no matter which surface they came from.
    external_ids: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="users", lazy="joined")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email} role={self.role}>"


class ApiKey(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Machine credential for alert ingestion. Only the hash is stored."""

    __tablename__ = "api_keys"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False, length=32), default=UserRole.RESPONDER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    tenant: Mapped[Tenant] = relationship(lazy="joined")


class RefreshToken(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """One outstanding refresh token per login session.

    Rotation: every ``POST /auth/refresh`` marks the presented token used and
    mints a fresh one, so a stolen refresh token is useful at most until the
    legitimate client refreshes once — at which point reuse is detected and the
    whole family is revoked. ``POST /auth/logout`` revokes without minting.
    """

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    replaced_by_jti: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
