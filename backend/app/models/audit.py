from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Enum, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.models.base import (
    Base,
    JSONColumn,
    TenantScopedMixin,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import AuditAction


class AuditLog(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Activity trail.

    Rows are immutable: there is no update path in the codebase, and migration
    ``0003`` installs a trigger rejecting UPDATE on this table.

    They are not permanent. ``DELETE /api/v1/audit`` lets an admin clear the
    tenant's trail (``services.audit.clear``), which is why this is an activity
    trail and not a compliance one — it cannot prove what an admin did.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_tenant_created", "tenant_id", "created_at"),
        Index("ix_audit_tenant_action", "tenant_id", "action"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )

    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, native_enum=False, length=64), nullable=False
    )

    # "user" | "agent" | "system" | "api_key" | "integration"
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="system")
    actor_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    actor_label: Mapped[str] = mapped_column(String(200), nullable=False, default="")

    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(120), nullable=True)

    incident_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Redacted before write: see app.services.audit.record
    before: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    after: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)

    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} {self.resource_type}:{self.resource_id}>"
