from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    Enum,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    JSONColumn,
    TenantScopedMixin,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import IntegrationProvider, IntegrationStatus

if TYPE_CHECKING:
    from app.models.tenant import Tenant


class Integration(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A configured connection to an external system.

    Credentials live in ``credentials_sealed`` as an envelope-encrypted JSON blob
    (see :mod:`app.core.crypto`) bound to ``tenant:{tenant_id}:integration:{id}``
    as AAD, so a row cannot be copied between tenants. The API never returns it;
    only ``credential_fingerprints`` and ``credential_keys`` are exposed so the
    UI can show *which* secrets are configured.
    """

    __tablename__ = "integrations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "provider", "name", name="uq_integrations_tenant_provider_name"
        ),
    )

    provider: Mapped[IntegrationProvider] = mapped_column(
        Enum(IntegrationProvider, native_enum=False, length=32), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    status: Mapped[IntegrationStatus] = mapped_column(
        Enum(IntegrationStatus, native_enum=False, length=24),
        default=IntegrationStatus.PENDING,
        nullable=False,
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Non-secret connection details: base urls, cluster name, region, default namespace.
    config: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    credentials_sealed: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_keys: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    credential_fingerprints: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )
    credentials_rotated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Secret used to verify inbound webhooks from this provider (also sealed).
    webhook_secret_sealed: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Does this integration permit *write* (remediation) calls, or read-only?
    allow_write: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Scope fence: only these namespaces/services may be touched via this integration.
    scope: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    last_health_check_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="integrations", lazy="noload")

    @property
    def crypto_context(self) -> str:
        """AAD binding the sealed blob to this exact row."""
        return f"tenant:{self.tenant_id}:integration:{self.id}"

    @property
    def is_usable(self) -> bool:
        return self.is_enabled and self.status in (
            IntegrationStatus.HEALTHY,
            IntegrationStatus.DEGRADED,
            IntegrationStatus.PENDING,
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Integration {self.provider}:{self.name} {self.status}>"
