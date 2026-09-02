"""Institutional memory: past incidents and runbooks the history agent searches."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.models.base import (
    Base,
    JSONColumn,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class IncidentEmbedding(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Vector index over resolved incidents.

    On Postgres the ``embedding`` column is upgraded to ``vector(1536)`` by the
    pgvector migration and queried with ``<=>``; on sqlite (tests) it stays a JSON
    array and :mod:`app.services.similarity` falls back to in-process cosine so
    the same code path is exercised either way.
    """

    __tablename__ = "incident_embeddings"
    __table_args__ = (Index("ix_incident_embeddings_tenant_incident", "tenant_id", "incident_id"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Text that was embedded: title + symptoms + root cause + resolution.
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    embedding: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    dimensions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Denormalised so a similarity hit is renderable without a second query.
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)


class Runbook(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Human-written operational knowledge surfaced to the investigators.

    Runbooks are *advisory context only*. A runbook can suggest an action but it
    cannot authorise one — the action still has to exist in the catalog and clear
    the policy engine.
    """

    __tablename__ = "runbooks"
    __table_args__ = (Index("ix_runbooks_tenant_service", "tenant_id", "service"),)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    service: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tags: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    symptoms: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content_markdown: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Action keys this runbook recommends, validated against the catalog on save.
    suggested_action_keys: Mapped[list[Any]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
