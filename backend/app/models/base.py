"""Declarative base + mixins shared by every table."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, MetaData, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeDecorator, Uuid

# Cross-dialect JSON: JSONB on Postgres, plain JSON on sqlite (tests).
JSONColumn = JSON().with_variant(JSONB(astext_type=String()), "postgresql")


class UTCDateTime(TypeDecorator):
    """A timestamp that is always timezone-aware UTC on the way in and out.

    Postgres round-trips ``timestamptz`` with its offset intact, but sqlite has
    no timezone type and hands back naive datetimes. Without normalising here,
    perfectly ordinary code like ``approval.expires_at < datetime.now(UTC)``
    raises ``TypeError`` on one backend and works on the other — a class of bug
    that only ever shows up in the environment you are not testing in.

    Normalising at the column boundary means every ``datetime`` in the
    application is aware UTC, on every dialect, with no per-comparison guards.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {dict[str, Any]: JSONColumn, list[Any]: JSONColumn}


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        server_default=func.now(),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )


class TenantScopedMixin:
    """Every business table carries its tenant id.

    Isolation is enforced in two places: the repository layer always filters on
    ``tenant_id`` (see :mod:`app.services.repository`), and Postgres row-level
    security policies key off ``current_setting('opspilot.tenant_id')`` for
    defence in depth (see the RLS migration).
    """

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


def tenant_index(table_name: str, *columns: str) -> Index:
    """Helper for the (tenant_id, ...) composite indexes every list query needs."""
    return Index(f"ix_{table_name}_tenant_{'_'.join(columns)}", "tenant_id", *columns)
