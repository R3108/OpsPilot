"""Refresh-token rotation and run heartbeats.

Adds ``refresh_tokens``: one row per outstanding refresh token, so
``POST /auth/refresh`` can rotate (mark used, mint fresh) and detect reuse,
and ``POST /auth/logout`` can revoke. Includes the tenant-isolation RLS policy
for the new table, matching the ``0002`` hardening.

Also adds ``agent_runs.last_heartbeat_at`` so the stuck-run reconciler can tell
a dead worker from a slow-but-alive run.

Idempotency note: ``0001`` builds the schema from live model metadata via
``create_all``, so on a *fresh* database ``refresh_tokens`` (and the heartbeat
column) already exist by the time this revision runs. Every operation below is
therefore guarded — create only what is missing — so the chain works both on
fresh databases and on databases migrating up from ``0003``.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import inspect, text
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _table_exists(bind, table: str) -> bool:  # noqa: ANN001, ANN202
    return inspect(bind).has_table(table)


def _column_exists(bind, table: str, column: str) -> bool:  # noqa: ANN001, ANN202
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if not _table_exists(bind, "refresh_tokens"):
            op.create_table(
                "refresh_tokens",
                sa.Column("id", UUID(as_uuid=True), primary_key=True),
                sa.Column(
                    "tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False
                ),
                sa.Column(
                    "user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False
                ),
                sa.Column("jti", sa.String(64), nullable=False),
                sa.Column("token_hash", sa.String(128), nullable=False),
                sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
                sa.Column("replaced_by_jti", sa.String(64), nullable=True),
                sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
                sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            )
            op.create_index("ix_refresh_tokens_tenant_id", "refresh_tokens", ["tenant_id"])
            op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
            op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"], unique=True)
            op.execute("ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY")
            op.execute("ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY")
            op.execute(
                """
                CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
                    USING (
                        tenant_id = NULLIF(
                            current_setting('opspilot.tenant_id', true), ''
                        )::uuid
                    )
                """
            )
        elif not _rls_policy_exists(bind):
            op.execute("ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY")
            op.execute("ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY")
            op.execute(
                """
                CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
                    USING (
                        tenant_id = NULLIF(
                            current_setting('opspilot.tenant_id', true), ''
                        )::uuid
                    )
                """
            )
        if not _column_exists(bind, "agent_runs", "last_heartbeat_at"):
            op.add_column(
                "agent_runs",
                sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            )
    else:
        from app.models import Base

        Base.metadata.create_all(bind=bind, tables=[Base.metadata.tables["refresh_tokens"]])
        if not _column_exists(bind, "agent_runs", "last_heartbeat_at"):
            op.add_column(
                "agent_runs",
                sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            )


def _rls_policy_exists(bind) -> bool:  # noqa: ANN001, ANN202
    row = bind.execute(
        text(
            "SELECT 1 FROM pg_policies "
            "WHERE schemaname = 'public' AND tablename = 'refresh_tokens' "
            "AND policyname = 'refresh_tokens_tenant_isolation'"
        )
    ).first()
    return row is not None


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Dropping the table removes its indexes; the policy must go first.
        op.execute("DROP POLICY IF EXISTS refresh_tokens_tenant_isolation ON refresh_tokens")
        op.execute("ALTER TABLE refresh_tokens DISABLE ROW LEVEL SECURITY")
        op.drop_table("refresh_tokens")
        if _column_exists(bind, "agent_runs", "last_heartbeat_at"):
            op.drop_column("agent_runs", "last_heartbeat_at")
    else:
        op.drop_table("refresh_tokens")
        if _column_exists(bind, "agent_runs", "last_heartbeat_at"):
            op.drop_column("agent_runs", "last_heartbeat_at")
