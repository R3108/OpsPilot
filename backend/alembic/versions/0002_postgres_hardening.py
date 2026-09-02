"""Postgres-only hardening: pgvector, audit immutability, row-level security.

Everything here is a no-op on other dialects so the test suite (sqlite) runs the
same migration chain the production database does.

Three things happen:

1. **pgvector** — the embedding column is upgraded from JSON to ``vector(1536)``
   with an IVFFlat index, so historical-incident similarity is an index lookup
   rather than a table scan. Skipped when the server has no ``vector`` extension
   available (a bare Postgres install rather than the ``pgvector/pgvector``
   image); the column stays JSONB and ``similarity`` takes its lexical path.
2. **Audit immutability** — a trigger rejects UPDATE and DELETE on
   ``audit_logs``. The application has no such code path, but the trail should
   not depend on the application being correct.
3. **Row-level security** — tenant isolation enforced by the database as defence
   in depth behind the repository layer's ``tenant_id`` filters.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import warnings
from collections.abc import Sequence

from sqlalchemy import text
from sqlalchemy.engine import Connection

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tables that carry tenant_id and therefore get an RLS policy.
TENANT_TABLES = [
    "users",
    "api_keys",
    "incidents",
    "timeline_entries",
    "evidence",
    "hypotheses",
    "agent_runs",
    "agent_steps",
    "verifications",
    "postmortems",
    "remediation_actions",
    "approvals",
    "policy_rules",
    "action_execution_logs",
    "integrations",
    "audit_logs",
    "incident_embeddings",
    "runbooks",
]

AUDIT_GUARD = """
CREATE OR REPLACE FUNCTION opspilot_audit_is_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
"""


def _has_pgvector(bind: Connection) -> bool:
    """Is the ``vector`` extension installable on this server?

    True on the ``pgvector/pgvector`` image the stack ships and on any managed
    Postgres that offers it; false on a plain install, where ``CREATE EXTENSION``
    would abort the whole migration.
    """
    return (
        bind.execute(
            text("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'")
        ).first()
        is not None
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    # -- 1. pgvector ------------------------------------------------------
    if _has_pgvector(bind):
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
        op.execute(
            """
            ALTER TABLE incident_embeddings
                ALTER COLUMN embedding DROP DEFAULT,
                ALTER COLUMN embedding TYPE vector(1536)
                USING NULLIF(embedding::text, '[]')::vector(1536)
            """
        )
        op.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_incident_embeddings_vector
                ON incident_embeddings
                USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100)
            """
        )
    else:
        warnings.warn(
            "pgvector is not available on this server; incident_embeddings.embedding "
            "stays JSONB and similarity search falls back to the lexical path. "
            "Install the extension and re-run this migration for vector search.",
            RuntimeWarning,
            stacklevel=2,
        )

    # -- 2. append-only audit --------------------------------------------
    op.execute(AUDIT_GUARD)
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION opspilot_audit_is_append_only()
        """
    )

    # -- 3. row-level security -------------------------------------------
    # The app sets `SET LOCAL opspilot.tenant_id = '<uuid>'` per transaction.
    # When the setting is absent the policy denies everything, so a missing
    # SET fails closed rather than exposing another tenant's rows.
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                USING (
                    tenant_id = NULLIF(
                        current_setting('opspilot.tenant_id', true), ''
                    )::uuid
                )
            """
        )

    # Useful partial indexes for the hot list queries.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_incidents_active
            ON incidents (tenant_id, created_at DESC)
            WHERE status NOT IN ('closed', 'resolved')
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_approvals_pending
            ON approvals (tenant_id, requested_at)
            WHERE status = 'pending'
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute("DROP INDEX IF EXISTS ix_approvals_pending")
    op.execute("DROP INDEX IF EXISTS ix_incidents_active")

    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS opspilot_audit_is_append_only()")

    op.execute("DROP INDEX IF EXISTS ix_incident_embeddings_vector")
    op.execute("ALTER TABLE incident_embeddings ALTER COLUMN embedding TYPE jsonb USING '[]'::jsonb")
