"""Allow an admin to clear the audit trail.

Migration ``0002`` installed a trigger rejecting both UPDATE and DELETE on
``audit_logs``. This narrows that guard to UPDATE only, so the "Clear audit log"
admin action can delete rows.

What is given up: the trail is no longer proof of what happened, because an
admin can now erase the record of their own actions. What is kept: existing rows
still cannot be *edited*, so an entry that survives a clear is still verbatim
what was written. That is a weaker property than append-only and should not be
described as append-only. See ``docs/SAFETY.md``.

Like ``0002`` this is a no-op on non-Postgres dialects, so the sqlite test suite
runs the same chain.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same function name as 0002 so the chain has one guard, not two; only the
# message and the trigger's event list change.
NO_UPDATE_GUARD = """
CREATE OR REPLACE FUNCTION opspilot_audit_is_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs rows are immutable; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

APPEND_ONLY_GUARD = """
CREATE OR REPLACE FUNCTION opspilot_audit_is_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
    op.execute(NO_UPDATE_GUARD)
    op.execute(
        """
        CREATE TRIGGER audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION opspilot_audit_is_append_only()
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs")
    op.execute(APPEND_ONLY_GUARD)
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION opspilot_audit_is_append_only()
        """
    )
