"""Initial schema.

Created from the declarative metadata rather than a transcribed autogenerate
diff. For revision 1 this is both shorter and *more* correct: the dialect
variants declared on the models (JSONB on Postgres, JSON on sqlite) are applied
by the dialect itself, so the same migration produces the right column types on
either backend, and there is no risk of the migration drifting from the models
before the first release.

Every migration after this one is a normal ``alembic revision --autogenerate``.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from app.models import Base

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
