"""Index reconciliation retention cleanup by observation time."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0005_reconciliation_state_index"
down_revision: str | None = "0004_responsive_work_queue"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Keep bounded retention cleanup within the database statement timeout."""
    op.create_index(
        "ix_reconciliation_states_observed_at",
        "reconciliation_states",
        ["observed_at"],
    )
    schema_metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(
        schema_metadata.update().where(schema_metadata.c.singleton_id == 1).values(version=4)
    )


def downgrade() -> None:
    """Reject a downgrade that could leave retention unbounded."""
    raise RuntimeError(
        "reconciliation retention indexing cannot be safely downgraded; restore a verified backup"
    )
