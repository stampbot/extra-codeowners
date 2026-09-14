"""Recheck completions recorded before stale evaluations requeued themselves."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0007_reconciliation_completion"
down_revision: str | None = "0006_webhook_trace_links"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Leave old completions unconfirmed so the next scan rechecks them."""

    with op.batch_alter_table("reconciliation_states") as batch:
        batch.add_column(
            sa.Column("confirmed_completed_at", sa.DateTime(timezone=True), nullable=True)
        )
    schema_metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(
        schema_metadata.update().where(schema_metadata.c.singleton_id == 1).values(version=6)
    )


def downgrade() -> None:
    """Require restoration of the previous application's verified backup."""

    raise RuntimeError(
        "reconciliation completion confirmation cannot be safely downgraded; "
        "restore a verified backup"
    )
