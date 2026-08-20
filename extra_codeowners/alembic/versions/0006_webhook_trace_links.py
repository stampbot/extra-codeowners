"""Retain trusted webhook producer context for worker trace links."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0006_webhook_trace_links"
down_revision: str | None = "0005_reconciliation_state_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add optional local producer trace identifiers to retained deliveries."""

    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.add_column(sa.Column("producer_trace_id", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("producer_span_id", sa.String(length=16), nullable=True))
        batch.add_column(sa.Column("producer_trace_flags", sa.Integer(), nullable=True))
    schema_metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(
        schema_metadata.update().where(schema_metadata.c.singleton_id == 1).values(version=5)
    )


def downgrade() -> None:
    """Reject a downgrade that would discard diagnostic evidence."""

    raise RuntimeError(
        "webhook trace-link retention cannot be safely downgraded; restore a verified backup"
    )
