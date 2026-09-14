"""Coordinate recovery API spending and repository discovery across replicas."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0008_recovery_api_budget"
down_revision: str | None = "0007_reconciliation_completion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "installation_api_budgets",
        sa.Column("installation_id", sa.Integer(), primary_key=True),
        sa.Column("request_limit", sa.Integer(), nullable=False),
        sa.Column("remaining", sa.Integer(), nullable=False),
        sa.Column("reset_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("probe_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("repository_cursor", sa.String(512), nullable=False),
    )
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=7))


def downgrade() -> None:
    raise RuntimeError(
        "recovery API budgets cannot be safely downgraded; restore a verified backup"
    )
