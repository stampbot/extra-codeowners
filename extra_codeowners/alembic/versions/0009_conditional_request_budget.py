"""Fence conditional-request refunds against concurrent quota accounting."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0009_conditional_request_budget"
down_revision: str | None = "0008_recovery_api_budget"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "installation_api_budgets",
        sa.Column("accounting_revision", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "installation_api_budgets",
        sa.Column("pull_cursor_repository", sa.String(512), nullable=True),
    )
    op.add_column(
        "installation_api_budgets",
        sa.Column("pull_cursor_number", sa.BigInteger(), nullable=True),
    )
    budgets = sa.table(
        "installation_api_budgets",
        sa.column("accounting_revision", sa.BigInteger()),
        sa.column("pull_cursor_repository", sa.String(512)),
        sa.column("pull_cursor_number", sa.BigInteger()),
    )
    op.execute(
        budgets.update().values(
            accounting_revision=0, pull_cursor_repository="", pull_cursor_number=0
        )
    )
    with op.batch_alter_table("installation_api_budgets") as batch:
        batch.alter_column("accounting_revision", existing_type=sa.BigInteger(), nullable=False)
        batch.alter_column("pull_cursor_repository", existing_type=sa.String(512), nullable=False)
        batch.alter_column("pull_cursor_number", existing_type=sa.BigInteger(), nullable=False)
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=8))


def downgrade() -> None:
    raise RuntimeError(
        "conditional-request accounting cannot be safely downgraded; restore a verified backup"
    )
