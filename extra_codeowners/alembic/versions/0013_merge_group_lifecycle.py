"""Keep terminal candidate history out of the queue and retain recheck deadlines."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0013_merge_group_lifecycle"
down_revision: str | None = "0012_merge_candidate_recheck"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "merge_group_work", sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "merge_group_work",
        sa.Column("recheck_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    work = sa.table(
        "merge_group_work",
        sa.column("recheck_check_id", sa.BigInteger()),
        sa.column("recheck_due_at", sa.DateTime(timezone=True)),
        sa.column("available_at", sa.DateTime(timezone=True)),
    )
    op.execute(
        work.update().where(work.c.recheck_check_id > 0).values(recheck_due_at=work.c.available_at)
    )
    op.drop_index("ix_merge_group_claim", table_name="merge_group_work")
    pending = sa.text("completed_generation < generation")
    op.create_index(
        "ix_merge_group_claim",
        "merge_group_work",
        ["available_at", "lease_until"],
        sqlite_where=pending,
        postgresql_where=pending,
    )
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=12))


def downgrade() -> None:
    raise RuntimeError("candidate retirement cannot be safely downgraded; restore a backup")
