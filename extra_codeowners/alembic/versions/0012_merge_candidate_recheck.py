"""Schedule rechecks only for newly confirmed passing candidates."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0012_merge_candidate_recheck"
down_revision: str | None = "0011_merge_group_work"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("merge_group_work", sa.Column("recheck_check_id", sa.BigInteger(), nullable=True))
    active = sa.text("recheck_check_id > 0")
    op.create_index(
        "ix_merge_group_recheck",
        "merge_group_work",
        ["repository_id", "available_at"],
        sqlite_where=active,
        postgresql_where=active,
    )
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=11))


def downgrade() -> None:
    raise RuntimeError(
        "candidate recheck state cannot be safely downgraded; restore a verified backup"
    )
