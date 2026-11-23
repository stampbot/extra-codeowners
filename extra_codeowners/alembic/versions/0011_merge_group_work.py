"""Persist candidate work and fence cancelled or superseded attempts."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0011_merge_group_work"
down_revision: str | None = "0010_authority_discovery_cursor"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "webhook_deliveries", sa.Column("merge_group_digest", sa.String(64), nullable=True)
    )
    op.create_table(
        "merge_group_work",
        sa.Column("installation_id", sa.BigInteger(), primary_key=True),
        sa.Column("repository_id", sa.BigInteger(), primary_key=True),
        sa.Column("head_sha", sa.String(40), primary_key=True),
        sa.Column("repository_full_name", sa.String(512), nullable=False),
        sa.Column("base_ref", sa.String(1024), nullable=False),
        sa.Column("base_sha", sa.String(40), nullable=False),
        sa.Column("head_ref", sa.String(1024), nullable=False),
        sa.Column("destroyed", sa.Boolean(), nullable=False),
        sa.Column("pull_number", sa.BigInteger(), nullable=True),
        sa.Column("entry_id", sa.String(256), nullable=True),
        sa.Column("pull_id", sa.String(256), nullable=True),
        sa.Column("pull_head_sha", sa.String(40), nullable=True),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("completed_generation", sa.BigInteger(), nullable=False),
        sa.Column("attempts", sa.BigInteger(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "generation >= 1 AND completed_generation >= 0 AND completed_generation <= generation",
            name="ck_merge_group_generation",
        ),
    )
    op.create_index("ix_merge_group_claim", "merge_group_work", ["available_at", "lease_until"])
    op.create_index(
        "ix_merge_group_pull",
        "merge_group_work",
        ["installation_id", "repository_full_name", "pull_number"],
    )
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=10))


def downgrade() -> None:
    raise RuntimeError("merge group work cannot be safely downgraded; restore a verified backup")
