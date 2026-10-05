"""Resume authority discovery after a completed prefix across quota windows."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0010_authority_discovery_cursor"
down_revision: str | None = "0009_conditional_request_budget"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("evaluation_jobs", sa.Column("base_ref_hint", sa.String(255), nullable=True))
    op.add_column("authority_jobs", sa.Column("membership_next_page", sa.Integer(), nullable=True))
    op.add_column(
        "authority_jobs", sa.Column("membership_expected_total", sa.Integer(), nullable=True)
    )
    op.add_column("authority_jobs", sa.Column("pull_cursor_number", sa.BigInteger(), nullable=True))
    op.add_column(
        "authority_jobs", sa.Column("handled_pull_fingerprints", sa.JSON(), nullable=True)
    )
    op.add_column("authority_jobs", sa.Column("listing_next_page", sa.Integer(), nullable=True))
    op.add_column(
        "authority_jobs", sa.Column("listing_last_number", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "authority_jobs", sa.Column("interactive_wake_generation", sa.Integer(), nullable=True)
    )
    op.add_column("authority_jobs", sa.Column("pending_base_refs", sa.JSON(), nullable=True))
    op.add_column("authority_jobs", sa.Column("pending_full_rescan", sa.Boolean(), nullable=True))
    op.add_column(
        "authority_jobs", sa.Column("pending_rescan_reason", sa.String(255), nullable=True)
    )
    op.add_column(
        "authority_jobs", sa.Column("listing_expected_total", sa.Integer(), nullable=True)
    )
    jobs = sa.table(
        "authority_jobs",
        sa.column("pull_cursor_number", sa.BigInteger()),
        sa.column("handled_pull_fingerprints", sa.JSON()),
        sa.column("listing_next_page", sa.Integer()),
        sa.column("listing_last_number", sa.BigInteger()),
        sa.column("interactive_wake_generation", sa.Integer()),
        sa.column("pending_base_refs", sa.JSON()),
        sa.column("pending_full_rescan", sa.Boolean()),
        sa.column("membership_next_page", sa.Integer()),
    )
    op.execute(
        jobs.update().values(
            pull_cursor_number=0,
            handled_pull_fingerprints={},
            listing_next_page=1,
            listing_last_number=0,
            interactive_wake_generation=0,
            pending_base_refs={},
            pending_full_rescan=False,
            membership_next_page=1,
        )
    )
    with op.batch_alter_table("authority_jobs") as batch:
        batch.alter_column("pull_cursor_number", existing_type=sa.BigInteger(), nullable=False)
        batch.alter_column("handled_pull_fingerprints", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("listing_next_page", existing_type=sa.Integer(), nullable=False)
        batch.alter_column("listing_last_number", existing_type=sa.BigInteger(), nullable=False)
        batch.alter_column(
            "interactive_wake_generation", existing_type=sa.Integer(), nullable=False
        )
        batch.alter_column("pending_base_refs", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("pending_full_rescan", existing_type=sa.Boolean(), nullable=False)
        batch.alter_column("membership_next_page", existing_type=sa.Integer(), nullable=False)
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=9))


def downgrade() -> None:
    raise RuntimeError("authority progress cannot be safely downgraded; restore a verified backup")
