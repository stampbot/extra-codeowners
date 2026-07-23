"""Fence Check Run publication across pull requests sharing one head."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0003_shared_head_epochs"
down_revision: str | None = "0002_retry_dead_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add durable commit-scoped epochs and bind queued evaluations to them."""
    op.create_table(
        "shared_head_epochs",
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("repository_full_name", sa.String(length=512), nullable=False),
        sa.Column("head_sha", sa.String(length=64), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "installation_id",
            "repository_full_name",
            "head_sha",
        ),
    )
    op.create_index(
        "ix_shared_head_epochs_changed_at",
        "shared_head_epochs",
        ["changed_at"],
    )

    op.add_column(
        "evaluation_jobs",
        sa.Column("shared_head_generation", sa.Integer(), nullable=True),
    )
    evaluation_jobs = sa.table(
        "evaluation_jobs",
        sa.column("shared_head_generation", sa.Integer()),
    )
    op.execute(
        evaluation_jobs.update()
        .where(evaluation_jobs.c.shared_head_generation.is_(None))
        .values(shared_head_generation=0)
    )
    with op.batch_alter_table("evaluation_jobs") as batch:
        batch.alter_column(
            "shared_head_generation",
            existing_type=sa.Integer(),
            nullable=False,
        )

    schema_metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(
        schema_metadata.update().where(schema_metadata.c.singleton_id == 1).values(version=2)
    )


def downgrade() -> None:
    """Reject a rollback that could erase an accepted publication fence."""
    raise RuntimeError(
        "shared-head publication fences cannot be safely downgraded; "
        "restore a verified pre-migration backup"
    )
