"""Classify durable work and retain reconciliation completion fingerprints."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0004_responsive_work_queue"
down_revision: str | None = "0003_shared_head_epochs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add schedulable work classes without weakening existing queue fences."""
    with op.batch_alter_table("evaluation_jobs") as batch:
        batch.add_column(
            sa.Column(
                "work_class",
                sa.String(length=16),
                nullable=True,
            )
        )
    op.execute(sa.text("UPDATE evaluation_jobs SET work_class = 'interactive'"))
    op.execute(
        sa.text(
            "UPDATE evaluation_jobs SET work_class = 'recovery' "
            "WHERE reason = 'periodic_reconciliation'"
        )
    )
    with op.batch_alter_table("evaluation_jobs") as batch:
        batch.alter_column("work_class", existing_type=sa.String(length=16), nullable=False)
        batch.create_check_constraint(
            "ck_evaluation_jobs_work_class",
            "work_class IN ('interactive', 'recovery')",
        )
        batch.drop_index("ix_evaluation_jobs_claim")
        batch.create_index(
            "ix_evaluation_jobs_claim",
            ["state", "work_class", "available_at", "lease_until"],
        )
    with op.batch_alter_table("shared_head_epochs") as batch:
        batch.add_column(
            sa.Column(
                "work_class",
                sa.String(length=16),
                nullable=True,
            )
        )
    op.execute(sa.text("UPDATE shared_head_epochs SET work_class = 'interactive'"))
    with op.batch_alter_table("shared_head_epochs") as batch:
        batch.alter_column("work_class", existing_type=sa.String(length=16), nullable=False)
        batch.create_check_constraint(
            "ck_shared_head_epochs_work_class",
            "work_class IN ('interactive', 'recovery')",
        )
        batch.drop_index("ix_shared_head_epochs_claim")
        batch.create_index(
            "ix_shared_head_epochs_claim",
            ["work_class", "available_at", "lease_until"],
            postgresql_where=sa.text("invalidated_generation < generation"),
            sqlite_where=sa.text("invalidated_generation < generation"),
        )

    op.create_table(
        "reconciliation_states",
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("repository_full_name", sa.String(length=512), nullable=False),
        sa.Column("pull_number", sa.Integer(), nullable=False),
        sa.Column("head_sha", sa.String(length=64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "installation_id",
            "repository_full_name",
            "pull_number",
        ),
    )
    op.create_table(
        "provider_backpressure",
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(length=2000), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("installation_id"),
    )

    schema_metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(
        schema_metadata.update().where(schema_metadata.c.singleton_id == 1).values(version=3)
    )


def downgrade() -> None:
    """Reject a downgrade that could reschedule accepted work incorrectly."""
    raise RuntimeError(
        "responsive queue scheduling cannot be safely downgraded; restore a verified backup"
    )
