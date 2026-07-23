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
        sa.Column("invalidated_generation", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=2000), nullable=True),
        sa.CheckConstraint(
            "generation >= 1",
            name="ck_shared_head_epochs_generation_positive",
        ),
        sa.CheckConstraint(
            "invalidated_generation >= 0 AND invalidated_generation <= generation",
            name="ck_shared_head_epochs_invalidation_bounds",
        ),
        sa.CheckConstraint(
            "attempts >= 0",
            name="ck_shared_head_epochs_attempts_nonnegative",
        ),
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
    op.create_index(
        "ix_shared_head_epochs_claim",
        "shared_head_epochs",
        ["available_at", "lease_until"],
        postgresql_where=sa.text("invalidated_generation < generation"),
        sqlite_where=sa.text("invalidated_generation < generation"),
    )

    op.add_column(
        "evaluation_jobs",
        sa.Column("shared_head_generation", sa.Integer(), nullable=True),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("installation_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("repository_full_name", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("pull_number", sa.Integer(), nullable=True),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("head_sha", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("shared_head_generation", sa.Integer(), nullable=True),
    )
    evaluation_jobs = sa.table(
        "evaluation_jobs",
        sa.column("installation_id", sa.Integer()),
        sa.column("repository_full_name", sa.String(length=512)),
        sa.column("head_sha_hint", sa.String(length=64)),
        sa.column("shared_head_generation", sa.Integer()),
    )
    shared_head_epochs = sa.table(
        "shared_head_epochs",
        sa.column("installation_id", sa.Integer()),
        sa.column("repository_full_name", sa.String(length=512)),
        sa.column("head_sha", sa.String(length=64)),
        sa.column("generation", sa.Integer()),
        sa.column("invalidated_generation", sa.Integer()),
        sa.column("changed_at", sa.DateTime(timezone=True)),
        sa.column("available_at", sa.DateTime(timezone=True)),
        sa.column("attempts", sa.Integer()),
    )
    # A carried direct job may represent a webhook whose synchronous reset
    # failed before the migration. Give each known head durable high-priority
    # invalidation work before the new application can evaluate it.
    op.execute(
        shared_head_epochs.insert().from_select(
            (
                "installation_id",
                "repository_full_name",
                "head_sha",
                "generation",
                "invalidated_generation",
                "changed_at",
                "available_at",
                "attempts",
            ),
            sa.select(
                evaluation_jobs.c.installation_id,
                evaluation_jobs.c.repository_full_name,
                evaluation_jobs.c.head_sha_hint,
                sa.literal(1),
                sa.literal(0),
                sa.func.current_timestamp(),
                sa.func.current_timestamp(),
                sa.literal(0),
            )
            .where(evaluation_jobs.c.head_sha_hint.is_not(None))
            .distinct(),
        )
    )
    op.execute(
        evaluation_jobs.update()
        .where(evaluation_jobs.c.head_sha_hint.is_not(None))
        .values(shared_head_generation=1)
    )
    op.execute(
        evaluation_jobs.update()
        .where(evaluation_jobs.c.head_sha_hint.is_(None))
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
