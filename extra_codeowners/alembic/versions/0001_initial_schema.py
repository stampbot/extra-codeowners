"""Create the first explicitly managed database schema."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the durable queue, audit, lease, and compatibility tables."""
    op.create_table(
        "schema_metadata",
        sa.Column("singleton_id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("singleton_id"),
    )
    op.execute(sa.text("INSERT INTO schema_metadata (singleton_id, version) VALUES (1, 1)"))

    op.create_table(
        "evaluation_jobs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("repository_full_name", sa.String(length=512), nullable=False),
        sa.Column("pull_number", sa.Integer(), nullable=False),
        sa.Column("head_sha_hint", sa.String(length=64), nullable=True),
        sa.Column("last_delivery_id", sa.String(length=128), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("authority_generation", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=2000), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "installation_id",
            "repository_full_name",
            "pull_number",
            name="uq_evaluation_job_pr",
        ),
    )
    op.create_index(
        "ix_evaluation_jobs_claim",
        "evaluation_jobs",
        ["state", "available_at", "lease_until"],
    )

    op.create_table(
        "webhook_deliveries",
        sa.Column("delivery_id", sa.String(length=128), nullable=False),
        sa.Column("event", sa.String(length=128), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invalidation_required", sa.Boolean(), nullable=False),
        sa.Column("invalidation_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("delivery_id"),
    )
    op.create_index(
        "ix_webhook_deliveries_received_at",
        "webhook_deliveries",
        ["received_at"],
    )

    op.create_table(
        "evaluation_audits",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("repository_full_name", sa.String(length=512), nullable=False),
        sa.Column("pull_number", sa.Integer(), nullable=False),
        sa.Column("head_sha", sa.String(length=64), nullable=False),
        sa.Column("conclusion", sa.String(length=32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "repository_full_name",
            "pull_number",
            name="uq_evaluation_audit_pr",
        ),
    )

    op.create_table(
        "service_leases",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )

    op.create_table(
        "authority_jobs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("scope_key", sa.String(length=512), nullable=False),
        sa.Column("base_ref", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=2000), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "installation_id",
            "scope_key",
            "base_ref",
            name="uq_authority_job_scope",
        ),
    )
    op.create_index(
        "ix_authority_jobs_claim",
        "authority_jobs",
        ["state", "available_at", "lease_until"],
    )

    op.create_table(
        "authority_epochs",
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("installation_id"),
    )


def downgrade() -> None:
    """Reject destructive in-place downgrades; restore a verified backup instead."""
    raise RuntimeError("the initial schema is forward-only; restore a verified backup to remove it")
