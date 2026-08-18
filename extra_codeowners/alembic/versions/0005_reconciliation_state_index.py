"""Classify carried recovery fences and bound reconciliation retention cleanup."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

__all__ = ("branch_labels", "depends_on", "down_revision", "revision")

revision: str = "0005_reconciliation_state_index"
down_revision: str | None = "0004_responsive_work_queue"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Keep carried recovery work out of foreground lanes and bound cleanup."""
    # Revision 0004 had to classify carried jobs before it could add the
    # work_class column to shared-head epochs. Finish that classification here:
    # an epoch is recovery work only when at least one carried evaluation for
    # the same head is recovery and none is direct evidence. Any ambiguity is
    # intentionally interactive, which preserves the fail-closed fence.
    op.execute(
        sa.text(
            """
            UPDATE shared_head_epochs
            SET work_class = 'recovery'
            WHERE EXISTS (
                SELECT 1
                FROM evaluation_jobs
                WHERE evaluation_jobs.installation_id = shared_head_epochs.installation_id
                  AND evaluation_jobs.repository_full_name = shared_head_epochs.repository_full_name
                  AND evaluation_jobs.head_sha_hint = shared_head_epochs.head_sha
                  AND evaluation_jobs.work_class = 'recovery'
            )
              AND NOT EXISTS (
                SELECT 1
                FROM evaluation_jobs
                WHERE evaluation_jobs.installation_id = shared_head_epochs.installation_id
                  AND evaluation_jobs.repository_full_name = shared_head_epochs.repository_full_name
                  AND evaluation_jobs.head_sha_hint = shared_head_epochs.head_sha
                  AND evaluation_jobs.work_class = 'interactive'
            )
            """
        )
    )
    op.create_index(
        "ix_reconciliation_states_observed_at",
        "reconciliation_states",
        ["observed_at"],
    )
    schema_metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(
        schema_metadata.update().where(schema_metadata.c.singleton_id == 1).values(version=4)
    )


def downgrade() -> None:
    """Reject a downgrade that could leave retention unbounded."""
    raise RuntimeError(
        "reconciliation retention indexing cannot be safely downgraded; restore a verified backup"
    )
