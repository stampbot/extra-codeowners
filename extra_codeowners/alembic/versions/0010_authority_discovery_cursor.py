"""Resume authority discovery after a completed prefix across quota windows."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import groupby
from typing import Any

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
    op.add_column("authority_jobs", sa.Column("target_base_refs", sa.JSON(), nullable=True))
    op.add_column("authority_jobs", sa.Column("pending_full_rescan", sa.Boolean(), nullable=True))
    op.add_column(
        "authority_jobs", sa.Column("pending_rescan_reason", sa.String(255), nullable=True)
    )
    op.add_column(
        "authority_jobs", sa.Column("listing_expected_total", sa.Integer(), nullable=True)
    )
    jobs = sa.table(
        "authority_jobs",
        sa.column("id", sa.Integer()),
        sa.column("installation_id", sa.Integer()),
        sa.column("scope_key", sa.String(512)),
        sa.column("base_ref", sa.String(255)),
        sa.column("reason", sa.String(255)),
        sa.column("generation", sa.Integer()),
        sa.column("state", sa.String(16)),
        sa.column("attempts", sa.Integer()),
        sa.column("requested_at", sa.DateTime(timezone=True)),
        sa.column("available_at", sa.DateTime(timezone=True)),
        sa.column("lease_owner", sa.String(128)),
        sa.column("lease_until", sa.DateTime(timezone=True)),
        sa.column("last_error", sa.String(2000)),
        sa.column("pull_cursor_number", sa.BigInteger()),
        sa.column("handled_pull_fingerprints", sa.JSON()),
        sa.column("listing_next_page", sa.Integer()),
        sa.column("listing_last_number", sa.BigInteger()),
        sa.column("interactive_wake_generation", sa.Integer()),
        sa.column("pending_base_refs", sa.JSON()),
        sa.column("target_base_refs", sa.JSON()),
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
            target_base_refs={},
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
        batch.alter_column("target_base_refs", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("pending_full_rescan", existing_type=sa.Boolean(), nullable=False)
        batch.alter_column("membership_next_page", existing_type=sa.Integer(), nullable=False)
    # Old workers must be drained before this migration. Consolidate their
    # accepted branch work too, rather than leaving a separate history scan
    # per old branch. The whole migration retains its transaction boundary.
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(jobs)
        .where(jobs.c.scope_key != "*")
        .order_by(jobs.c.installation_id, jobs.c.scope_key, jobs.c.id)
    ).mappings()
    for _, group in groupby(rows, key=lambda row: (row["installation_id"], row["scope_key"])):
        pending = list(group)
        broad = next((row for row in pending if not row["base_ref"]), None)
        if len(pending) == 1 and broad is not None:
            continue
        retained = broad if broad is not None else pending[0]
        targets = {row["base_ref"]: row["reason"] for row in pending if row["base_ref"]}
        if broad is not None or len(targets) > 100 or any(len(ref) > 255 for ref in targets):
            targets = {}
        removed_ids = [row["id"] for row in pending if row["id"] != retained["id"]]
        if removed_ids:
            connection.execute(jobs.delete().where(jobs.c.id.in_(removed_ids)))
        values: dict[str, Any] = {"base_ref": "", "target_base_refs": targets}
        if len(pending) > 1:
            values.update(
                generation=max(row["generation"] for row in pending) + 1,
                state=(
                    "pending"
                    if any(row["state"] in {"pending", "in_progress"} for row in pending)
                    else retained["state"]
                ),
                attempts=0,
                requested_at=min(row["requested_at"] for row in pending),
                available_at=min(row["available_at"] for row in pending),
                lease_owner=None,
                lease_until=None,
                last_error=None,
            )
        connection.execute(jobs.update().where(jobs.c.id == retained["id"]).values(**values))
    metadata = sa.table(
        "schema_metadata",
        sa.column("singleton_id", sa.Integer()),
        sa.column("version", sa.Integer()),
    )
    op.execute(metadata.update().where(metadata.c.singleton_id == 1).values(version=9))


def downgrade() -> None:
    raise RuntimeError("authority progress cannot be safely downgraded; restore a verified backup")
