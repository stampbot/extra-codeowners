"""Reactivate terminal jobs produced by pre-release builds."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_retry_dead_jobs"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Return legacy dead jobs to the durable retry queue transactionally."""
    now = sa.func.now()
    for table_name in ("authority_jobs", "evaluation_jobs"):
        table = sa.table(
            table_name,
            sa.column("state", sa.String()),
            sa.column("attempts", sa.Integer()),
            sa.column("available_at", sa.DateTime(timezone=True)),
            sa.column("lease_owner", sa.String()),
            sa.column("lease_until", sa.DateTime(timezone=True)),
            sa.column("last_error", sa.String()),
        )
        op.execute(
            table.update()
            .where(table.c.state == "dead")
            .values(
                state="pending",
                attempts=0,
                available_at=now,
                lease_owner=None,
                lease_until=None,
                last_error=None,
            )
        )


def downgrade() -> None:
    """Leave reactivated work intact because its former state cannot be reconstructed."""
    raise RuntimeError("reactivated queue rows cannot be safely downgraded")
