"""Persist the latest evaluation evidence in its own transaction."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from extra_codeowners.database_metadata import Base, utcnow


class EvaluationAudit(Base):
    """Most recent evaluation evidence for operations and debugging."""

    __tablename__ = "evaluation_audits"
    __table_args__ = (
        UniqueConstraint("repository_full_name", "pull_number", name="uq_evaluation_audit_pr"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    pull_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    conclusion: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


def record_audit(
    sessions: sessionmaker[Session],
    repository_full_name: str,
    pull_number: int,
    head_sha: str,
    conclusion: str,
    details: dict[str, Any],
) -> None:
    """Upsert the most recent evaluation evidence."""
    with sessions.begin() as session:
        row = session.scalar(
            select(EvaluationAudit).where(
                EvaluationAudit.repository_full_name == repository_full_name,
                EvaluationAudit.pull_number == pull_number,
            )
        )
        if row is None:
            session.add(
                EvaluationAudit(
                    repository_full_name=repository_full_name,
                    pull_number=pull_number,
                    head_sha=head_sha,
                    conclusion=conclusion,
                    details=details,
                )
            )
        else:
            row.head_sha = head_sha
            row.conclusion = conclusion
            row.details = details
            row.evaluated_at = utcnow()
