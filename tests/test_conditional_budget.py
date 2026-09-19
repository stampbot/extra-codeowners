from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta
from os import environ
from pathlib import Path

import pytest
from sqlalchemy import text, update
from sqlalchemy.engine import make_url

from extra_codeowners.api_budget import BudgetReceipt, CoreQuota, RecoveryApiBudget
from extra_codeowners.database import Base, InstallationApiBudget, QueueStore, utcnow
from extra_codeowners.migrations import upgrade_database


@pytest.fixture(params=["sqlite", "postgresql"])
def budget_store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[QueueStore]:
    url = f"sqlite:///{tmp_path / 'conditional-budget.db'}"
    if request.param == "postgresql":
        request.node.add_marker(pytest.mark.integration)
        url = environ.get("TEST_POSTGRES_URL", "")
        if not url:
            pytest.skip("TEST_POSTGRES_URL is not configured")
        database = make_url(url).database
        assert database is not None and database.endswith("_test")
    store = QueueStore(url)
    if request.param == "postgresql":
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database(url)
    store.initialize()
    try:
        yield store
    finally:
        store.close()


def known_quota(remaining: int = 90, *, reset_at: datetime | None = None) -> CoreQuota:
    return CoreQuota(100, remaining, reset_at or utcnow() + timedelta(hours=1))


def establish(
    budget_store: QueueStore, installation_id: int = 17
) -> tuple[RecoveryApiBudget, BudgetReceipt]:
    budget = RecoveryApiBudget(budget_store)
    budget.observe(installation_id, known_quota())
    receipt = budget.admit(installation_id, recovery=False)
    assert receipt is not None
    return budget, receipt


def row(store: QueueStore, installation_id: int = 17) -> InstallationApiBudget:
    with store.session() as session:
        value = session.get(InstallationApiBudget, installation_id)
        assert value is not None
        return value


def test_valid_refund_is_single_use_and_requires_higher_provider_balance(
    budget_store: QueueStore,
) -> None:
    budget, receipt = establish(budget_store)
    budget.observe(17, known_quota(90), not_modified_receipt=receipt)
    assert row(budget_store).remaining == 90
    budget.observe(17, known_quota(90), not_modified_receipt=receipt)
    assert row(budget_store).remaining == 90

    budget, receipt = establish(budget_store, 18)
    budget.observe(18, known_quota(88), not_modified_receipt=receipt)
    assert row(budget_store, 18).remaining == 88


def test_concurrent_refund_and_intervening_admission_are_fenced(budget_store: QueueStore) -> None:
    budget, receipt = establish(budget_store)
    peer = RecoveryApiBudget(budget_store)

    def refund() -> None:
        budget.observe(17, known_quota(90), not_modified_receipt=receipt)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: refund(), range(2)))
    assert row(budget_store).remaining == 90

    budget, receipt = establish(budget_store, 18)
    peer.admit(18, recovery=False)
    budget.observe(18, known_quota(90), not_modified_receipt=receipt)
    assert row(budget_store, 18).remaining == 88


def test_wrong_installation_reset_and_expired_receipts_cannot_refund(
    budget_store: QueueStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    budget, receipt = establish(budget_store)
    budget.observe(18, known_quota(90), not_modified_receipt=receipt)
    assert row(budget_store).remaining == 89

    other = RecoveryApiBudget(budget_store)
    other.observe(18, known_quota(90), not_modified_receipt=receipt)
    assert row(budget_store).remaining == 89

    # A receipt from a different window is rejected even while the current
    # window is still live.
    wrong_window = BudgetReceipt(17, receipt.reset_at + timedelta(seconds=1), receipt.revision)
    budget.observe(17, known_quota(90), not_modified_receipt=wrong_window)
    assert row(budget_store).remaining == 89

    # At the exact reset boundary the receipt is expired and cannot refund.
    now = utcnow().replace(microsecond=0)
    with budget_store.session() as session:
        session.execute(
            update(InstallationApiBudget)
            .where(InstallationApiBudget.installation_id == 17)
            .values(reset_at=now)
        )
    monkeypatch.setattr("extra_codeowners.api_budget.utcnow", lambda: now)
    budget.observe(
        17,
        known_quota(89, reset_at=now + timedelta(seconds=1)),
        not_modified_receipt=receipt,
    )
    assert row(budget_store).remaining == 89


def test_unknown_probe_returns_none_and_out_of_order_observation_invalidates_receipt(
    budget_store: QueueStore,
) -> None:
    budget = RecoveryApiBudget(budget_store)
    assert budget.admit(17, recovery=True) is None
    assert row(budget_store).remaining == 0

    budget.observe(17, known_quota(90))
    receipt = budget.admit(17, recovery=False)
    assert receipt is not None
    budget.observe(17, known_quota(89))
    budget.observe(17, known_quota(90), not_modified_receipt=receipt)
    assert row(budget_store).remaining == 89


def test_receipt_reset_window_is_exact_and_immutable(budget_store: QueueStore) -> None:
    _, receipt = establish(budget_store)
    assert receipt == BudgetReceipt(receipt.installation_id, receipt.reset_at, receipt.revision)
    with pytest.raises(FrozenInstanceError):
        receipt.revision = 0  # type: ignore[misc]
