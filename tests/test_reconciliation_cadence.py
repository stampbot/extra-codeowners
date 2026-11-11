"""Check polling deadlines without sleeping or changing durable accounting."""

from __future__ import annotations

import pytest

from extra_codeowners.reconciliation_cadence import ReconciliationCadence


def test_retry_only_visits_deferred_installation_and_completes_the_cycle() -> None:
    now = 0.0
    cadence = ReconciliationCadence(lambda: now)
    assert cadence.begin([1, 2]) == {1, 2}
    cadence.record(1, 300, complete=True)
    cadence.record(2, 60, complete=False)
    assert not cadence.finish()
    assert cadence.delay(300) == 60

    now = 60
    assert cadence.begin([1, 2]) == {2}
    cadence.record(2, 300, complete=True)
    assert cadence.finish()
    assert cadence.delay(300) == 240
    assert not cadence.finish()
    assert cadence.begin([1, 2]) == set()
    assert not cadence.finish()

    # A new cycle needs both installations, even when their deadlines differ.
    now = 300
    assert cadence.begin([1, 2]) == {1}
    cadence.record(1, 300, complete=True)
    assert not cadence.finish()
    now = 360
    assert cadence.begin([1, 2]) == {2}
    cadence.record(2, 300, complete=True)
    assert cadence.finish()


def test_elapsed_retry_is_not_restarted_after_a_slow_other_installation() -> None:
    now = 0.0
    cadence = ReconciliationCadence(lambda: now)
    cadence.begin([1, 2])
    cadence.record(1, 60, complete=False)
    now = 180
    cadence.record(2, 300, complete=True)
    assert not cadence.finish()
    assert cadence.delay(300) == 1
    assert cadence.begin([1, 2]) == {1}


def test_later_failure_invalidates_an_installations_earlier_cycle_completion() -> None:
    now = 0.0
    cadence = ReconciliationCadence(lambda: now)
    cadence.begin([1, 2])
    cadence.record(1, 300, complete=True)
    cadence.record(2, 600, complete=False)
    now = 300
    assert cadence.begin([1, 2]) == {1}
    cadence.record(1, 600, complete=False)
    now = 600
    assert cadence.begin([1, 2]) == {2}
    cadence.record(2, 300, complete=True)
    assert not cadence.finish()


def test_validated_scope_changes_update_cycle_membership() -> None:
    now = 0.0
    cadence = ReconciliationCadence(lambda: now)
    cadence.begin([1, 2])
    cadence.record(1, 300, complete=True)
    cadence.record(2, 60, complete=False)
    now = 60
    # A new installation must complete; the removed installation cannot block.
    assert cadence.begin([1, 3]) == {3}
    assert not cadence.finish()
    cadence.record(3, 300, complete=True)
    assert cadence.finish()
    # A re-added installation is due immediately, not at its old deadline.
    assert cadence.begin([1, 2, 3]) == {2}
    cadence.record(2, 300, complete=True)
    assert not cadence.finish()


def test_reset_discards_deadlines_and_partial_cycle_evidence() -> None:
    cadence = ReconciliationCadence(lambda: 0)
    cadence.begin([1, 2])
    cadence.record(1, 300, complete=True)
    cadence.record(2, 60, complete=False)
    cadence.reset()
    assert cadence.begin([1, 2]) == {1, 2}
    cadence.record(2, 300, complete=True)
    assert not cadence.finish()


def test_long_deferral_still_bounds_app_scope_discovery() -> None:
    cadence = ReconciliationCadence(lambda: 0)
    cadence.begin([1])
    cadence.record(1, 86_401, complete=False)
    assert cadence.delay(300) == 300
    assert cadence.begin([1]) == set()
    assert not cadence.finish()


def test_empty_scope_completes_a_cycle_without_spinning() -> None:
    cadence = ReconciliationCadence(lambda: 0)
    assert cadence.begin([]) == set()
    assert cadence.finish()
    assert not cadence.finish()
    assert cadence.delay(300) == 300


@pytest.mark.parametrize("delay", [0, -1, True, 0.5, float("nan"), 86_402])
def test_invalid_delay_is_rejected(delay: int) -> None:
    cadence = ReconciliationCadence(lambda: 0)
    cadence.begin([1])
    with pytest.raises(ValueError, match="reconciliation delay"):
        cadence.record(1, delay, complete=True)


def test_record_requires_an_active_cycle() -> None:
    cadence = ReconciliationCadence(lambda: 0)
    with pytest.raises(RuntimeError, match="cycle has not started"):
        cadence.record(1, 60, complete=True)
