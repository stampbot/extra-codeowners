"""A continuation may omit completed work, but cannot invent current scope."""

from extra_codeowners.reconciliation_sweep import ReconciliationSweeps


def test_short_continuation_skips_only_completed_current_repository_identities() -> None:
    sweeps = ReconciliationSweeps(lambda: 0)
    scope = {"example/a": 101, "example/b": 102}
    assert sweeps.begin(1, scope, lifetime_seconds=900) == set()
    sweeps.complete_repository(1, "example/a", 101)
    assert sweeps.begin(1, scope, lifetime_seconds=900) == {"example/a"}
    # A new route or a recreated repository at the same route is fresh work.
    assert sweeps.begin(1, {"example/a": 103}, lifetime_seconds=900) == set()
    sweeps.complete_repository(1, "example/a", 103)
    assert sweeps.begin(1, {"example/renamed": 103}, lifetime_seconds=900) == set()


def test_removed_scope_missing_identity_and_new_cycle_cannot_keep_skips() -> None:
    sweeps = ReconciliationSweeps(lambda: 0)
    sweeps.begin(1, {"example/a": 101}, lifetime_seconds=900)
    sweeps.complete_repository(1, "example/a", 101)
    assert sweeps.begin(1, {}, lifetime_seconds=900) == set()
    assert sweeps.begin(1, {"example/a": 101}, lifetime_seconds=900) == set()
    sweeps.complete_repository(1, "example/a", 101)
    sweeps.finish(1)
    assert sweeps.begin(1, {"example/a": 101}, lifetime_seconds=900) == set()


def test_progress_expires_even_when_a_sweep_never_finishes() -> None:
    now = 0.0
    sweeps = ReconciliationSweeps(lambda: now)
    scope = {"example/a": 101}
    sweeps.begin(1, scope, lifetime_seconds=900)
    sweeps.complete_repository(1, "example/a", 101)
    now = 899
    assert sweeps.begin(1, scope, lifetime_seconds=900) == {"example/a"}
    now = 900
    assert sweeps.begin(1, scope, lifetime_seconds=900) == set()


def test_leader_loss_and_installation_removal_forget_advisory_progress() -> None:
    sweeps = ReconciliationSweeps(lambda: 0)
    scope = {"example/a": 101}
    for installation in (1, 2):
        sweeps.begin(installation, scope, lifetime_seconds=900)
        sweeps.complete_repository(installation, "example/a", 101)
    sweeps.retain([2])
    assert sweeps.begin(1, scope, lifetime_seconds=900) == set()
    assert sweeps.begin(2, scope, lifetime_seconds=900) == {"example/a"}
    sweeps.reset()
    assert sweeps.begin(2, scope, lifetime_seconds=900) == set()
