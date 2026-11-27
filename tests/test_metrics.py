"""Fixed metric labels for webhook deliveries."""

from unittest.mock import Mock

from pytest import MonkeyPatch

from extra_codeowners import metrics


def test_webhook_metrics_use_only_known_labels(monkeypatch: MonkeyPatch) -> None:
    counter = Mock()
    monkeypatch.setattr(metrics, "WEBHOOKS", counter)

    for event, action in (
        ("pull_request", "opened"),
        ("push", ""),
        ("pull_request", "new-action"),
        ("new-event", "opened"),
        ("another-event", "another-action"),
    ):
        metrics.record_webhook(event, action)

    assert [call.args for call in counter.labels.call_args_list] == [
        ("pull_request", "opened"),
        ("push", "received"),
        ("pull_request", "other"),
        ("other", "other"),
        ("other", "other"),
    ]
