"""Prometheus metrics exposed by the service."""

from prometheus_client import Counter, Gauge, Histogram

WEBHOOKS = Counter(
    "extra_codeowners_webhooks_total",
    "Verified GitHub webhook deliveries",
    ("event", "action"),
)
WEBHOOK_FAILURES = Counter(
    "extra_codeowners_webhook_failures_total",
    "Rejected or failed GitHub webhook deliveries",
    ("reason",),
)
EVALUATIONS = Counter(
    "extra_codeowners_evaluations_total",
    "Pull request policy evaluations",
    ("conclusion",),
)
EVALUATION_SECONDS = Histogram(
    "extra_codeowners_evaluation_seconds",
    "Time spent evaluating one pull request",
)
QUEUE_DEPTH = Gauge("extra_codeowners_queue_depth", "Pending durable work items")
SHARED_HEAD_INVALIDATION_DEPTH = Gauge(
    "extra_codeowners_shared_head_invalidation_depth",
    "Exact commit generations awaiting durable Check Run invalidation",
)
SHARED_HEAD_INVALIDATIONS = Counter(
    "extra_codeowners_shared_head_invalidations_total",
    "Durable exact-head invalidation attempts",
    ("result",),
)
DEAD_JOBS = Gauge(
    "extra_codeowners_dead_jobs",
    "Legacy terminal rows that startup should automatically reactivate",
)
INSECURE_MODE = Gauge(
    "extra_codeowners_insecure_changes_enabled",
    "Whether built-in non-delegable paths are disabled",
)
RECONCILIATIONS = Counter(
    "extra_codeowners_reconciliations_total",
    "Completed open pull request reconciliation attempts",
    ("result",),
)
RECONCILIATION_LAST_SUCCESS = Gauge(
    "extra_codeowners_reconciliation_last_success_timestamp_seconds",
    "Unix timestamp of the latest successful open pull request reconciliation",
)
