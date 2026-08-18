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
QUEUE_WORK_CLASS_DEPTH = Gauge(
    "extra_codeowners_queue_work_class_depth",
    "Pending durable work items by kind and scheduling class",
    ("kind", "work_class"),
)
QUEUE_WORK_CLASS_OLDEST_AGE_SECONDS = Gauge(
    "extra_codeowners_queue_work_class_oldest_age_seconds",
    "Age of the oldest pending durable work item by kind and scheduling class",
    ("kind", "work_class"),
)
QUEUE_WAIT_SECONDS = Histogram(
    "extra_codeowners_queue_wait_seconds",
    "Time a ready durable work attempt waits before a worker starts it",
    ("kind", "work_class"),
    buckets=(1, 2.5, 5, 10, 15, 30, 60, 120, 300, 600),
)
WEBHOOK_TO_CHECK_COMPLETION_SECONDS = Histogram(
    "extra_codeowners_webhook_to_check_completion_seconds",
    "Accepted work age when evaluation finishes without a retry",
    ("work_class",),
    buckets=(1, 2.5, 5, 10, 15, 30, 60, 120, 300, 600),
)
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
    "Open pull request reconciliation outcomes",
    ("result",),
)
RECONCILIATION_LAST_SUCCESS = Gauge(
    "extra_codeowners_reconciliation_last_success_timestamp_seconds",
    "Unix timestamp of the latest complete open pull request reconciliation",
)
