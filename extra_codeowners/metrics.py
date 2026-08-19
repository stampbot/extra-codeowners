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
    buckets=(0.1, 0.5, 1, 2.5, 5, 10, 15, 30, 60, 120, 300, 600),
)
WORK_ATTEMPTS = Counter(
    "extra_codeowners_work_attempts_total",
    "Durable worker attempts by work kind, scheduling class, and outcome",
    ("kind", "work_class", "outcome"),
)
WORK_ATTEMPT_SECONDS = Histogram(
    "extra_codeowners_work_attempt_seconds",
    "Wall-clock time spent on one durable worker attempt",
    ("kind", "work_class", "outcome"),
    buckets=(0.1, 0.5, 1, 2.5, 5, 10, 15, 30, 60, 120, 300, 600),
)
GITHUB_API_REQUESTS = Counter(
    "extra_codeowners_github_api_requests_total",
    "Logical GitHub API requests by fixed operation, authentication mode, and outcome",
    ("operation", "authentication", "outcome"),
)
GITHUB_API_REQUEST_SECONDS = Histogram(
    "extra_codeowners_github_api_request_seconds",
    "Wall-clock time for one logical GitHub API request",
    ("operation", "authentication", "outcome"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30, 60),
)
GITHUB_RATE_LIMIT_EVENTS = Counter(
    "extra_codeowners_github_rate_limit_events_total",
    "GitHub API rate-limit responses observed by authentication scope",
    ("scope",),
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
RECONCILIATION_SECONDS = Histogram(
    "extra_codeowners_reconciliation_seconds",
    "Wall-clock time for one elected reconciliation scan",
    ("outcome",),
    buckets=(1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800),
)
RECONCILIATION_LAST_SUCCESS = Gauge(
    "extra_codeowners_reconciliation_last_success_timestamp_seconds",
    "Unix timestamp of the latest complete open pull request reconciliation",
)
TRACE_EXPORTS = Counter(
    "extra_codeowners_trace_exports_total",
    "OpenTelemetry trace export batches by result",
    ("outcome",),
)
