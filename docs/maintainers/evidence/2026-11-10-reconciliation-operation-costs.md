# Reconciliation operation costs: November 10, 2026

Listing checks and pull requests accounted for 4,399 of the 6,379 requests
in one successful alpha.73 reconciliation attempt. The request permits were
not the main source of delay. Reducing request volume or overlapping safe,
independent work merits investigation; neither change is implemented by this
receipt.

The attempt ended at 09:24:14.011 UTC on November 10, 2026. It ran for
1,991.73 seconds on [alpha.73][release], source
`95dfd13f5ce26962c73c8bcf9d78d911178f67c5`, queued 78 PRs and reported no
failed installation or budget deferral. The [quiet-window receipt][quiet]
records the stable replicas and complete linked-trace capture.

## Method

The follow-up query selected operation, work class, response status,
conditional-request state and recorded phase durations from every linked
request. It also selected the version and pod identity so an older or newer
deployment could not silently enter the result.

The bounded capture used [TraceQL field selection][selection] in twelve time
partitions, plus one summary read. All backend search jobs completed. After
deduplication it retained 6,379 single-request rows, matching the summary's
expected detail and outer-request counts. These are aggregate results from
the complete selected-attribute set, not an extrapolation from three sample
traces. Private identities and raw query results remain in maintainer captures.

## Request breakdown

Every returned request used the `recovery` work class. The counts and HTTP
phase sums were:

| Operation | Requests | Conditional requests | HTTP 304 responses | HTTP seconds, summed |
| --- | --- | --- | --- | --- |
| `check.list` | 2,610 | 2,609 | 892 | 830.89 |
| `pull.list` | 1,789 | 1,784 | 506 | 567.79 |
| `content.get` | 980 | 0 | 0 | 169.75 |
| `repository.ref` | 980 | 980 | 284 | 271.99 |
| `installation.repositories` | 19 | 19 | 0 | 19.10 |
| `app.installations` | 1 | 0 | 0 | 0.24 |

The `content.get` group contains 972 `404` responses and eight `200`
responses. Across all groups there were 3,725 `200`, 1,682 `304` and 972
`404` responses. An individual response status is not proof of a repository's
enrollment state or of how much quota GitHub charged.

Many conditional requests still returned `200`. That alone does not tell us
whether the response changed, whether GitHub varied its validator, or whether
an endpoint honored the condition. The capture did not compare response bodies
or establish a cause.

## Interpretation and limits

The HTTP sums total 1,859.77 seconds and agree with the retained summary.
Quota admission totaled 43.15 seconds and accounting 49.07 seconds. Permit
waits totaled about 0.012 seconds. These are sums of instrumented phases,
not wall-clock percentages or a forecast of the gain from concurrency.

Check and PR listing are the largest measured groups, so optimizing an
unrelated worker-cleanup task would not address most of this attempt's cost.
Any request reduction must still detect policy addition/removal, changed
heads and managed checks. Any concurrency change must preserve ordered,
durable progress, rate-limit coordination and capacity for direct events.

This is one completed attempt on an existing large installation. It does
not establish initial-discovery cost, acceptable recovery latency, a maximum
scan duration or fresh visits to every repository within that attempt.
[Issue #203][performance] retains the performance investigation. No cache,
quota, concurrency or installation setting changed to obtain these results.

[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.73
[quiet]: 2026-11-10-quiet-reconciliation-and-new-enrollment.md
[selection]: https://grafana.com/docs/tempo/latest/traceql/construct-traceql-queries/#selection
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
