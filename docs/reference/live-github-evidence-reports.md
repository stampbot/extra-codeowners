# Live GitHub evidence reports

Extra CODEOWNERS has two opt-in tools for recording behavior that unit tests
cannot establish:

- `mise run test:github-contract` exercises Check Runs, rulesets, pull
  requests, and an optional App-authored review in a disposable repository.
- `mise run capture:github-lifecycle-contract` records the delivery shape for
  selected GitHub App lifecycle events.

Both tools write sanitized JSON. They do not produce an attestation, approve a
release, or prove that a deployed Extra CODEOWNERS service handled an event.
Follow the [live GitHub contract guide](../how-to/run-live-github-contract.md)
for the destructive test procedure.

## Compatibility rules

Consumers must require an exact `schema_version`. A higher version may change
field meaning as well as structure; do not accept it as though it were the
version documented here.

Both report types bind observations to:

- the full 40-character source commit in `source_revision`
- the pinned GitHub REST version in `api_version`
- a UTC capture or fixture timestamp.

The reports are sanitized, not anonymous. Event names, actions, timestamps,
HTTP status codes, and payload field names can still reveal operational
details. Inspect a report before attaching it to a public issue.

## Repository fixture report, schema 2

The repository fixture writes `live-github-contract-report.json` unless
`EXTRA_CODEOWNERS_LIVE_REPORT_FILE` names another path.

### Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Exact report schema. This page describes version `2`. |
| `api_version` | GitHub REST API version sent with every request. |
| `source_revision` | Full source commit supplied by the operator. |
| `started_at`, `finished_at` | Fixture timestamps. |
| `fixture` | Installation selection modes and whether fixture resources were deliberately kept. |
| `assertions` | Raw, named observations. Values are `true`, `false`, or `null`. |
| `webhook_contracts` | Event metadata and payload key sets, without delivery IDs or payload values. |
| `interpretation` | The fixture's narrow interpretation of the Check Run and ruleset observations. Present only when the fixture reaches interpretation. |
| `result` | `observed`, `failed`, or `interrupted`. |
| `failure_type` | Exception class when `result` is `failed`; no provider error text is retained. |
| `cleanup_succeeded` | True only when cleanup was attempted, reported no error, and the repository was not deliberately kept. |
| `cleanup_failure_count` | Number of cleanup failures, when nonzero. |
| `evidence_completeness` | Machine-readable account of which probes returned a determinate value. |

A configuration or credential error can happen before the fixture owns a
report. In that case the command exits nonzero before it can write one.
When a later fixture step fails, the report keeps the fields collected up to
that point. `interpretation` can therefore be absent from a `failed` or
`interrupted` report. Consumers must treat an absent field as unavailable
evidence, not as a favorable result.

### Observation states

Each raw assertion has one corresponding state under
`evidence_completeness.observations`:

| Raw report condition | State | Meaning |
| --- | --- | --- |
| `true` | `observed_true` | The probe ran and observed the condition. |
| `false` | `observed_false` | The probe ran and did not observe the condition. |
| `null` | `not_run` | The fixture deliberately skipped an optional or inapplicable probe. |
| Key absent | `missing` | The run ended before it recorded the probe. |
| Any other value | `invalid` | The report does not satisfy this schema. |

False is evidence. It is not favorable evidence by definition. For example, a
false expected-source observation is complete enough to diagnose but unsafe
for rollout.

The completeness object also groups names into `observed_false`, `not_run`,
`missing`, and `invalid` arrays. These arrays make omissions visible without
requiring a consumer to infer meaning from JSON truthiness.

### Completeness fields

`configured_observations_complete` is true when every probe required by this
run has either an `observed_true` or `observed_false` state. The required set
always includes the core ruleset, Check Run, shared-head, retarget, and pull
request delivery probes. It also includes:

- the three App-review probes when approver App credentials were supplied
- `installation_repository_added_delivery_observed` when the checker uses a
  selected-repositories installation.

`configured_run_complete` also requires:

- `result` to be `observed`
- cleanup to have succeeded
- the checker installation selection to be `all` or `selected`.

It says that the configured automated run is complete. It does not say that
every observation was true, that the GitHub contract failed closed, or that
the service is ready for production.

`full_automated_observations_complete` requires determinate values for all
core and App-review probes, even when the optional approver was not configured
for this run. It does not include cleanup, deployed service tests, or manual
lifecycle work. Use it to find missing provider evidence, never as a release
gate by itself.

`manual_evidence_required` names the remaining deployed delivery,
reconciliation, lifecycle, access-loss, and merge-handback work. The automated
fixture never marks those items complete.

Require the configured automated evidence with:

```bash
jq -e '
  .schema_version == 2 and
  .result == "observed" and
  .cleanup_succeeded == true and
  .evidence_completeness.configured_run_complete == true
' live-github-contract-report.json
```

Then review the actual observations:

```bash
jq '{
  interpretation,
  assertions,
  observed_false: .evidence_completeness.observed_false,
  not_run: .evidence_completeness.not_run,
  missing: .evidence_completeness.missing,
  invalid: .evidence_completeness.invalid,
  manual: .evidence_completeness.manual_evidence_required
}' live-github-contract-report.json
```

Do not add a blanket `all(.assertions[]; . == true)` gate. Some assertions
measure unsafe inheritance and are favorable when false, while diagnostics
can be `null` when their prerequisite did not occur.

### Raw assertions

The core observations are:

| Assertion | Question answered |
| --- | --- |
| `organization_ruleset_expected_source` | Does the organization ruleset require this context from the checker App ID? |
| `repository_ruleset_expected_source` | Does the repository ruleset require this context from the checker App ID? |
| `completed_success_to_in_progress_blocks_merge` | Does replacing success with `in_progress` produce both a blocked mergeability state and a blocked merge API attempt? |
| `shared_head_inherits_success_before_invalidation` | Does a second pull request with the same head inherit the existing commit-scoped success? |
| `shared_head_invalidation_blocks_both_pull_requests` | Does invalidating that success block both pull requests? |
| `retarget_inherits_commit_scoped_success_before_invalidation` | Does a retargeted pull request inherit the existing commit-scoped success? |
| `pull_request_opened_delivery_observed` | Did the checker App's delivery log expose the fixture's opened event? |
| `pull_request_retarget_delivery_observed` | Did the checker App's delivery log expose the fixture's edited event after retargeting? |

The optional App-review observations are:

| Assertion | Question answered |
| --- | --- |
| `numeric_approval_rule_blocks_before_app_review` | Does a required approval count of one block before the App reviews? |
| `app_review_attributed_to_bot` | Does GitHub attribute the review actor to type `Bot`? |
| `app_review_counts_as_numeric_approval` | Does that App review make the pull request clean after the pre-review block? |

The diagnostic observations are:

| Assertion | Question answered |
| --- | --- |
| `in_progress_merge_state_blocked` | Did mergeability settle on `blocked` after invalidation? |
| `in_progress_merge_attempt_blocked` | Did the merge API reject the attempt? This is `null` when the state probe did not block. |
| `installation_repository_added_delivery_observed` | Did a selected-repositories installation expose the add event for the fixture repository? This is `null` for an all-repositories installation. |

## Lifecycle delivery report, schema 1

The lifecycle collector writes `live-github-lifecycle-report.json` unless
`EXTRA_CODEOWNERS_LIFECYCLE_REPORT_FILE` names another path.

It reads a bounded sequence of pages from the
[App delivery API][app-deliveries], keeps summaries for the exact
installation, timestamp window, and requested event/action pairs, and fetches
matching details. Pagination follows only the cursor from GitHub's
`rel="next"` link. The collector accepts these pairs:

```text
installation.created
installation.deleted
installation.new_permissions_accepted
installation.suspend
installation.unsuspend
installation_repositories.added
installation_repositories.removed
installation_target.renamed
repository.archived
repository.deleted
repository.renamed
repository.transferred
repository.unarchived
```

### Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Exact report schema. This page describes version `1`. |
| `api_version` | GitHub REST API version sent with every request. |
| `source_revision` | Full source commit supplied by the operator. |
| `since` | Inclusive lower timestamp selected by the operator. |
| `captured_at` | Time the collector built the report. |
| `scope` | Reminder that the capture covers one configured disposable App installation. |
| `expected` | Sorted event/action pairs requested for this capture. |
| `delivery_list_limit` | Maximum delivery summaries read across all pages; currently `100`. |
| `delivery_page_limit` | Maximum delivery-list requests; currently `8`. |
| `delivery_page_size` | Maximum summaries requested in one page; currently `100`. |
| `delivery_pages_read` | Number of delivery-list requests completed. |
| `delivery_detail_limit` | Maximum matching delivery details read; currently `24`. |
| `delivery_window_complete` | True when GitHub returns a page without a `rel="next"` link; false when a list bound stops paging while that relation remains. |
| `delivery_details_complete` | False when more matching summaries exist than the detail limit permits. |
| `observations` | State, summary count, and unique sanitized contracts for each expected pair. |
| `capture_complete` | True only when both bounds are complete and every expected pair was observed. |
| `result` | `observed`, `incomplete`, or `failed`. |
| `failure_type` | Exception class when `result` is `failed`; no provider error text is retained. |

The table is the union of successful, incomplete, and failed reports. A failed
capture contains `schema_version`, `api_version`, `source_revision`, `since`,
`captured_at`, `expected`, `result`, and `failure_type`. It omits bounds,
observations, `scope`, and `capture_complete` because the collector cannot claim
their values after an arbitrary failure. Consumers must treat those absent
fields as incomplete evidence.

Each observation state is `observed`, `not_observed`, or `incomplete`.
`not_observed` means the requested pair was absent from a complete bounded
window. It is determinate negative evidence, not proof that GitHub can never
send the event. `incomplete` means the page or detail bound prevented that
conclusion.

`result: observed` means the collector could account for the requested window
and details. It can coexist with `capture_complete: false` when an expected
event was absent. The command still exits nonzero in that case. A shell
consumer must require `capture_complete`, not `result` alone:

```bash
jq -e '
  .schema_version == 1 and
  .result == "observed" and
  .capture_complete == true and
  all(.observations[]; .state == "observed")
' live-github-lifecycle-report.json
```

[GitHub's pagination contract][rest-pagination] omits the `Link` header when
all results fit in the current response and uses a `rel="next"` link when
another page exists. A full page without `rel="next"` is therefore complete. A
short page with `rel="next"` is not; the collector follows its cursor until
GitHub omits that relation or a bound is reached.

The collector never requests a URL supplied by a response. It accepts only a
cursor from an HTTPS link for the fixed GitHub delivery endpoint, then sends
that cursor to the endpoint it already trusts. A malformed, ambiguous,
duplicate, or off-host next link fails the capture. If another page remains
after 100 summaries or eight page requests, `delivery_window_complete` is
false. More than 24 matching summaries makes `delivery_details_complete`
false. Use a fresh, low-traffic disposable App whose delivery history fits
within the list bounds. Use a shorter timestamp window when the detail bound
is reached. Do not raise the bounds and treat the result as equivalent
evidence.

Before sanitizing a matching detail, the collector verifies that its identity,
event, action, timestamp, and summary metadata agree with the list response.
The collector requires matching response-status and redelivery metadata in
both records. Conflicting or missing metadata fails the capture instead of
combining two deliveries into one observation.

For each unique delivery shape, `contracts` retains only:

- event and action
- response status code and redelivery flag
- root payload field names
- field names within a fixed set of relevant objects and object lists.

Delivery IDs, installation IDs, repository IDs, actor names, headers,
pagination URLs and cursors, signatures, payload values, response bodies, and
provider error messages are not written.

A lifecycle configuration error happens before capture starts, so it does not
write a report.

## Exit codes

| Command | Code | Meaning |
| --- | --- | --- |
| Repository fixture | `0` | The fixture obtained determinate automated observations. Inspect completeness and values separately. |
| Repository fixture | `1` | Setup, observation, or cleanup failed. |
| Repository fixture | `2` | Configuration or credentials were rejected before the fixture started. |
| Repository fixture | `130` | The operator interrupted the fixture; cleanup was attempted. |
| Lifecycle collector | `0` | The bounded window and details were complete, and every expected event was observed. |
| Lifecycle collector | `1` | An expected event was absent, a bound was exceeded, or capture failed. |
| Lifecycle collector | `2` | Configuration was rejected before capture started. |

An exit code is a transport signal, not the evidence itself. Retain and review
the sanitized report whenever the command got far enough to write one.

[app-deliveries]: https://docs.github.com/en/rest/apps/webhooks?apiVersion=2026-03-10#list-deliveries-for-an-app-webhook
[rest-pagination]: https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
