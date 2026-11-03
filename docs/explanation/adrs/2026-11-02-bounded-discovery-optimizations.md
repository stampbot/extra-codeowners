# ADR: Bound discovery optimizations without weakening evidence

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-02 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Local discovery reuse and transient read retries. This does not change approval policy, publication fences or the production enforcement contract. |
| Related | [Architecture](../architecture.md#discovery-reuse-and-retries), [threat-model invariants](../threat-model.md#invariants), [November evidence](../../maintainers/evidence/2026-11-02-reconciliation-and-alpha67.md) |
| Implementation | [PR #256](https://github.com/stampbot/extra-codeowners/pull/256), [PR #258](https://github.com/stampbot/extra-codeowners/pull/258) |
| Revisit when | Discovery needs persistent or shared cached representations, or a retry would change write behavior, quota admission or the operation deadline. |

This record captures the choices implemented by the linked pull requests.
It does not declare the reconciliation performance gate complete.

## Business driver

Large installations spend time validating many repositories and pull requests
that need no evaluation. The measured discovery cache evicted pages for lack
of space, while one received GitHub server error ended a long scan early.
Reducing those costs is useful only if it doesn't turn yesterday's evidence
or an uncertain API result into permission to merge.

## Constraints

- Incomplete evidence blocks success, and authorization evidence comes from
  GitHub, not a webhook or local cache (XCO-001 and XCO-014).
- An uncertain write must not become a confirmed result (XCO-008).
- Diagnostics keep the private-data boundary in XCO-011.
- API quota admission, publication fences and the
  [scheduled-recheck decision](2026-10-11-keep-results-on-scheduled-rechecks.md)
  remain authoritative.

## Decision

**Y statement:** We will use bounded, disposable local storage and a bounded
retry for explicitly classified discovery-read failures, because large scans
need to tolerate storage pressure and a transient read failure, so recovery
can make progress without accepting stale evidence or adding write retries.

The decision has these boundaries:

- Local encoding may reduce retained bytes, but cannot admit a representation
  that exceeds the original unencoded limit. Decoding is bounded; invalid
  storage becomes a miss. Each process may discard its entire cache.
- Cached bodies and pagination links require authenticated HTTP revalidation
  before reuse. A cache hit alone is never approval evidence.
- Every physical attempt needs authentication and quota admission. An
  uncertain request is not proof of an unused quota charge.
- A discovery operation has one transient-retry budget, shared with its
  original deadline and at most one token refresh. It does not gain a new
  deadline for each attempt. Waiting holds no request permit or database
  transaction and respects shutdown and cancellation.
- A retry removes conditional validators. A `304` without matching validated
  cached evidence fails closed. Persistent errors stay errors.
- Eligible failure classes are explicit and tested. Discovery optimizations
  must not silently extend to writes, ordinary reads, streaming requests,
  permission failures or rate-limit responses.

The [HTTP and metric reference](../../reference/http-api.md#get-metrics)
defines the current caps, eligible response statuses and timing fields.

## Consequences

- Local caches don't coordinate replicas or replace shared database state.
  A rollout drops the cache without a schema or persistent-state rollback.
- Authenticated revalidation still makes HTTP requests. More retained pages
  do not prove a faster full scan or create API capacity.
- A bounded retry can recover one transient failure; it cannot guarantee a
  complete scan. New failure classes need regression tests that preserve the
  same deadline, quota and retry bounds.
- Performance and recovery claims need their own dated evidence. They don't
  follow from passing cache or retry unit tests.

## Alternatives considered

### Keep unencoded storage and fail on the first server error

This avoids encoding and retry logic. The observed byte evictions and partial
scan show the cost: useful representations churn and a transient response can
end an installation's scan after substantial work.

### Trust cached evidence until its local expiry

This removes more HTTP traffic, but local age cannot prove that a review,
permission, policy or GitHub representation is still current. It conflicts
with XCO-001 and XCO-014.

### Retry every failed API operation

This treats discovery and publication alike. A lost write response can mean
GitHub applied the write already; replaying it is not a safe read retry.
Unbounded attempts or renewed deadlines would also consume quota and delay
shutdown without a fixed limit.
