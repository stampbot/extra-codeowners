# ADR: Bound read-ahead and resume an active reconciliation sweep

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-12 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Periodic installation discovery; approval evaluation and authority fan-out retain their existing guards. |
| Extends | [Installation retry cadence](2026-11-11-installation-retry-cadence.md) and [bounded discovery optimizations](2026-11-02-bounded-discovery-optimizations.md). |
| Implementation | [Issue #203](https://github.com/stampbot/extra-codeowners/issues/203) |
| Revisit when | Whole-cohort measurements show request cost, memory use or recovery latency remains unsuitable. |

## Business driver

A quota retry resumed after the last completed repository, then replayed the
earlier prefix before declaring the scan complete. Healthy installations were
already protected from another installation's early retry, but completed
repositories within the active sweep were not. Serial HTTP reads also dominated
the measured scan time. More worker processes would not fix a single elected
discovery loop.

## Constraints

Current authenticated membership remains authoritative. A cached name cannot
prove that the repository at that route is still the same repository. Every
new periodic sweep must revisit the current scope to repair missed events.

The database has one partial-PR cursor per installation. Concurrent readers
must not race to overwrite it. Discovery and direct events still share GitHub's
limits; concurrency creates no additional quota.

## Decision

**Y statement:** We will retain bounded advisory progress for the active sweep
and prefetch a few repository streams, because short retries should finish the
remaining work instead of repeating the completed prefix, while one ordered
consumer keeps durable cursor updates safe.

Each attempt still fetches and validates the complete installation list and
the installation's repository membership. Completed progress matches both
immutable repository ID and current route. Renames, recreations, new membership
and missing IDs cannot establish a completed match. Losing election or stopping
forgets the advisory state; a replacement leader uses the existing durable
cursors and may repeat reads.

Progress expires after the greater of the scan and PR-recheck intervals,
measured from the sweep's start, not its latest retry. A perpetually incomplete
sweep cannot suppress completed repositories indefinitely. Finishing a sweep
also discards its progress, so the next periodic scan starts fresh. Neither
expiry nor a due time promises a wall-clock recovery bound during provider
backoff or queue backlog.

Read-ahead uses at most four repository streams, or half the configured GitHub
request concurrency rounded down, with a minimum of one. Each stream buffers
one result and retains its current PR listing. It can fetch evidence for a
later repository before an earlier one commits, but cannot write jobs or
cursors. The consumer handles repositories and PRs in deterministic order and
commits each completed PR before moving on. A reader's partial results precede
its error. Failure, interruption or early exit cancels and drains unused reads.
Every physical request still needs the existing shared admission checks.

After one scan interval of work, an installation yields at the next repository
boundary if work remains. It requests a one-second continuation and lets other
due installations run. This is cooperative fairness, not a hard timeout: one
repository, pagination or membership discovery can take longer. If discovery
omits immutable IDs, the service uses the conservative full-scan path without
advisory skipping or this yield optimization.

## Consequences

Short retries can omit completed repositories, but not uncommitted prefetched
ones. Some requests can therefore be spent on read-ahead that is later
discarded. Whole-cohort measurements must include those requests and every
partial attempt; the final successful root is not the total cost.

Concurrency can shorten HTTP waits without reducing the number of requests in
a wholly fresh scan. Prefix retention reduces one source of repeated requests;
it does not make every unenrolled repository free to discover. A cold leader
and expired progress intentionally repeat some work.

This adds no schema, configuration option or authorization cache. Rolling back
restores serial discovery and prefix replay; existing durable work remains
readable. Live latency, cost and checkpoint evidence remain separate release
gates until measured on the deployed version.

## Alternatives considered

### Commit concurrently from each repository reader

That would let one repository overwrite another's partial-PR cursor. Keep the
consumer ordered instead of adding a migration and more coordination state.

### Trust the repository-name cursor as a completed-prefix proof

A name can be renamed or recreated. Use fresh membership and immutable IDs for
the optimization; keep the old cursor only as the durable ordering hint it
already was.

### Shorten the global scan interval

That schedules more copies of the expensive work. Remove replay and overlap
bounded reads first, then measure the whole installation again.
