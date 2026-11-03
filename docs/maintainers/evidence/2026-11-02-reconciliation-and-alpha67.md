# Reconciliation and alpha.67: November 2, 2026

The live label-withdrawal/restoration probes passed on alpha.65 and alpha.67.
Both deployments stayed healthy during their bounded observations. Full
reconciliation remained slow and incomplete across repeated attempts, so
these results do not complete the performance or production-enforcement gates.

## Scope and source evidence

All times below are UTC on November 2, 2026. This receipt summarizes the
[dated issue evidence](https://github.com/stampbot/extra-codeowners/issues/203#issuecomment-6583054451)
and the retained probe journals, per-pod samples, completion logs and Tempo
captures. Raw logs, trace identifiers and infrastructure/fixture identities
remain in the maintainer's private evidence records.

The tested releases bind the observations to these revisions:

| Release | Source revision |
| --- | --- |
| [Alpha.65](https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.65) | `b6e6d1e7a06692211d118a431e08ae5676107f08` |
| [Alpha.67](https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.67) | `02f064ea82a23bf6b791d87ccc0145a08eabb759` |

Both ran two replicas on separate Kubernetes nodes with shared PostgreSQL
state. Each observation checked pod identity, image continuity, readiness,
restart counts and counter continuity; neither window observed a pod change,
restart or counter reset. No installation access selection, queue or quota
override was used to reduce the workload.

## Approval probe

The retained disposable PR had an approved delegated path and a required
delegation label. Author-as-owner was disabled. The guarded probe removed
only that label, waited for the final missing-approval result, restored it,
and waited for final success. Restoration also ran on failure or interruption.

These are individual observations, measured from API-request start to GitHub's
whole-second check-completion timestamp, not from the API response:

| Release | Label removed: final failure | Label restored: final success | Evaluation trace durations |
| --- | --- | --- | --- |
| Alpha.65 | 13.52 seconds | 11.45 seconds | 8.00 / 7.74 seconds |
| Alpha.67 | 10.33 seconds | 10.60 seconds | 6.57 / 7.26 seconds |

Alpha.65 also showed the explicit interim blocking failure after 8.52 seconds.
The alpha.67 remove request began at 18:38:47.668581 and its final failure
completed at 18:38:58. Restoration began at 18:39:01.395186 and final success
completed at 18:39:12. The label was restored and the PR head was unchanged.

Both evaluation traces from each probe were complete. They contained 17 and
18 outer GitHub operations, no recorded request error or retry, and negligible
request-permit wait. This is not a latency percentile, service-level objective
or whole-installation performance guarantee. Parallel operations and nested
token requests can overlap; phase sums are not wall-clock percentages.

## Alpha.65 reconciliation baseline

The baseline collected 100 samples from 16:23:52.987513 through
18:11:21.979548, about 107 minutes. No additional controlled fixture changes
occurred during this window. Other repositories in the installation could
still produce work; "quiet" does not mean the whole installation was idle.

One pod held the scan lease. Its completed outcomes were:

| Outcome | Completion | Duration | PRs queued | Finding |
| --- | --- | --- | --- | --- |
| Partial | 16:57:41 | 1,782.77 seconds | 84 | A received GitHub `check.list` HTTP 500 failed one installation. No budget deferral, lease loss or stop signal was recorded. |
| Partial | 17:20:21 | 1,060.27 seconds | 73 | Recovery admission deferred; no failed installation or lost lease. |
| Success | 18:03:25 | 2,283.50 seconds | 12 | Completion log, success counter, last-success timestamp and duration histogram agree. |

The first partial's complete trace contained 4,615 outer operations. Their
phase totals included 1,490.35 seconds HTTP, 97.72 seconds quota admission,
103.29 seconds quota accounting and 0.017 seconds permit wait. Nested token
requests were excluded. This locates most of that attempt's time in serial
HTTP work, not permit contention.

Across the window, the elected pod recorded 3,433 page-cache byte evictions.
Its final page cache held 522 entries using 25,147,555 bytes. The other pod
recorded no elected outcome. These process counters include other recovery
work; they are not exact per-scan attribution, and physical requests are not
the same as primary-quota charges.

There was one full success, not two. Scan completion also does not mean every
queued evaluation had finished at that instant. The encoding and transient
5xx-retry changes were not deployed during this baseline.

## Alpha.67 release and deployment verification

The complete release verifier exited zero. It checked both platform
inventories and notice bundles, CPython/Debian/Python/Rust source archives,
Python distributions, the chart package, OpenVEX evidence, artifact signatures
and GitHub provenance bound to the source revision above. The provenance
check rejected self-hosted runners. The final source PR's CI reported
2,449 tests passed, one skipped and 90% coverage; main/release run
[41493483378](https://github.com/stampbot/extra-codeowners/actions/runs/41493483378)
succeeded.

The independently checked artifact bindings were:

| Artifact | Digest |
| --- | --- |
| Multi-platform image index | `sha256:71e5a1e9a709f53910976c822f2542b4e526689e006b12a1fbaa33770c3d259c` |
| OCI chart manifest | `sha256:bf3227a6bf8b75503c45bc5cc0e697547761d19f7ebfbc4b084078c086888f34` |
| Chart package | `sha256:fa1451f541e9bacd1e30302088acf383e3d4976dc1c6a60a29e5e8a5f503ad7a` |

Both native image digests matched the image index, and the chart package
matched its registry content layer. All 38 downloaded assets matched GitHub's
reported SHA-256 metadata. That metadata is not a separate signed checksum
manifest. The annotated Git tag was unsigned; verification relied on signed
artifacts and source-bound provenance, not a claim of tag signing. Runtime VEX
version 7 had 26 `fixed` statements and no new exclusion.

The deployment PR changed only the app's chart version and image digest. Its
applicable checks passed; an unrelated namespace-boundary check failed with
the same normalized error on the base revision. The authorized app-only admin
merge left that policy untouched. The normalized comparison and deployment
PR reference are retained with the private evidence, not published here.

Argo's repository-resolution comparison error cleared without a forced
refresh or sync. Automatic sync ran from 18:34:38 through 18:34:59. Both pods
reported the expected version, source, App identity and PostgreSQL backend;
readiness passed. Argo was Synced/Healthy, with two Ready replicas, zero
restarts, separate nodes and a PodDisruptionBudget requiring at least one
healthy pod. No permission, credential, approval policy, installation
selection, database schema or other application changed.

These are technical artifact checks, not approval of corresponding-source
completeness or the distribution mechanism. Issue #18 remains open.

## Alpha.67 reconciliation observation

The read-only observer completed 45 samples from 18:39:27.052747 through
19:26:46.102489, about 47 minutes. It made no further fixture changes or
webhook redeliveries. Pod identities/images stayed stable, both replicas were
Ready, and no restarts or counter resets were observed.

The elected pod recorded two partial outcomes and no success:

| Completion | PRs queued | Finding |
| --- | --- | --- |
| 19:07:42 | 81 | One failed installation after `httpx.RemoteProtocolError`: the server disconnected before response headers. No quota deferral or lease loss. |
| 19:21:17 | 1 | Recovery admission deferred. No failed installation, lost lease or stop signal. |

The first partial's complete trace lasted 1,349.90 seconds and contained
3,669 outer operations. No HTTP status was received for the failed pull-list
request, so it did not enter the received-5xx retry branch. Issue #260 tracks
that connection-disconnect follow-up; it is not implemented in this release.

The elected pod recorded one `pull.list` recovery-budget deferral. This names
the guard, not whether the cause was a reserve threshold, reset handling or
an unknown budget. Its page cache stored 1,523 entries, rejected 29 for size,
and recorded no byte eviction during the window. At the end it retained
1,486 pages using 4,873,009 bytes and 2,915 compact entries using 1,104,611
bytes. The other pod recorded no elected outcome and ended with no cached
pages and seven compact entries using 4,154 bytes.

The smaller retained cache does not prove faster complete reconciliation.
Neither partial counts as a successful cycle, and outcomes from different
images cannot be combined to claim two quiet successes.

## Trace completeness

The alpha.65 full successful run returned 6,228 child spans without its
`reconciliation.run` root on two fetches several minutes apart. Retained
spans covered 17:25:21 through 18:02:43. No complete full-run phase attribution
is claimed. The shorter partial attempts retained their roots.

The observed Tempo 2.9.0 backend had an effective per-trace limit of
5,000,000 bytes and nonzero size-related discard increases in the surrounding
window. That is a strong lead, not proof that a particular discard belonged
to this trace. A successful exporter batch does not prove complete backend
retention. Issue #259 and the
[open design](../../explanation/design/2026-11-02-bounded-reconciliation-traces.md)
track the investigation; no shared Tempo configuration was changed.

## Limits and cleanup

No receiver outage, access-selection change, direct queue edit, quota override
or webhook redelivery was used for these observations. No new test repository
was created. The retained PR's label was restored, its head was unchanged,
and its final check was successful. The observers exited and temporary
worktrees, build caches and large verified downloads were removed; private
evidence and verification receipts were retained.

The runs did not establish two quiet successful cycles, isolated
missed-webhook causation, or a live multipage checkpoint across a quota reset.
They do not resolve shared-head inheritance, installation access-loss coverage
or distribution approval. The production warnings and open release gates
remain in force.
