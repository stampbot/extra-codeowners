# Alpha.69 release and approval validation: November 5, 2026

Alpha.69 deployed automatically and passed the delegated-approval withdrawal
and restoration test. Both image architectures and the released chart verified
against the publication evidence. This receipt does not establish production
enforcement or complete corresponding-source coverage.

## Scope and source evidence

The tested [v0.1.0-alpha.69 release][release] comes from source
`31820d7e207f18846f1d0260c270e22c78047db7` and reports Python distribution
version `0.1.0a69`. [Main CI and release run 41981060400][release-run]
succeeded. All times in this receipt are UTC on November 5, 2026.

The canary uses two Kubernetes replicas on different nodes with shared
PostgreSQL state. The approval test uses a retained disposable PR and a
non-required check, with author-as-owner disabled. Raw traces, delivery and
check identifiers, pod identities and fixture details remain in the
maintainer's private evidence records.

## Artifact verification

The unchanged `verify-release-provenance.sh` exited zero. It checked the
wheel, sdist, chart package, both platform inventories and notice bundles,
CPython/Python/Rust/Debian source bundles, and OpenVEX evidence. The signatures
and GitHub attestations identify the official release workflow and source
revision above; provenance verification rejects self-hosted runners. The
image's OpenVEX attestation and image/chart signatures also verified. No trust
check was disabled.

Both native image digests match the image index, release digest files and
signed inventories. The independently pulled OCI chart package is
byte-identical to the GitHub release package. Their bindings are:

| Artifact | Digest |
| --- | --- |
| Multi-platform image index | `sha256:a858a4e1c7dd97a02e6eaed1c85b8d1827e65c652019925bf0c65dfc6405bd69` |
| OCI chart manifest | `sha256:66091d129b52aa5886c23461a0d3ab9b4f84c1b2754115ae74eeed7a0b314827` |
| Chart package | `sha256:c19431ccd74d5cc4989a645c2fef86433b512888da1998fccd530ab92c1aefd1` |

All 38 downloaded files also matched GitHub's release-asset SHA-256 metadata.
That metadata comparison is separate from signature verification, not an
independent signed checksum manifest. The annotated tag is unsigned; the
checks rely on artifact signatures and source-bound provenance.

The source-retention job reported authenticated, version-matched Debian
source reuse. It completed without consulting Snapshot. This is publication
evidence for [issue #264][source-reuse], following the
[collector preflight](2026-11-05-debian-source-reuse.md).

The notice and Python source manifests report no unresolved entries within
their declared scope. The native source records cover six reviewed Psycopg
distro source packages on amd64 and eight on arm64; each Rust bundle contains
134 crate sources and 146 component records. Those counts do not prove a
complete native-library inventory, notice compliance or distribution approval.
[Issue #18][sources] retains those gates.

Alpha.69's published VEX contains 26 `fixed` statements. A later PR scan used
a newer vulnerability database and reported CVE-2026-109518 for the unchanged
APT packages. [The separate APT assessment][apt-assessment] records why package
installation is outside the shipped service's execution path, with explicit
limits. It does not patch APT or replace alpha.69's immutable VEX asset.

## Automatic rollout

The deployment changed only this App's chart version and immutable image
digest. All deployment checks and automated code/security reviews passed.
There was no change to credentials, policies, installation selection, database
schema, replica count or other applications.

Argo's first comparison at 07:06:58 reported a repository-resolution error.
Its next normal reconciliation cleared the condition at 07:09:03. Automatic
sync ran from 07:09:04 through 07:10:13, ending Synced/Healthy. No forced
refresh, sync or cluster mutation was used.

At 07:10:57 both replicas reported the expected version, source revision,
App identity, check name, policy location and PostgreSQL backend. Readiness
passed, both replicas had zero restarts, and they ran on different nodes.
The PodDisruptionBudget required one healthy pod and reported two. Its new
sync wave was `1`, after the Deployment. No controlled drain was performed.

## Approval probe

The guarded probe removed only the delegation's required label, waited for
the final missing-approval result, restored the label and waited for success.
Its cleanup restores the label even on failure or interruption.

These are individual observations from API-request start to GitHub's
whole-second completion timestamp:

| Trigger | Request start | Final result | Elapsed |
| --- | --- | --- | --- |
| Remove required label | 07:11:08.835399 | Failure at 07:11:17 | 8.16 seconds |
| Restore required label | 07:11:20.926276 | Success at 07:11:31 | 10.07 seconds |

An interim blocking failure was visible with completion timestamp 07:11:12.
Both evaluation traces were complete: 5.28 and 7.25 seconds, with 17 and 19
outer GitHub operations. Neither recorded a request error or retry. The label
was restored, the PR head was unchanged and the check ended successful.
These measurements are not latency percentiles or a service-level objective.

## Observation method

At 07:11:39, after the probe completed, the autoscaler evicted one pod as
underutilized. The first observer attempt stopped before saving a complete
sample because the replacement wasn't ready. It is not part of the measured
epoch. At 07:12:32 the replacement and surviving replica passed the same
runtime checks.

The new observer began at 07:12:46.736951. Each sample checks readiness,
image and pod identity, node separation, restart counts and counter continuity.
No further controlled fixture changes, webhook redeliveries, access-selection
changes or quota overrides occurred during the observation. Other repositories
can still generate work; this is not an idle installation.

This receipt covers 39 complete samples through 07:50:47.707324, a window of
about 38 minutes. Pod identities, images and counters stayed continuous;
both replicas remained Ready on different nodes with zero restarts.

The first elected attempt ended partial at 07:50:05 after 1,832.96 seconds.
It queued 77 PRs, with no failed installation, lost lease or stop signal.
Recovery admission deferred a `check.list` request. That names the guard;
it does not identify which reserve/reset condition caused the deferral.
The other replica recorded no elected outcome.

## Large partial-scan trace

Tempo returned one independent `reconciliation.run` summary for that attempt.
The summary reported 5,653 logical-request details, and a completed backend
search found exactly 5,653 unique linked traces. Three fetched examples each
had one request root, no parent, and the correct scan link; their queried JSON
measured 3,259–3,261 bytes. These are JSON response sizes, not OTLP wire sizes.
Search IDs were normalized for Tempo's omitted leading zeroes before counting.

The summary retains these request-phase totals:

| Phase | Seconds |
| --- | --- |
| HTTP | 1,601.18 |
| Quota admission | 79.63 |
| Quota accounting | 82.26 |
| Authentication | 0.047 |
| Permit wait | 0.011 |
| Body handling | 0.217 |

Nested token-request phases are excluded from the aggregate; overlapping
operations still mean these sums are not wall-clock percentages. The source
deliberately omits no sampled request. A successful exporter batch alone was
not used as proof of complete backend retention, and no shared backend limit
or sampling setting was changed.

This is complete telemetry for a large partial attempt, not a successful full
scan. [Issue #259][traces] retains that separate criterion.
[Issue #203][performance] still needs two quiet successful cycles, isolated
missed-webhook recovery and a live multipage checkpoint across a quota reset.
Completion of a resumed scan would not establish that every repository was
freshly visited within one attempt, or that all queued evaluations had finished.

The guarded probe and bounded observation complete [issue #260][disconnect]'s
rollout check. No real disconnect was observed or injected here; the retry
guarantees are covered by the merged regression tests, not a live fault-injection
claim. Further observations after this window belong in a later dated receipt.

## Limits and cleanup

No receiver outage or lifecycle/access-loss experiment was performed.
[Issue #1][provider-contract] retains the known pre-event shared-head risk,
not merely an unexecuted happy-path test. The check remains unsuitable as a
replacement for native production enforcement.

Large downloaded source payloads were removed after verification, reclaiming
497,957,467 bytes. Compact signatures, inventories, chart packages, digests,
VEX and verification receipts remain. Temporary test databases, rendered docs
and owned caches are removed after their checks finish; unrelated worktrees
and user changes are preserved. No new test repository was created.

[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.69
[release-run]: https://github.com/stampbot/extra-codeowners/actions/runs/41981060400
[source-reuse]: https://github.com/stampbot/extra-codeowners/issues/264
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[provider-contract]: https://github.com/stampbot/extra-codeowners/issues/1
[apt-assessment]: https://github.com/stampbot/extra-codeowners/pull/269
[traces]: https://github.com/stampbot/extra-codeowners/issues/259
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[disconnect]: https://github.com/stampbot/extra-codeowners/issues/260
