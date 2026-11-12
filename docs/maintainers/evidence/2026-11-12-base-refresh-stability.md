# Base-refresh stability: November 12, 2026

Alpha.89 retained a successful check through an unchanged base update without
a Check Run write. A policy change that withdrew approval made the check
blocking; restoring the policy restored success. This validates the base-refresh
fix, not the separate large-installation performance gate.

The observations below use a retained private fixture. Repository, trace, pod
and node identities remain in maintainer captures. Times are UTC.

## Release and rollout

[PR #297][fix] added a comparison with the prior successful audit before a base
refresh can retain success. Changed or unprovable inputs still block first.
[Alpha.89][release] contains source
`eccb080060b709b9f65e85582e5c2693cc7fc838`; its [main CI run][ci] passed.

Independent verification matched all 42 immutable release assets, totaling
776,879,382 bytes, by size and SHA-256. Signatures, provenance and source/VEX
bindings passed. The registry index matched both signed native image digests,
and the registry chart matched the signed release package.

The image index is
`sha256:8a099b946ba56daef3c7e4cfdb3ec5bf2d7192d78ecbc68862303b3e7368bc41`.

The version/digest-only [deployment PR][deployment] merged at 15:54:10 after
passing checks and clean code/security reviews. Argo briefly reported a
repository lookup error, then recovered on its ordinary retry. No forced
refresh, sync, credential change or direct cluster mutation was used.

Verification at 16:01:04 found two Ready replicas on distinct nodes, zero
restarts, the expected version/source and unchanged App/PostgreSQL identity.
The disruption budget reported two healthy replicas and minimum availability 1.

## Approval and base-update probes

The delegated-path fixture's head remained unchanged throughout these probes.

| Probe | Observation |
| --- | --- |
| Remove the required delegation label | Fresh final failure observed through the API after 16.07 seconds. |
| Restore that label | Fresh success observed after 12.17 seconds. |
| Append a policy comment without changing its parsed values | Fresh `base_branch_recheck` success after 45.47 seconds; the fingerprint and sampled Check Run fields remained unchanged. |
| Disable repository policy | First blocking API observation after 20.03 seconds; a fresh failed audit followed about 108 seconds after the request. |
| Restore the original policy | Success and a fresh audit observed after 31.04 seconds. |

For the unchanged update, the Check Run kept its earlier completion time of
16:02:46. Its completed worker trace lasted 6.07 seconds and contained **zero**
`check.update` or `check.create` requests. The withdrawal and restoration worker
traces lasted 6.69 and 7.66 seconds and each contained two check updates.
Their resource identities matched the verified alpha.89 pod epoch.

The original policy blob, head, label set and review identities/states were
verified afterward. No repository was created, and no installation selection,
queue, quota or deployment setting changed during the probes.

An earlier attempt stopped on a harness assertion that expected an audit
trigger string rather than its reason/delivery object. It restored the policy
and does not count as a completed test. The corrected run completed all cases.

## Limits

The timings include API polling and read-only audit capture. They are not
continuous UI observations, latency percentiles or atomic merge guarantees.
The policy-withdrawal proof includes a blocking interim result and a fresh
denial audit; it does not claim the final diagnostic was polled before cleanup.
The zero-write count covers the selected completed worker trace, not every
authority-worker request.

These results support [issue #296][issue]. They do not establish the request
cost, recovery latency or checkpoint contract in [issue #203][performance],
nor the remaining provider/lifecycle contracts in [issue #1][provider]. Keep
the App non-required during evaluation.

[fix]: https://github.com/stampbot/extra-codeowners/pull/297
[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.89
[ci]: https://github.com/stampbot/extra-codeowners/actions/runs/43246232843
[deployment]: https://github.com/neverendingsupport/argo-apps/pull/2671
[issue]: https://github.com/stampbot/extra-codeowners/issues/296
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[provider]: https://github.com/stampbot/extra-codeowners/issues/1
