# Installation suspension and recovery: November 19, 2026

Suspending the App blocked access, but it didn't clear a previously passing
Check Run. The fixture with GitHub's native code-owner rule stayed blocked.

## Setup

The deployed service ran `v0.1.0-alpha.95` from commit
`9c373e49c1670d5c557067e22318f4b4bd135ebc`, with two Kubernetes replicas and
PostgreSQL. The test used an existing all-repositories installation in a
GitHub.com playground organization, separate from the operating installation.
Two retained private fixtures served different purposes:

- One open pull request had a passing Extra CODEOWNERS check that no rule
  required.
- The other open pull request had no qualifying review. Its active ruleset
  required native code-owner review and had no bypass actors. It did not
  require Extra CODEOWNERS.

Both pull-request heads and the rulesets stayed unchanged. No pull request
was merged or retargeted during this test.

## Observations

The first suspend/resume round trip ran at 03:25 UTC. Both operations succeeded,
and GitHub delivered both lifecycle webhooks. A local parser failed to record
one while-suspended read, so the table uses the second round trip.

| Time (UTC) | Observation |
| --- | --- |
| 03:28:37 | GitHub confirmed suspension. It denied a token request scoped to one fixture with HTTP 403. |
| 03:28:38 | The passing advisory check was still visible, with the same ID and completion time. GitHub reported the native-review fixture blocked. |
| 03:28:39–40 | GitHub confirmed resume with the same installation ID, permissions and repository selection. The same fixture-scoped token request returned HTTP 201. |
| 03:29:02 | The worker logged completion of installation-wide discovery. |

GitHub recorded original `installation.suspend` and `installation.unsuspend`
deliveries with HTTP 202 responses. The matching service logs show that the
receiver acknowledged `suspend` without queuing work. It durably accepted
`unsuspend` and queued an installation-wide authority job. Discovery finishing
does not mean every downstream evaluation has finished.

## What this establishes

Native enforcement kept the unapproved fixture blocked while the App was
unavailable. We read GitHub's reported merge state; we didn't attempt a merge.
An old green check is not evidence that the App still has access or has
reevaluated the pull request. Resume restores access and starts recovery;
operators still need to wait for current results.

Both probe tokens issued while the App was active were revoked. The playground
installation was active at the end, and the separate installation's state was
unchanged. No webhook was redelivered and no shared deployment or App settings
changed. The maintainer retained the sanitized event field names and correlated
timestamps. These are positive delivery observations, not a complete delivery
history.

Uninstall/reinstall, repository transfer, deletion and selected-access removal
were not part of this run. The result also does not close the shared-commit
enforcement gap. Keep the production warning and follow
[the access handback procedure](../../how-to/operate.md#change-repository-access-safely).
The remaining acceptance criteria are in
[issue #1](https://github.com/stampbot/extra-codeowners/issues/1).
