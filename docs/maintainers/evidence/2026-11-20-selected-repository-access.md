# Removing and restoring one repository: November 20, 2026

Removing a repository from the App's selection stopped GitHub from issuing a
new token for that repository. Its old passing check stayed visible. Adding
the repository back triggered a fresh evaluation without a manual refresh.

## Setup

We used the [reinstalled playground App](2026-11-20-installation-reinstall.md)
on `v0.1.0-alpha.95` (commit `9c373e49c1670d5c557067e22318f4b4bd135ebc`).
An organization owner changed only the advisory fixture's selection. The
shared policy repository and the native-review fixture remained selected.
Both fixture PRs kept their heads and rules.

## Observations

GitHub delivered both original events with HTTP 202 responses. The receiver
did different work for removal and restoration:

| Time (UTC) | Observation |
| --- | --- |
| 03:08:20 | The receiver acknowledged `installation_repositories.removed` without queuing work. |
| 03:08:42 | Two repositories remained in the installation. GitHub denied a new token scoped to the removed repository with HTTP 422. The old advisory success kept its ID and completion time. |
| 03:09:31 | The receiver accepted `installation_repositories.added` and queued discovery for that repository. |
| 03:09:36 | Discovery finished for the restored repository. |
| 03:09:41–42 | GitHub showed a new completion time on the advisory success. The fresh evaluation also appeared in the service audit. |
| 03:09:52 | The installation had all three repositories again. A token scoped to the restored repository returned HTTP 201. |

Both events included `action`, `installation`, `repositories_added`,
`repositories_removed`, `repository_selection`, `requester`, and `sender`.
The matching added or removed list named only the advisory repository. We
retained the field names and delivery metadata, and revoked the probe tokens.

## Scope

No rule required the advisory check, and the separate native-review fixture
stayed blocked. We didn't attempt a merge. This run did not test whether
GitHub revokes tokens issued before deselection. It did not remove the
policy repository, transfer or delete a repository, or establish that
commit-scoped checks can replace native enforcement.
