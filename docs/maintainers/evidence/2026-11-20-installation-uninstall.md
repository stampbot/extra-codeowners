# Installation uninstall: November 20, 2026

Uninstalling Extra CODEOWNERS stopped the playground installation from
issuing tokens. GitHub still showed its old green check. Native code-owner
review kept a separate, unapproved pull request blocked.

## Before the uninstall

The [November 19 resume](2026-11-19-installation-suspend-resume.md) queued
recovery work. Workers deferred some of it to preserve the playground's
GitHub API budget. A November 20 read showed no remaining resume jobs. Both
fixture pull requests had fresh evaluations: failure for the unapproved PR
and success for the advisory fixture.

The service still ran `v0.1.0-alpha.95`. The same two private fixtures kept
their original heads and rules. The native-review fixture required GitHub's
native rule, with no bypass actors. The other fixture had a passing Extra
CODEOWNERS check that no rule required.

## What we observed

The playground installation used all-repositories selection. We removed
only that installation, not the App registration or the separate operating
installation.

| Time (UTC) | Observation |
| --- | --- |
| 02:43:07–09 | GitHub accepted the uninstall with HTTP 202. |
| 02:43:09 | GitHub sent the original `installation.deleted` delivery. The receiver returned HTTP 202 and logged that it ignored the event without scheduling reevaluation. |
| 02:43:11 | Both the installation lookup and the scoped token request returned HTTP 404. The advisory check kept the same ID and completion time. GitHub reported the native-review fixture blocked. |

The deleted event contained `action`, `installation`, `repositories`, and
`sender` at the top level. We matched the installation in memory and kept
only the delivery metadata and field names. We did not redeliver the event
or attempt a merge. The separate operating installation stayed active with
the same repository selection and permissions.

## What this does not prove

An installation can't clear an old check after it loses access. Keep native
enforcement in place before you uninstall, and follow the
[access handback procedure](../../how-to/operate.md#change-repository-access-safely).
This run ended with the playground App uninstalled. It did not test a new
installation, repository transfer or deletion, selected-repository removal,
or the shared-commit enforcement gap.
