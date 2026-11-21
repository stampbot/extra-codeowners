# Selected-repository reinstall: November 20, 2026

Reinstalling Extra CODEOWNERS restored access to both test repositories and
their shared policy repository. The App reevaluated both open pull requests
without a manual refresh.

## Setup

An organization owner used GitHub's installation page after the
[playground uninstall](2026-11-20-installation-uninstall.md). The new
installation used selected-repository access. A read-only probe confirmed
that it could see exactly the three selected repositories. The old
installation still returned HTTP 404, and the separate operating
installation stayed active.

The service ran `v0.1.0-alpha.95` from commit
`9c373e49c1670d5c557067e22318f4b4bd135ebc`. Neither test PR changed
its head or rules. The advisory PR had no rule requiring the Extra
CODEOWNERS check. The unapproved PR's native code-owner rule still blocked it.

## What GitHub and the service reported

The timeline separates accepting the webhook, finding the fixture PRs,
and finishing their evaluations.

| Time (UTC) | Observation |
| --- | --- |
| 03:04:22 | GitHub sent the original `installation.created` delivery. The receiver stored the work and returned HTTP 202. |
| 03:04:28 | Discovery finished for both fixture repositories. |
| 03:05:33–39 | The audit recorded a failure on the unapproved PR and a success on the advisory PR. GitHub showed a new completion time for the advisory check. |

The create event contained `action`, `installation`, `repositories`,
`requester`, and `sender` at the top level. Its repository list matched the
three selected repositories. We kept the field names and delivery metadata,
not the payload values. We revoked the probe token after reading membership.

This run verified reinstall and recovery. It did not remove a repository
from the new installation, test repository transfer or deletion, or change
the [limits of commit-scoped checks](../../reference/project-status.md#production-enforcement-blocker).
