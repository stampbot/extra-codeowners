# ADR: Delegate App approvals through a required check

## Record

| Field | Value |
| --- | --- |
| Date | 2026-07-13 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Danny Sauer |
| Scope | How an approving GitHub App's review can satisfy code-owner policy. It doesn't cover the ordinary approval count or other repository rules. |
| Related | [Native CODEOWNERS comparison](../native-codeowners.md), [threat model](../threat-model.md) |
| Implementation | [Bootstrap commit `2d18a53`](https://github.com/stampbot/extra-codeowners/commit/2d18a539bc23efd2c6633c2a33808592cb40683d) |
| Revisit when | GitHub supports a GitHub App as a native code owner with path-limited authority. |

## Business driver

Review automation such as [Stampbot](https://github.com/dannysauer/stampbot)
already decides when a routine change, such as a lockfile update, may be
approved. GitHub's native **Require review from Code Owners** rule still waits
for a person, so every one of those pull requests needs a human approval that
adds nothing to the automation's own policy.

## Constraints

- Human ownership stays in `CODEOWNERS`, in the users and teams GitHub
  documents as owners.
- An App must not gain authority over the files that decide who may approve or
  what the App will do.
- Missing, stale, or contradictory evidence must block a merge rather than
  allow one.

## Decision

**Y statement:** We will publish a separate required Check Run,
`Extra CODEOWNERS / approval`, that accepts either a human code-owner approval
or an enrolled App's approval for delegated paths, because GitHub's native rule
can't express path-limited App authority, so automation can satisfy owner
policy for narrow, routine changes while people keep every other approval.

The decision has these boundaries:

- Each distinct effective owner set is satisfied on its own, by a human or by
  an App whose delegation covers those paths and owners.
- Organization policy enrolls an App by immutable identity and sets
  guardrails. Repository policy delegates paths and owners within that, and it
  can't enroll a new App or remove an organization guardrail.
- By default, an App can't approve the paths that decide who may approve:
  `CODEOWNERS`, workflows, local actions, Stampbot's `/stampbot.toml`, and the
  repository policy file. A repository can opt its own policy file into App
  delegation, and an operator can remove the built-in list with an explicit
  insecure setting; the
  [configuration reference](../../reference/configuration.md#built-in-non-delegable-paths)
  has the exact rules. Other Apps' control files need organization guardrails.
- The check replaces only the native code-owner switch. The ordinary approval
  count and every other repository rule stay in place.

## Consequences

- Operators run and secure a service whose check gates merges, including its
  database and App credentials.
- Repository administrators must swap the native code-owner switch for the
  required check, and must configure the expected App source so another actor
  can't publish a check with the same name.
- A Check Run belongs to a commit while the decision belongs to a pull request.
  That mismatch is the project's main production blocker; see the
  [project status](../../reference/project-status.md#production-enforcement-blocker).

## Alternatives considered

### Keep the current approach

Leave native code-owner enforcement alone and have people approve routine
automated changes. This needs no new service, and it's still what production
repositories should do today. It doesn't remove the human approval that the
automation's own policy already made redundant.

### List the App's bot account in CODEOWNERS

GitHub documents code owners as users or teams with write access. It doesn't
document a GitHub App bot account as a supported owner type, and even if one
worked, a `CODEOWNERS` entry can't say which App was enrolled, which owner it
stands in for, which labels narrow it, or which paths it must never approve.
