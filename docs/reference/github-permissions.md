# GitHub permissions and webhook events

Extra CODEOWNERS authenticates with GitHub App installation tokens. Its registration permissions cover evidence collection, Check Run publication, authority-change webhooks, and expected-source selection. GitHub's [permission-selection guide](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app) describes how GitHub maps API operations and events to these permissions.

## Repository permissions

The App registration requests these repository permissions:

| GitHub App permission | Access | What Extra CODEOWNERS uses it for |
| --- | --- | --- |
| Checks | Read and write | Find, create, and update this App's `Extra CODEOWNERS / approval` Check Run. |
| Contents | Read | Read policy and `CODEOWNERS` at an exact commit. The service does not check out or write repository content. |
| Pull requests | Read | Fetch the current pull request, changed files, labels, and reviews; receive pull-request and review webhooks. |
| Statuses | Read and write on the installation only | Make the App available as an expected source for organization-level required-check rulesets. Runtime installation tokens omit this permission. |
| Metadata | Read | Read repository metadata and direct-collaborator permissions; receive label, collaborator, and repository-lifecycle webhooks. GitHub grants this baseline permission with repository access. |

Statuses is a registration-time discovery permission. Extra CODEOWNERS never calls the commit-status API. GitHub documents the organization-ruleset requirement under [Require status checks to pass before merging](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging).

The service does not request:

- Issues
- Actions
- Workflows
- Administration
- Deployments
- Pull requests write.

The application that submits a delegated review is a separate actor. It may need Pull requests write for its own work. Extra CODEOWNERS never submits or dismisses a review.

## Organization permissions

The App registration requests one organization permission:

| GitHub App permission | Access | What Extra CODEOWNERS uses it for |
| --- | --- | --- |
| Members | Read | Confirm active membership in a visible CODEOWNER team and confirm that the team grants qualifying repository access; receive organization, team, and membership events that can revoke authority. |

Team CODEOWNERS require Members read. Extra CODEOWNERS does not request organization Administration write.

For direct users, the service calls GitHub's [Get repository permissions for a user](https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user), which uses Metadata read. For teams, it checks that the team is visible, verifies active membership, and calls [Check team permissions for a repository](https://docs.github.com/en/rest/teams/teams#check-team-permissions-for-a-repository). That endpoint requires Members read and Metadata read, and its result includes inherited access.

These GitHub permission values qualify an owner:

| Owner type | GitHub permission values that qualify |
| --- | --- |
| Direct user | `write`, `maintain`, `admin` |
| Team | `push`, `maintain`, `admin` |

## Repository selection

A selected-repositories installation must include:

- every repository whose pull requests the App evaluates
- the repository that holds organization policy, which defaults to the organization's `.github` repository.

If the installation cannot read organization policy, delegated application approval fails closed. Access to a target repository alone never lets the App infer or copy enrollment policy.

Before removing target access, suspending an installation, or uninstalling the App, hand every affected repository back to native enforcement:

1. Restore GitHub's native **Require review from Code Owners** rule.
2. Remove Extra CODEOWNERS as a required check with an expected source.

After access is removed, the App may no longer be able to revoke a success it published earlier. Removing the organization-policy repository schedules conservative installation-wide fencing for targets that remain accessible, but that asynchronous response does not replace the handoff.

## Webhook subscriptions

Webhook events trigger both pull-request evaluation and broader authority fan-out. The App Manifest explicitly subscribes to the selectable events below. GitHub sends `installation` and `installation_repositories` to every GitHub App and does not permit them in `default_events`; Extra CODEOWNERS still handles both. `installation_target` is an explicit subscription.

Scheduled reconciliation remains the recovery path for a delivery that never reaches the service.

| Event | Relevant action or change | Result |
| --- | --- | --- |
| `pull_request` | Open, reopen, synchronize, ready-for-review, convert-to-draft, edit, label, unlabel, request review, or remove review request | Enqueue that pull request because the head, base, changed files, or label restrictions may have changed. |
| `pull_request_review` | Submit, edit, or dismiss | Enqueue that pull request because approval or changes-requested evidence changed. |
| `check_run` | Rerequest | Enqueue only when GitHub associates the rerequested check with exactly one pull request. |
| `push` | Any non-deletion branch push in a target repository | Schedule durable repository fan-out, then reevaluate open pull requests whose base ref is that branch. A base push can change the merge base, changed paths, or applicable `CODEOWNERS` without changing the pull-request head. Tag pushes and deleted refs are ignored. |
| `push` | On the organization-policy repository's default branch: the effective policy path changed, the push was forced, or changed-path evidence was missing, malformed, or truncated | Schedule installation-wide fan-out. A complete, non-forced push that does not change the policy path is ignored. |
| `label` | Any delivered repository label-definition action | Schedule repository fan-out. Renaming or deleting a label can change current delegation restrictions without a pull-request label event. |
| `member` or `team_add` | Any delivered collaborator or team-access action | Schedule fan-out for open pull requests in that repository. |
| `membership` or `team` | Any delivered team-membership, team-definition, or team-access action | Schedule installation-wide fan-out because several repositories may be affected. |
| `organization` | Any delivered organization or membership action | Schedule installation-wide fan-out because organization membership and identity can affect human CODEOWNER eligibility. |
| `repository` | Delete, rename, or transfer the organization-policy repository; edit its default branch | Schedule installation-wide fan-out because the source or revision of organization trust policy changed. |
| `repository` | Rename, transfer, or unarchive a target repository | Schedule installation-wide fan-out so work is rediscovered under the current repository name and open pull requests in an unarchived repository are reevaluated. Other repository actions are acknowledged without work. |
| `installation` | Create, unsuspend, or accept new permissions | Schedule installation-wide fan-out after the App gains access to current state. Other installation actions are authenticated and acknowledged without work. |
| `installation_repositories` | Add repositories | Schedule installation-wide fan-out after repository selection expands. |
| `installation_repositories` | Remove the organization-policy repository, or omit or malform `repositories_removed` | Retain the delivery, advance the installation authority epoch, and schedule installation-wide fan-out because enrollment policy may have disappeared for every remaining target. |
| `installation_repositories` | Remove only well-formed ordinary target repositories | Authenticate and acknowledge without work. Access is already gone, so the App cannot update checks in those targets; operators must complete the handoff first. |
| `installation_target` | Rename the account on which the App is installed | Schedule installation-wide fan-out because repository full names and organization-scoped owners may have changed. |

Only the listed actions create retained work. Other authenticated deliveries are acknowledged without durable deduplication. In particular, the App's own Check Run updates do not create more retained database traffic.

Pull-request work for the configured organization-policy repository is ignored because that repository remains under native human enforcement. Relevant default-branch policy pushes and the listed repository-lifecycle changes are still processed as installation-wide authority changes.

Webhook payload fields are scheduling hints. Workers fetch current authorization evidence from GitHub before they decide.

Authority work is claimed from broadest scope to narrowest:

1. Installation-wide work.
2. Repository-wide work.
3. Base-specific push work.

Installation-wide work first creates durable repository fences. A repository-wide fence replaces older base-specific rows for the same repository. If one installation and repository would accumulate a 101st distinct base ref, all of those rows collapse into one conservative repository-wide row.

Each repository job lists the affected open pull requests, creates or supersedes their evaluation jobs, and makes a bounded attempt to put managed checks back into `in_progress`. Failures stay pending and retry indefinitely with bounded backoff. Authority work cannot be abandoned safely because an earlier success may still be visible.

Direct subscriptions shorten the stale-success window, but webhook delivery and GitHub API updates remain eventually consistent. Reconciliation periodically revisits otherwise idle open pull requests after a missed or unsupported change.

`merge_group` is not supported. GitHub requires Merge queues read to deliver that event. Extra CODEOWNERS will request that permission only after merge-queue evaluation exists and has passed contract testing.

GitHub's [webhook event reference](https://docs.github.com/en/webhooks/webhook-events-and-payloads) lists current event-to-permission requirements.

## Installation-token scope

The service authenticates as the App to mint short-lived installation tokens. Each request explicitly downscopes the token to:

```text
checks: write
contents: read
members: read
pull_requests: read
```

Statuses is deliberately absent. If a runtime token is compromised, it cannot write commit statuses even though the installation has Statuses write for expected-source selection.

Runtime tokens are also:

- limited to repositories granted to the installation
- cached only in memory, with a conservative refresh window
- never written to the queue, audit store, logs, or Check Run output.

## Permission changes

A release that needs another permission must include:

1. An implementation and threat-model change that names the endpoint or event.
2. Tests that show why the existing permission set is insufficient.
3. Matching changes to the App Manifest and this page.
4. Release notes that identify the new access.
5. Instructions for operators to approve or reject the installation upgrade.

Roadmap features do not justify speculative permissions.
