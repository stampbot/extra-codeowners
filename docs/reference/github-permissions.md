# GitHub permissions and webhook events

Extra CODEOWNERS uses a GitHub App installation token and requests only permissions needed to fetch evaluation evidence and publish its check. GitHub's [permission-selection guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app) remains the upstream source for permission behavior.

## Repository permissions

| GitHub App permission | Access | Required operation |
| --- | --- | --- |
| Checks | Read and write | Find, create, and update the App's `Extra CODEOWNERS / approval` Check Run. |
| Contents | Read | Read CODEOWNERS and policy files at an exact commit. No Git checkout or content write is needed. |
| Pull requests | Read | Fetch pull-request base/head state, changed files, labels present on the pull request, and submitted reviews; receive pull-request and review webhooks. |
| Statuses | Read and write at installation only | Make the App selectable as the expected source for organization-level required-check rulesets. Runtime installation tokens deliberately omit this permission. |
| Metadata | Read | GitHub grants this baseline permission with repository access. It supplies repository metadata, direct-collaborator permission evidence, label-definition webhooks, and target- and policy-repository lifecycle webhooks. |

The Statuses permission is a GitHub organization-ruleset discovery requirement, not a runtime capability Extra CODEOWNERS uses. GitHub documents that an organization ruleset can select a GitHub App as the expected source only after the App is installed with `statuses` write permission in [Require status checks to pass before merging](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging). The service never calls the commit-status API. Do not grant Issues, Actions, Workflows, Administration, Deployments, or Pull requests write access to Extra CODEOWNERS.

The App that submits a delegated review is a separate actor and may need Pull requests write access for its own purpose. Extra CODEOWNERS itself never submits or dismisses reviews.

## Organization permissions

| GitHub App permission | Access | Required operation |
| --- | --- | --- |
| Members | Read | Query whether a human reviewer is an active team member and whether that visible team grants qualifying write access to the repository; receive collaborator, organization-membership, team-membership, and team-change events used to revoke stale authority. |

Team CODEOWNERS are a core use case, so Members read is part of the initial permission set. Extra CODEOWNERS does not request organization Administration write access.

GitHub documents Metadata read for [Get repository permissions for a user](https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user), and Members read plus Metadata read for [Check team permissions for a repository](https://docs.github.com/en/rest/teams/teams#check-team-permissions-for-a-repository). The latter also verifies inherited team access. Extra CODEOWNERS accepts direct-user permission values `write`, `maintain`, or `admin`, and team permission flags `push`, `maintain`, or `admin`.

## Repository selection

For a selected-repositories installation, grant access to:

- every repository whose pull requests Extra CODEOWNERS evaluates; and
- the configured organization-policy repository containing organization policy (the organization's `.github` repository by default).

If the installation cannot read organization policy, application delegation fails closed. Adding a target repository without the configured organization-policy repository does not authorize the App to infer or copy enrollment policy.

Before removing a target or organization-policy repository, suspending the installation, or uninstalling the App, restore GitHub's native **Require review from Code Owners** rule and remove Extra CODEOWNERS as a required expected-source check from every affected target. Once the App loses target access, it cannot revoke an existing success there. Removing the organization-policy repository triggers conservative installation-wide fencing for targets that remain accessible, but that asynchronous reaction is not a substitute for the safe handoff.

## Webhook subscriptions

The event set schedules both pull-request evaluation and durable fan-out after broader authority changes. The App Manifest explicitly subscribes to the selectable events in this table. GitHub automatically sends `installation` and `installation_repositories` to every GitHub App and does not allow those two events to be selected manually, so they are handled at runtime but omitted from `default_events`. `installation_target` remains an explicit subscription. Scheduled reconciliation remains a backstop for deliveries that never reach the service.

| Event | Relevant actions or change | Initial behavior |
| --- | --- | --- |
| `pull_request` | Open, reopen, synchronize, ready/draft transition, edit, label/unlabel, review request change | Enqueue the affected pull request because its head, base, files, or label restrictions may have changed. |
| `pull_request_review` | Submit, edit, dismiss | Enqueue the affected pull request because approval or changes-requested evidence changed. |
| `check_run` | Rerequest | Enqueue only when GitHub associates the rerequested check with exactly one pull request. |
| `push` | Any branch push in a target repository | Durably schedule repository fan-out, then reevaluate open pull requests whose base ref names that branch. Every such push matters because it can change the merge base, changed paths, and applicable CODEOWNERS rules without changing the pull-request head. |
| `push` | Effective policy path changed on the organization-policy repository's default branch, or GitHub's changed-path evidence is incomplete | Durably schedule installation-wide fan-out. A complete push that does not change the policy path is ignored. |
| `label` | Any delivered repository label-definition change | Durably schedule repository fan-out because renaming or deleting a label can change a delegation's current restrictions without producing a pull-request label event. |
| `member` or `team_add` | Any delivered repository collaborator or team-access change | Durably schedule fan-out for open pull requests in that repository. |
| `membership` or `team` | Any delivered team-membership, team-definition, or team-access change | Durably schedule installation-wide fan-out because the event can affect CODEOWNER eligibility in multiple repositories. |
| `organization` | Any delivered organization or organization-membership change | Durably schedule installation-wide fan-out because organization membership and identity changes can invalidate human CODEOWNER eligibility. |
| `repository` | Delete, rename, or transfer the configured organization-policy repository; or change its default branch | Durably schedule installation-wide fan-out because the source or revision of organization trust policy changed. |
| `repository` | Rename, transfer, or unarchive a target repository | Durably schedule installation-wide fan-out so work is rediscovered under the current repository identity and an unarchived repository's open pull requests are reevaluated. Other repository events are acknowledged without work. |
| `installation` | Create, unsuspend, or accept new permissions | Durably schedule installation-wide fan-out after the App becomes able to evaluate current state. Other installation actions are authenticated and acknowledged without work. |
| `installation_repositories` | Add repositories | Durably schedule installation-wide fan-out after repository selection expands. |
| `installation_repositories` | Remove the configured organization-policy repository, or provide missing or malformed `repositories_removed` evidence | Conservatively retain the delivery, advance the installation authority epoch, and schedule installation-wide fan-out because enrollment policy may have disappeared for every still-accessible target. |
| `installation_repositories` | Remove only well-formed ordinary target repositories | Authenticate and acknowledge without work. The App has already lost the capability needed to update a check in each removed target, so operators must use the safe access-removal procedure first. |
| `installation_target` | Rename the user or organization account on which the App is installed | Durably schedule installation-wide fan-out because repository full names and organization-scoped owners may have changed. |

Only actions the handler understands enqueue and retain work. Other authenticated deliveries are acknowledged without durable deduplication so ignored events, including the App's own check updates, cannot amplify retained database traffic. Pull-request work for the configured organization-policy repository is likewise ignored because that repository retains native human enforcement. Its relevant default-branch policy push and the listed repository lifecycle changes are exceptions that create installation-wide authority work. Payload fields are scheduling hints, and workers fetch current authorization evidence from GitHub before deciding.

Installation-wide authority work is claimed before repository-wide work, which is claimed before base-specific pushes. Installation-wide work first splits into durable repository-scoped fences. A repository-wide fence replaces older base-specific rows for that repository; if more than 100 distinct base-ref rows would accumulate for one installation and repository, they collapse into one conservative repository-wide row. Each repository job then enumerates affected open pull requests, creates or supersedes their durable evaluation jobs, and attempts bounded parallel invalidation of managed checks. Failures remain pending and retry indefinitely with bounded backoff because abandoning authority work could leave a stale success visible. Direct subscriptions reduce the stale-success window, but delivery and GitHub API processing remain eventually consistent. Reconciliation periodically reevaluates otherwise idle open pull requests after a missed or unsupported change.

`merge_group` is not in the initial supported set. GitHub requires Merge queues read permission to receive that event. The project will request that additional permission only when merge-queue evaluation is implemented and contract-tested.

See GitHub's [webhook event reference](https://docs.github.com/en/webhooks/webhook-events-and-payloads) for current event-to-permission requirements.

## Installation-token scope

The service authenticates as the App to mint short-lived installation tokens. At mint time it explicitly downscopes them to:

```text
checks: write
contents: read
members: read
pull_requests: read
```

Statuses is intentionally omitted, so a compromised runtime token cannot write commit statuses even though the App installation has that registration permission for organization-ruleset expected-source selection. Tokens are also limited to repositories granted to the installation, cached in memory with conservative expiration, and never written to the durable queue, audit store, logs, or check output.

## Permission-change procedure

A release that needs a new permission must include:

1. an implementation and threat-model change explaining the endpoint or event;
2. tests demonstrating why existing permissions are insufficient;
3. updated App manifest and this reference page;
4. release notes identifying the new access; and
5. operator instructions to approve or reject the installation upgrade.

Do not bundle speculative permissions for roadmap features.
