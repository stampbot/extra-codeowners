# GitHub permissions and webhook events

Extra CODEOWNERS uses GitHub App installation tokens. The requested permissions fetch evaluation evidence, publish the check, receive authority-change events, and support expected-source selection. GitHub's [permission-selection guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app) defines upstream permission behavior.

## Repository permissions

| GitHub App permission | Access | Required operation |
| --- | --- | --- |
| Checks | Read and write | Find, create, and update the App's `Extra CODEOWNERS / approval` Check Run. |
| Contents | Read | Read CODEOWNERS and policy files at an exact commit. No Git checkout or content write is needed. |
| Pull requests | Read | Fetch pull-request base/head state, changed files, labels present on the pull request, and submitted reviews; receive pull-request and review webhooks. |
| Statuses | Read and write at installation only | Make the App selectable as the expected source for organization-level required-check rulesets. Runtime installation tokens omit this permission. |
| Metadata | Read | GitHub grants this baseline permission with repository access. It supplies repository metadata, direct-collaborator permission evidence, label-definition webhooks, and target- and policy-repository lifecycle webhooks. |

The Statuses permission supports GitHub organization-ruleset discovery. Extra CODEOWNERS does not use it at runtime. GitHub documents that an organization ruleset can select a GitHub App as the expected source only after the App is installed with `statuses` write permission in [Require status checks to pass before merging](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging).

The service never calls the commit-status API. Extra CODEOWNERS does not need these permissions:

- Issues
- Actions
- Workflows
- Administration
- Deployments
- Pull requests write.

The App that submits a delegated review is a separate actor. It may need Pull requests write access for its own purpose. Extra CODEOWNERS never submits or dismisses reviews.

## Organization permissions

| GitHub App permission | Access | Required operation |
| --- | --- | --- |
| Members | Read | Query whether a human reviewer is an active team member and whether that visible team grants qualifying write access to the repository; receive collaborator, organization-membership, team-membership, and team-change events used to revoke stale authority. |

Team CODEOWNERS require Members read. Extra CODEOWNERS does not request organization Administration write access.

GitHub documents Metadata read for [Get repository permissions for a user](https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user). [Check team permissions for a repository](https://docs.github.com/en/rest/teams/teams#check-team-permissions-for-a-repository) requires Members read and Metadata read. The team endpoint also verifies inherited access.

| Owner type | Accepted permission values |
| --- | --- |
| Direct user | `write`, `maintain`, `admin` |
| Team | `push`, `maintain`, `admin` |

## Repository selection

For a selected-repositories installation, grant access to:

- every repository whose pull requests Extra CODEOWNERS evaluates
- the configured organization-policy repository containing organization policy (the organization's `.github` repository by default).

If the installation cannot read organization policy, application delegation fails closed. Adding a target repository without the configured organization-policy repository does not authorize the App to infer or copy enrollment policy.

Before removing repository access, suspending the installation, or uninstalling the App, every affected target requires this handoff:

1. Restore GitHub's native **Require review from Code Owners** rule.
2. Remove Extra CODEOWNERS as a required expected-source check.

Once the App loses target access, it cannot revoke an existing success there. Removing the organization-policy repository triggers conservative installation-wide fencing for targets that remain accessible. That asynchronous reaction does not replace the handoff.

## Webhook subscriptions

The event set schedules both pull-request evaluation and durable fan-out after broader authority changes. The App Manifest explicitly subscribes to the selectable events in this table. GitHub automatically sends `installation` and `installation_repositories` to every GitHub App and does not allow those two events to be selected manually, so they are handled at runtime but omitted from `default_events`. `installation_target` remains an explicit subscription. Scheduled reconciliation remains a backstop for deliveries that never reach the service.

| Event | Relevant actions or change | Behavior |
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

Only supported actions enqueue and retain work. Other authenticated deliveries are acknowledged without durable deduplication. This prevents ignored events, including the App's own check updates, from amplifying retained database traffic.

Pull-request work for the configured organization-policy repository is ignored because that repository retains native human enforcement. Relevant default-branch policy pushes and the listed repository lifecycle changes are exceptions. They create installation-wide authority work.

Payload fields are scheduling hints. Workers fetch current authorization evidence from GitHub before deciding.

Authority work is claimed in this order:

1. Installation-wide work.
2. Repository-wide work.
3. Base-specific pushes.

Installation-wide work first splits into durable repository-scoped fences. A repository-wide fence replaces older base-specific rows for that repository. If more than 100 distinct base-ref rows would accumulate for one installation and repository, they collapse into one conservative repository-wide row.

Each repository job enumerates affected open pull requests. It creates or supersedes their durable evaluation jobs and attempts bounded parallel invalidation of managed checks. Failures remain pending and retry indefinitely with bounded backoff. Abandoning authority work could leave a stale success visible.

Direct subscriptions reduce the stale-success window. Delivery and GitHub API processing remain eventually consistent. Reconciliation periodically reevaluates otherwise idle open pull requests after a missed or unsupported change.

`merge_group` is not supported. GitHub requires Merge queues read permission to receive that event. The App will request that permission only after merge-queue evaluation is implemented and contract-tested.

See GitHub's [webhook event reference](https://docs.github.com/en/webhooks/webhook-events-and-payloads) for current event-to-permission requirements.

## Installation-token scope

The service authenticates as the App to mint short-lived installation tokens. At mint time it explicitly downscopes them to:

```text
checks: write
contents: read
members: read
pull_requests: read
```

Statuses is omitted from runtime tokens. A compromised runtime token therefore cannot write commit statuses, even though the App installation has that registration permission for expected-source selection.

Runtime tokens have these additional constraints:

- limited to repositories granted to the installation
- cached in memory with conservative expiration
- never written to the durable queue, audit store, logs, or check output.

## Permission-change procedure

A release that needs a new permission must include:

1. an implementation and threat-model change explaining the endpoint or event
2. tests demonstrating why existing permissions are insufficient
3. updated App manifest and this reference page
4. release notes identifying the new access
5. operator instructions to approve or reject the installation upgrade.

Do not bundle speculative permissions for roadmap features.
