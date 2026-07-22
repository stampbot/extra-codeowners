# Checks and evaluation reference

The default Check Run name is `Extra CODEOWNERS / approval`. A required-check rule must also select the Extra CODEOWNERS App as its expected source; the name alone does not identify who published a check.

This page defines the evaluator's security contract for version `0.1`. Compatibility may change before `1.0`, but no change may weaken this contract without a documented security review.

## Evaluation evidence

The evaluator fetches authorization evidence from GitHub instead of trusting mutable webhook fields. It uses:

- the current base repository identity, base commit, base ref, and head commit
- every changed file, including the previous name of a renamed file
- repository policy and standard `CODEOWNERS` from the exact base commit
- organization policy from the configured policy repository's default branch
- submitted and dismissed pull-request reviews
- current pull-request labels when delegations depend on them
- current user permission, team visibility, repository access, and active membership
- enrolled App metadata and immutable bot-account identity.

A webhook supplies a trigger and a delivery ID. It does not supply authorization truth.

Standard `CODEOWNERS` lookup follows GitHub's precedence: `.github/CODEOWNERS`, then `CODEOWNERS` in the repository root, then `docs/CODEOWNERS`. The first file found is the only one evaluated.

## Evaluation sequence

For an open pull request in an enrolled repository, Extra CODEOWNERS:

1. Fetches the pull request and records its current base and head revisions. The authoritative `base.repo.full_name` must match the queued repository. A mismatch is discarded before any policy read or Check Run write, so a delayed old-name delivery cannot revive work after a rename or transfer.
2. Creates or updates the App's named Check Run on the head as `in_progress`. This revokes an earlier success before mutable approval evidence is collected. A repository with no policy and no existing managed check remains unenrolled and gets no check.
3. Confirms that the worker still owns the current leased database generation. A newer trigger leaves the check blocking for the superseding generation.
4. Loads and validates repository policy. When policy is enabled, it also loads organization policy and standard `CODEOWNERS` from their defined revisions. Disabled policy finishes with a diagnostic failure instead of collecting approval evidence.
5. For enabled policy, checks the reported changed-file count, then paginates GitHub's pull-files API. API or transport failures leave the check blocking while the durable job retries. A count of 3,000 or more produces a diagnostic failure because GitHub cannot prove that the list is complete.
6. Evaluates both the old and new path of every rename.
7. Applies last-match-wins `CODEOWNERS` precedence and groups changed paths by their effective owner set. Every distinct owner set is a separate requirement.
8. Accepts a qualifying human's latest effective approval only when that review targets the exact current head.
9. Otherwise, considers application approvals for the current head. The review actor and independently fetched App metadata must match organization enrollment. The delegation must match the path and owner set, and its label restrictions must all pass.
10. Rejects application substitution for every effective non-delegable path.
11. Fetches the pull request again before publication. A changed state, base ref, base commit, head commit, changed-file count, or label set discards the result and queues another evaluation.
12. Under the publication guards, rechecks the evaluation generation and the installation authority epoch stored when the row was enqueued. It also refuses to finish while relevant authority fan-out is pending, including during retry backoff.
13. Before publishing success, confirms that the head belongs to exactly this one open pull request. A shared head produces failure because GitHub Check Runs belong to commits, not individual pull requests.
14. Checks for a newer generation again after GitHub accepts the completed Check Run. If a trigger raced with publication, the service immediately returns the check to `in_progress` for the next evaluation.

GitHub documents the 3,000-file ceiling in [List pull request files](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files). Extra CODEOWNERS fails at exactly 3,000 because it cannot tell whether GitHub truncated that response.

## Evidence and work limits

The service applies these limits before it can authorize a pull request:

| Evidence or operation | Accepted limit | Behavior beyond the limit |
| --- | --- | --- |
| Repository or organization policy file | 1,000,000 bytes | Reject the fetch. An existing managed check stays `in_progress` while the worker retries. A repository with no managed check remains without one because enrollment cannot be proved. |
| Standard `CODEOWNERS` | 3 MiB | Reject the fetch and keep the managed check blocking while the worker retries. GitHub also ignores a `CODEOWNERS` file larger than 3 MiB. |
| Changed files | Fewer than 3,000 | A reported or returned count of 3,000 or more produces a diagnostic failure because completeness cannot be proved. |
| Reviews returned by GitHub | At most 1,000 | A 1,001st review exceeds the evidence budget and produces a diagnostic failure. |
| Current human approvals multiplied by relevant same-organization CODEOWNER teams | At most 250 | A larger membership-query set produces a diagnostic failure instead of skipping teams. |
| Conservative changed-path and policy-pattern estimate | At most 2,000,000 matches | A larger estimate produces a diagnostic failure before expensive matching. The estimate reserves two paths for every changed file to cover renames. |

Changed-file, review, membership, and match-operation limits produce failure without truncating or skipping authorization evidence. Oversized policy and `CODEOWNERS` fetches follow the blocking retry behavior in the table. Other GitHub API, rate-limit, transport, and database exceptions also keep an existing check blocking and leave the job pending. Large pull requests must be split, or redundant policy and `CODEOWNERS` patterns reduced. Ownership must not be weakened to fit the budget.

## Authority fan-out order and bounds

The worker claims authority work from broadest scope to narrowest:

1. Installation-wide jobs.
2. Repository-wide jobs.
3. Base-specific push jobs.

An installation-wide job creates a current repository-wide fence for each accessible, unarchived target. A repository-wide job removes older base-specific rows for that installation and repository because it covers every open pull request there.

Repeated pushes to one base ref coalesce. One installation and repository may retain at most 100 distinct base-ref rows. A 101st distinct ref replaces them with one repository-wide job, which reevaluates all open pull requests while bounding queue growth from contributor-controlled branch names.

Evaluation and authority exceptions remain pending. Ordinary failures retry indefinitely with exponential backoff capped by `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`. A GitHub rate-limit response uses its own bounded provider delay. Authority invalidation cannot be abandoned after a dependency failure because an earlier success may still be visible.

## Owner-set behavior

The last matching `CODEOWNERS` pattern determines a path's owner set. Multiple owners on that line are alternatives within one set: an eligible approval from any one of them satisfies the human requirement.

Every distinct owner set represented by changed files must be satisfied independently. For example:

```text
/service-a/** @example-org/service-a
/service-b/** @example-org/service-b
```

A pull request that changes both services has two requirements. A delegation for `@example-org/service-a` cannot satisfy the `service-b` path.

A path with no effective `CODEOWNERS` match creates no owner requirement. An ownerless last-matching rule also clears ownership, following native last-match behavior. Ordinary review-count rules and other required checks still apply.

## Human and application reviews

Human review evidence follows these rules:

- Only `APPROVED` on the exact current head is eligible.
- The latest `APPROVED`, `CHANGES_REQUESTED`, or `DISMISSED` review from an actor determines that actor's effective opinion. A review comment does not replace an approval.
- A newer `CHANGES_REQUESTED` or `DISMISSED` review prevents an older approval from counting.
- A direct `@user` owner qualifies only while GitHub reports `write`, `maintain`, or `admin` repository permission.
- A team owner qualifies only while the reviewer is an active member, the team is visible rather than secret, and GitHub reports `push`, `maintain`, or `admin` repository access for the team.
- A new commit invalidates both human and application approvals from the old head for this check, even if GitHub's native stale-review setting would keep them.

For an application review, the immutable bot user ID, exact `<slug>[bot]` login, App ID, and App slug must match organization policy. Extra CODEOWNERS also fetches `GET /apps/{slug}` and requires GitHub to return the enrolled App ID and slug. Display names and review text never establish identity.

Missing or malformed fields in an opinionated review are incomplete authorization evidence. They are never silently skipped. Evidence that can be classified safely produces a completed diagnostic failure; an API response that cannot be interpreted safely leaves the check blocking while the job retries.

In this contract, “human” means GitHub returned actor type `User`. The service does not prove personhood. A machine account represented as a normal user can satisfy a direct owner or team requirement when it has the required current access, just as it can under native `CODEOWNERS`. Automation users should not be placed in human owner entries or teams.

## Application delegation

A delegated application approval is eligible only when all of these conditions hold:

- repository policy is present, enabled, and valid
- organization policy enrolls the application
- the review actor matches the complete enrolled identity
- the changed path matches a delegation pattern
- `for_owners` contains an effective owner or the explicit wildcard `"*"`
- every `required_labels` value is present and every `forbidden_labels` value is absent
- the path is not non-delegable.

Label comparison is case-insensitive. Labels only narrow a delegation: changing a label without a valid application review never satisfies ownership. Extra CODEOWNERS reads labels but does not create, remove, or rename them.

Overlapping delegation entries are alternatives. If one matching entry for an application passes its label conditions, that application is eligible for the path and owner set. Different approved applications may cover different paths in one owner-set requirement, but every path must have eligible approval coverage.

Unless `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true`, these built-in patterns are non-delegable:

```text
/CODEOWNERS
/.github/CODEOWNERS
/docs/CODEOWNERS
/stampbot.toml
/.github/workflows/**
/.github/actions/**
/<configured repository policy path>
```

The last entry is the configured `EXTRA_CODEOWNERS_POLICY_PATH`, rooted for matching. The insecure-changes escape hatch removes only these built-ins; organization-defined non-delegable paths remain active. When the escape hatch is enabled, the Check Run includes a warning and `extra_codeowners_insecure_changes_enabled` reports `1`.

## Check results

The result for each terminal or retry condition is listed below.

| Condition | Check behavior |
| --- | --- |
| Evaluation is running, retrying after a dependency exception, or superseded by newer evidence | Keep the managed check `in_progress`. Pending work retries indefinitely with bounded delay. |
| Relevant authority fan-out is pending or retrying | Keep the check `in_progress` until the fan-out succeeds. Do not bypass or manually complete it. |
| Every owned path's owner set is satisfied and evidence remains current | Publish `success` for the evaluated head. |
| A required human or application approval is missing or ineligible | Publish `failure` with the unresolved owner sets and paths. |
| Checked-in policy or `CODEOWNERS` is invalid | Publish `failure` with a diagnostic. |
| A deterministic evidence or complexity limit is exceeded | Publish `failure` with a diagnostic. Never truncate or skip evidence. |
| An opinionated review or required response is malformed, GitHub evidence cannot be fetched, GitHub is rate-limited, or the database fails before a complete decision exists | Keep an existing managed check blocking and retry. Some malformed model evidence that can be classified safely produces a completed diagnostic failure. Success is never inferred. |
| Base, head, changed-file count, or labels change during evaluation | Discard the result and queue another evaluation. |
| Several open pull requests share the head at success-publication time | Publish `failure`. Each pull request needs a distinct commit before the check can authorize it. |
| Repository policy is absent and this App has never created its named check on the current head | Publish no check. Organization policy alone does not enroll a repository. |
| Repository policy disappears after this App has created the named check, or policy sets `enabled=false` | Publish `failure` and reject application substitution. GitHub [treats a `neutral` required check as passing](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks), so disabled policy never uses `neutral`. |

## Check output and audit detail

Check details list owner sets, paths, warnings, and failure diagnostics. That content may reveal private repository metadata and inherits the repository's GitHub visibility. It must never contain installation tokens, private keys, webhook signatures, authorization headers, or complete private webhook payloads.

Paths, owners, and diagnostic text are repository-controlled and therefore untrusted. Before building the fixed Markdown layout, Extra CODEOWNERS:

- renders newline, carriage-return, tab, bidirectional controls, other control and formatting characters, and Unicode line and paragraph separators as visible text
- escapes Markdown punctuation in prose fields
- HTML-escapes code-like values inside explicit `<code>` elements.

This encoding prevents a crafted path or diagnostic from forging a heading, list, quote, or HTML element. It is not a confidentiality boundary. Check Run and log access must be restricted like any other private repository metadata.

The GitHub adapter caps the output title at 255 characters. Summary and detail text are each capped at 65,535 characters after output encoding. The authorization decision always uses the complete bounded evidence. After a stable publication, the audit row stores the full structured result even when GitHub's displayed detail omits the tail. The Check Run is a reviewer-facing explanation, not the complete audit record.

## Eventual consistency

Webhook processing and Check Run display are eventually consistent. For a mapped pull-request or review trigger, ingress first records the delivery and then makes a bounded attempt to set the managed check to `in_progress`. A repository with no policy and no previous managed check is skipped.

A fast-path timeout or GitHub API error is logged and acknowledged after durable acceptance. GitHub does not automatically redeliver failed webhooks, so the durable worker remains authoritative. It puts the check into a blocking state before collecting mutable evidence and restores that state if publication races with a newer trigger.

GitHub [creates a Check Run for a commit](https://docs.github.com/en/rest/checks/runs#create-a-check-run), while changed paths, labels, base revision, and reviews belong to a pull request. The publication-time uniqueness check prevents success when another open pull request already uses the head. It cannot stop a pull request opened or retargeted later from temporarily inheriting that commit's earlier success. The next webhook or scheduled reconciliation invalidates it, but neither mechanism removes the window.

This commit-to-pull-request inheritance window blocks production use. Extra CODEOWNERS does not provide native-equivalent enforcement until the window is removed or live GitHub contract testing proves a safe control.

Durable routes use mutable `owner/repository` names rather than immutable repository IDs. Each evaluation row therefore records the installation authority epoch current at enqueue time. A repository rename, transfer, or installation-owner rename advances that epoch and schedules installation-wide fan-out.

Work queued under an older epoch cannot publish, even if a worker first claims it later. The worker rediscovers repositories under current names, and it rejects a delayed old-name event when the current pull request's `base.repo.full_name` does not match the queued route. Because GitHub [redirects old repository names](https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository), Check Run writes are also serialized by installation and head.

These fences cannot preserve a capability after GitHub removes App access. A transfer, repository-selection change, suspension, or uninstall may leave the App unable to revoke an earlier success. Restore native enforcement and remove the Extra CODEOWNERS required check before making an intentional access change.

Archived repositories are excluded from authority fan-out and reconciliation because they cannot merge. A `repository.unarchived` event schedules installation-wide fan-out and rediscovers the target. An earlier success may remain visible until the event, fan-out, and Check Run updates complete, or until reconciliation recovers a missed event. Keep native enforcement enabled until current checks and negative tests pass after unarchive.

The following changes create durable authority fan-out:

- non-deletion pushes to target base branches
- organization-policy changes
- label-definition and collaborator changes
- membership, team, and organization changes
- installation, repository-selection, and repository-lifecycle changes.

Removing the configured organization-policy repository from App selection creates installation-wide work for targets that remain accessible. Missing or malformed removal evidence is treated the same way. A well-formed removal containing only ordinary target repositories is acknowledged without work because access is already gone.

The worker supersedes affected evaluations and attempts to invalidate their checks. A success can remain visible between the external change, webhook acceptance, durable fan-out, and GitHub's Check Run update. Reconciliation is the recovery path for missed delivery. If access has already been removed, it may be impossible for the App to update the old check at all.

Merge queues are not supported. Safe support requires `merge_group` evaluation and live contract testing.
