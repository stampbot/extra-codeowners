# Checks and evaluation reference

The default check name is `Extra CODEOWNERS / approval`. Required-check rules must also select the Extra CODEOWNERS App as the expected source. The name alone does not identify the publisher.

This page defines the evaluator's security contract for version 0.1. Compatibility may change before 1.0, but a change must not weaken these rules without a documented security review.

## Evaluation inputs

The evaluator obtains current evidence from GitHub rather than trusting mutable fields in a webhook payload:

- authoritative base repository identity plus base and head commit identifiers
- changed files, including previous names for renames
- standard `CODEOWNERS` and repository policy at the exact base commit
- organization policy from the configured organization-policy repository's default branch
- submitted and dismissed pull-request reviews
- current labels when a delegation requires them
- current user and team identity, repository write-access, visibility, and membership evidence
- enrolled App metadata and bot-account identity.

The webhook is a trigger and delivery identifier, not the source of authorization truth.

The standard file lookup matches GitHub's precedence: `.github/CODEOWNERS`, then `/CODEOWNERS`, then `docs/CODEOWNERS`. The first file found is the only one evaluated.

## Evaluation algorithm

For a pull request in an enrolled repository, Extra CODEOWNERS:

1. Records the current base and head commit identifiers. It verifies that GitHub's authoritative base repository full name matches the queued route. A mismatch is discarded before any Check Run or policy lookup, so a delayed old-name webhook cannot revive work after a rename or transfer. For the canonical route, it creates or updates the named check on the head as `in_progress`. This revokes prior success before the evaluator collects mutable approval evidence.
2. Confirms the leased database generation is still current. A newer trigger leaves the check blocking and lets the superseding generation evaluate.
3. Loads and validates organization policy, repository policy, and standard `CODEOWNERS` from their defined revisions.
4. Paginates changed files. A fetch or API exception leaves the check blocking while the job retries. A returned list that reaches GitHub's 3,000-file maximum produces a diagnostic failure because the evaluator cannot prove completeness.
5. Evaluates both the old and new path for every rename.
6. Applies standard CODEOWNERS pattern precedence to determine the effective owner set for each owned path.
7. Groups paths by effective owner set. Each distinct owner set must be independently satisfied.
8. Accepts an appropriate human's latest effective approving review only when it applies to the current head.
9. Otherwise, considers a current-head application approval. The App's review identity and independently fetched metadata must match organization enrollment. A delegation must also match the path, owner set, and every label restriction.
10. Rejects application substitution for every built-in or organization-defined non-delegable path.
11. Re-fetches the pull request's base and head identifiers before publishing a completed result. It then rechecks the pull-request generation and compares the evaluation row's enqueue-time installation authority epoch with the current epoch. If either revision changed, the result is discarded and queued again. A newer generation from a label or review also discards the stale result. The same applies when an installation-wide authority event advanced the epoch after the job was enqueued.
12. Refuses to complete while a relevant authority fan-out job remains pending, including during retry backoff. This separately blocks publication until work caused by an accepted base-branch, policy, label-definition, membership, team, organization, installation, repository-selection, or repository lifecycle event has fanned out successfully.
13. Before publishing success, confirms that the head commit belongs to exactly this one open pull request at that moment. A head shared by multiple open pull requests produces failure. GitHub Check Runs are commit-scoped and cannot safely represent different pull-request decisions on the same commit.
14. Rechecks the generation after the GitHub completion request. If a trigger raced with publication, the service immediately moves the check back to `in_progress` for the superseding evaluation.

GitHub documents the 3,000-file limit in the [List pull request files API](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files). Extra CODEOWNERS fails closed at exactly 3,000 returned files as well as beyond the limit; it cannot prove whether GitHub truncated that result.

## Evidence and complexity limits

The service applies bounded-work limits before it can authorize a pull request:

| Evidence or operation | Limit | Behavior at the limit |
| --- | --- | --- |
| Repository or organization policy file | 1,000,000 bytes | A larger fetch is rejected. An existing managed check stays blocking while the worker retries; a repository without a managed check remains without one because enrollment cannot be proved. |
| Standard `CODEOWNERS` | 3 MiB | A larger fetch is rejected and the managed check stays blocking while the worker retries because GitHub does not use the file. |
| Changed files | Fewer than 3,000 | Exactly 3,000 or more cannot prove completeness and produces a failing evaluation. |
| Submitted reviews returned by GitHub | At most 1,000 | More than 1,000 exceeds the supported evidence budget and produces a failing evaluation. |
| Current human approvals multiplied by relevant same-organization CODEOWNER teams | At most 250 | A larger membership-query set produces a failing evaluation instead of skipping teams. |
| Conservative changed-path and policy-pattern match estimate | At most 2,000,000 operations | A larger estimate produces a failing evaluation before expensive matching. Renames and the conservative estimate can count two paths per changed file. |

Deterministic limits publish a diagnostic failure after the service safely fetches the complete bounded evidence. Fetch, rate-limit, and database exceptions leave an existing check blocking and retry instead. Broad pull requests must be split, or redundant policy and CODEOWNERS patterns reduced. Ownership must not be weakened to bypass a budget.

## Authority fan-out bounds and precedence

Authority work runs from broadest to narrowest:

1. Installation-wide jobs.
2. Repository-wide jobs.
3. Base-specific push jobs.

An installation-wide job creates current repository-wide fences. A repository-wide job removes older base-specific rows for the same installation and repository because its reevaluation covers every open pull request there.

Repeated pushes to the same base ref coalesce. One installation and repository can retain at most 100 distinct base-ref rows. Adding a 101st distinct ref replaces those rows with one conservative repository-wide job. That job reevaluates all open pull requests, preserving branch coverage while bounding queue growth from contributor-controlled branch names.

Evaluation and authority exceptions remain pending. They retry indefinitely with exponential backoff capped by `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`. A GitHub rate-limit response uses its separately bounded `Retry-After` delay instead. Abandoning authority invalidation after a dependency failure could leave an earlier success visible.

## Owner-set semantics

The final matching `CODEOWNERS` pattern determines the owner set for a path, consistent with GitHub's last-match precedence. Multiple owners on that line form one owner set. An approval from an appropriate member of that set satisfies it; unrelated owners do not.

Extra CODEOWNERS evaluates every distinct owner set represented by changed files. For example:

```text
/service-a/** @example-org/service-a
/service-b/** @example-org/service-b
```

A pull request that changes both services must satisfy both owner sets. A delegation for `@example-org/service-a` cannot satisfy the `service-b` path.

Files with no effective CODEOWNERS match do not create a code-owner obligation. An ownerless last-matching rule clears ownership, matching native CODEOWNERS behavior. The repository's ordinary review count and other checks continue to apply.

## Review semantics

- Only an approving review for the exact current head commit is eligible.
- A direct human `@user` owner counts only while GitHub reports `write`, `maintain`, or `admin` repository permission for that user.
- A human team owner counts only while the reviewer is an active member, the team is visible rather than secret, and GitHub reports that the team grants `push`, `maintain`, or `admin` repository access.
- A newer effective `CHANGES_REQUESTED` review from the same actor prevents that actor's older approval from counting.
- Dismissed approvals do not count.
- Review comments without an approval state do not count.
- A pushed commit invalidates application and human evidence from an older head for this check, even when GitHub's own stale-review setting is looser.
- Application display names and review text never establish identity. The review's immutable bot user ID and exact `<slug>[bot]` login must match organization policy. Independently fetched `GET /apps/{slug}` metadata must also return the enrolled App ID and slug.
- Missing or malformed fields on an opinionated review are incomplete authorization evidence and fail the evaluation. They are not silently skipped.

In this contract, “human” means GitHub returned actor type `User`. Extra CODEOWNERS does not prove personhood. A machine account represented as a normal user can satisfy a standard CODEOWNERS identity or team membership when it has the required current repository access, as it can under native CODEOWNERS. Automation users should not appear in human owner entries or teams.

## Delegation semantics

A delegated application approval is eligible only when all conditions are true:

- repository policy is enabled and valid
- the organization enrolled the application
- the review actor matches the enrolled immutable identity
- the changed path matches a delegation pattern
- `for_owners` includes the effective owner or explicitly contains `"*"`
- every `required_labels` entry is currently present and every `forbidden_labels` entry is absent, using case-insensitive label matching
- the path is not non-delegable.

Labels can only narrow a delegation. Adding or removing a label without a valid application review never satisfies ownership. Extra CODEOWNERS reads current pull-request labels but does not create, remove, or rename them.

Overlapping delegation entries are alternatives, not cumulative filters. One matching entry with satisfied label conditions makes its application eligible for that path and owner set. Different eligible approved applications may cover different paths within the same owner-set requirement. Every path must be covered.

## Check outcomes

| Condition | Result behavior |
| --- | --- |
| A current evaluation is running, retrying after an evidence or API exception, or superseded by newer evidence | After the worker has moved the check to `in_progress`, keep that state blocking rather than successful. Failures remain pending and retry indefinitely with a bounded delay. |
| Relevant authority fan-out work is pending or retrying | Keep the check `in_progress` until authority work succeeds; do not bypass or manually complete failed work. |
| Every owned path's owner set is satisfied and all evidence remains current | Publish success for the evaluated head. |
| A human or application approval is missing or ineligible | Publish a non-successful result with the unresolved owner sets and paths. |
| Checked-in policy or CODEOWNERS is invalid | Publish failure with a check diagnostic. |
| A deterministic evidence or complexity limit is exceeded after safe collection, including 3,000 changed files, more than 1,000 reviews, or a membership or pattern-operation budget | Publish failure with a diagnostic; never truncate or skip authorization evidence. |
| An opinionated review or other required response is malformed, GitHub evidence cannot be fetched, GitHub is rate-limited, or the database fails before a complete decision exists | Keep an existing managed check blocking and retry indefinitely with a bounded delay; never infer success. Some safely classified malformed model evidence produces a completed diagnostic failure instead. |
| Base or head changes during evaluation | Discard the result and queue a new evaluation. |
| The head commit is already shared by multiple open pull requests at publication time | Publish failure. Push a distinct commit to each pull request before Extra CODEOWNERS can authorize it. |
| Repository policy is absent and this App has never created its named check on the current head | Publish no check. The repository remains unenrolled and organization policy alone creates no noise. |
| Repository policy is absent after this App has created its named check on the current head, or policy is explicitly disabled | Publish failure and never count application approvals. GitHub [treats a `neutral` required check as successful](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks), so disabled policy must not use a neutral conclusion. |

## Check detail rendering

Check details expose enough evidence for a repository reader to understand the decision, including owner sets, paths, warnings, and failure diagnostics. That evidence can contain private repository metadata and inherits the repository's GitHub visibility; it must not contain installation tokens, private keys, webhook signatures, authorization headers, or full private webhook payloads.

Repository-controlled paths, owners, and diagnostic text are untrusted rendering inputs. Extra CODEOWNERS applies these transformations before constructing the fixed Markdown layout:

- renders newline, carriage-return, tab, bidirectional, and other control or formatting characters as visible text
- escapes Markdown punctuation in prose fields
- HTML-escapes code-like values inside explicit `<code>` elements.

These transformations prevent a crafted path or policy diagnostic from forging a heading, list item, quote, or HTML element in the Check Run body. They are output-encoding controls, not a confidentiality boundary. Check Run and log access must be restricted as private repository metadata.

The GitHub adapter caps a Check Run output title at 255 characters. Summary and detail text are each capped at 65,535 characters. The adapter applies these publication caps after output encoding. The authorization decision always uses complete bounded evidence. After a stable publication, the durable audit row stores the full structured evaluation result even when the displayed detail tail was omitted. The Check Run body is a reviewer-oriented explanation, not the complete audit record.

## Eventual consistency

Webhook processing and GitHub check display are eventually consistent. For mapped review and pull-request triggers, ingress first records the delivery. It then makes a bounded attempt to create or update the managed check as `in_progress`. A repository with no policy and no prior managed check is skipped.

A fast-path timeout or GitHub API error is logged and acknowledged. The durable worker remains authoritative, and GitHub does not automatically redeliver failed webhooks. The worker keeps the check blocking before collecting mutable evidence. It restores that state if publication races with a newer trigger.

[GitHub creates a Check Run for a specific commit](https://docs.github.com/en/rest/checks/runs#create-a-check-run). Changed paths, base revision, labels, and reviews are pull-request evidence. The publication-time uniqueness check blocks success when another open pull request already uses the head. It cannot prevent a pull request opened or retargeted later from inheriting the earlier commit result until GitHub delivers the event and the service invalidates the check. Scheduled reconciliation limits the duration after a missed delivery but does not remove the window.

This commit-to-pull-request inheritance window blocks production use. Extra CODEOWNERS does not provide native-equivalent enforcement until the window is removed or GitHub contract testing establishes a safe control.

Durable repository routes use mutable `owner/repository` full names rather than GitHub's immutable repository ID. Each evaluation row therefore stores the installation authority epoch current at enqueue time. A repository rename, transfer, or installation-owner rename schedules installation-wide fan-out. The acceptance transaction also advances the epoch.

Work queued under the old identity cannot publish, even when first claimed after fan-out. Current repositories are rediscovered and enqueued with the new epoch. The worker also rejects a delayed old-name delivery accepted after the epoch bump. It compares the queued route with `base.repo.full_name` from the current pull-request response before reading policy or writing a check. GitHub [redirects old repository names after a rename](https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository), so Check Run writes are serialized by installation and head.

This fence does not preserve capabilities that GitHub removes. A repository transfer, repository-selection change, suspension, or uninstall can leave Extra CODEOWNERS unable to revoke an earlier success. Native enforcement must be restored and the Extra CODEOWNERS requirement removed before an intentional access change.

Archived repositories are excluded from authority fan-out and reconciliation because they cannot merge. GitHub's `repository.unarchived` event schedules installation-wide fan-out, which rediscovers an accessible unarchived repository. A prior success may remain visible while the event, durable fan-out, and Check Runs update are processed. After a missed delivery, it may remain until reconciliation. Native enforcement must remain in place until current checks and the negative tests are verified after unarchive.

The following changes create durable authority fan-out work:

- base-branch pushes
- organization-policy changes
- label-definition and collaborator changes
- membership, team, and organization changes
- installation, repository-selection, and repository lifecycle changes.

Removing the configured organization-policy repository from the App's selection creates installation-wide work for targets that remain accessible. Malformed removal evidence has the same result. A well-formed removal containing only ordinary targets is acknowledged without work because access is already gone.

The worker supersedes evaluation for affected open pull requests and attempts to invalidate their checks. A displayed success can remain between the external change, webhook acceptance, fan-out, and GitHub's Check Runs update. Scheduled reconciliation is the recovery path for a missed event. Removing a repository or suspending an installation can also remove the App's ability to revoke its old check. Native human enforcement must be restored before intentionally removing access.

Merge queues are not supported. Support requires reevaluation of `merge_group` state and contract testing before the project can claim high-assurance merge-queue compatibility.
