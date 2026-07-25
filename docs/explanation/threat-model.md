# Threat model

Extra CODEOWNERS helps decide whether a pull request may merge. Its most
important failure is a false success: the check reports that an owner approved
the change when no eligible owner did. That is a security incident, not flaky
CI.

This model covers the self-hosted GitHub App. There is no multi-tenant hosted
service today. Such a service would need a separate design for tenant
isolation, billing, abuse, and privacy before it could launch.

## What the service protects

The protected assets are:

- repository merge policy and the integrity of required checks
- GitHub App private keys, webhook secrets, setup-state secrets, and
  short-lived installation tokens
- organization App enrollment and repository delegation policy
- private repository metadata, including paths, ownership, reviews, and team
  membership
- durable queue and audit records that explain decisions.

## Where trust changes

```text
GitHub -- HMAC-signed POST --> shared HTTPS origin: /webhooks/github
operator network ----------> same origin: health, identity, metrics, setup
                                      |
                                      v
                           queue and audit database
                                      |
                                      v
                               evaluation workers
                                 |           |
              short-lived token  |           | sanitized data
                                 v           v
                               GitHub    checks and operator output

operator secret manager --------> webhook boundary and workers
organization administrators ----> organization enrollment policy ----+
repository maintainers ---------> base-commit delegation policy -----+--> workers
```

GitHub authenticates the installation and signs the webhook body. The request
then crosses the public boundary into the operator's service. Only the exact
webhook path needs public ingress. Health, runtime identity, metrics,
documentation, and setup may share the origin, but the proxy must restrict
those paths to operators. The application does not authenticate them.

A durable queue separates accepting an event from evaluating it. Workers cross
back into GitHub with short-lived, installation-scoped tokens.

Policy crosses a different boundary. Organization administrators decide which
App identities may be trusted. Repository maintainers may delegate to those
Apps, but only within the organization's guardrails and using policy from the
pull request's base commit.

The operator trusts the database and secret manager. Checks, logs, metrics, and
runtime identity usually have a wider audience, so they are lower-trust
outputs. Runtime identity is a service self-report, not provenance evidence.
Credentials and complete private payloads must not cross into any of them.

## Threats, controls, and residual risk

No one control carries the design. Each row names the control that reduces a
threat and the risk left after that control. The residual-risk column is part
of the security contract.

| Threat | Control | Residual risk |
| --- | --- | --- |
| A pull-request author edits delegation policy to authorize that pull request | Load repository policy and CODEOWNERS from the exact base commit. Assign policy paths to humans in CODEOWNERS and make those paths non-delegable by default. | A merged policy change governs later pull requests, so human review of it remains critical. |
| A pull-request author edits the DCO checker that evaluates the same pull request | Keep the active workflow read-only and secretless. The replacement evaluator is pure, does not execute pull-request content, and is intended to run from an independently controlled GitHub App. | The independent caller and required context do not exist yet. Until issue #40 is complete, the active workflow remains review evidence rather than an enforcement boundary. |
| A retarget or force-push changes the DCO commit range while evidence is collected | Select commit IDs through the GraphQL pull-request connection, require the exact repository, base, and head identity on every list and detail response, and require matching event, before, and after snapshots. | Publication-time revalidation is not implemented. Same-repository and private-fork commit-node reads still need live contract tests before rollout. |
| Organization enrollment policy is changed maliciously | Keep enrollment in the separately governed organization-policy repository (`.github` by default), with native human CODEOWNER enforcement. | Compromise of that repository's merge authority can expand application trust across repositories. |
| The organization-policy repository or installation account is renamed, transferred, deleted, changes default branch, or the policy repository is removed from App selection | Subscribe to repository, organization, installation-target, and repository-selection events. Treat malformed removal evidence as loss of the policy source, durably fan out current-state reevaluation, store an enqueue-time installation authority epoch, and reject queued routes that disagree with GitHub's authoritative base-repository identity. | Access loss can prevent revocation. A visible success may remain until the delivered event and fan-out finish, or until reconciliation recovers a missed delivery. |
| A target repository is renamed or transferred | Subscribe to repository lifecycle events, advance the enqueue-time installation authority epoch, rediscover current repository names, reject delayed old-name jobs against the authoritative base-repository identity, and serialize Check Run writers by installation and head. | A transfer can remove App access before an earlier success is revoked. Use the safe access-removal sequence unless destination access is already assured. |
| An archived repository with an earlier success is unarchived | Subscribe to `repository.unarchived`, durably schedule installation-wide current-state reevaluation, and leave native code-owner enforcement in place until it finishes. | The old success may remain through webhook processing and fan-out, or until reconciliation recovers a missed delivery. |
| An application expands its authority through workflow or local-action code | Make `.github/workflows/**` and `.github/actions/**` non-delegable by default. | A privileged workflow can invoke code elsewhere. Organization guardrails must include those repository-specific paths. |
| An application changes its own approval policy or decision code | Make Stampbot's root `/stampbot.toml` non-delegable by default. Require organization guardrails for every other enrolled App's local configuration and transitive decision inputs. | Extra CODEOWNERS cannot infer arbitrary App control files. An incomplete inventory can permit self-expansion. |
| A forged or modified webhook asks for success | Verify HMAC-SHA256 over the raw body before parsing, then fetch authorization evidence from GitHub. | A stolen webhook secret permits forged triggers, but not forged GitHub API evidence. |
| A crafted path, owner, or diagnostic forges trusted-looking Check Run content | Use a fixed evidence layout, render controls visibly, escape Markdown prose, and HTML-escape code-like values. | Check details still expose decision metadata to anyone who can view the repository. |
| GitHub redelivers an event | Deduplicate `X-GitHub-Delivery` transactionally. The retained delivery keeps the original head identity and the shared-generation token accepted for that head. If a pending fast-path retry discovers that the pull request has moved, it separately advances the live head's shared and evaluation generations and queues that head for invalidation. Prune delivery IDs after a configurable retention period. | An expired ID may enqueue another evaluation, but authorization evidence is fetched again. Retention must cover the operator's redelivery window. |
| A webhook is missed | Subscribe to authority changes, reconcile accessible open pull requests periodically, and support operator-requested GitHub redelivery. When reconciliation inserts missing work for a canonical head, it advances the shared generation in the same transaction. | A stale result can remain until the scan inserts work and a worker reaches GitHub. Reconciliation leaves an existing active or delayed row unchanged. |
| A head or base-branch commit arrives during evaluation | Require reviews for the exact head, fetch base and head again before publishing, and enqueue direct or base-ref fan-out work. | GitHub's check display remains eventually consistent during rapid changes. |
| Contributor-controlled branch names create an unbounded base-push queue | Coalesce the same base ref, retain at most 100 distinct base-ref rows per installation and repository, collapse overflow into one conservative repository-wide job, and claim broader authority work first. | A repository-wide job uses more GitHub API calls than a base-specific job and can temporarily increase merge latency. |
| Several pull requests share one head commit but need different decisions | Refuse success when another open pull request already uses the head. Every accepted direct trigger advances a shared generation and durably queues revocation for that exact commit. The invalidation worker resets an existing check by ID, fetches current state for every commit-to-pulls candidate, and fans out their evaluations. Publication requires the captured, current, and invalidated generations to match. | A pull request opened or retargeted after success can inherit that commit-scoped result until GitHub delivers its webhook and the service accepts it. The commit-to-pulls response has no completeness marker, so an omitted candidate is also undetectable. These provider assumptions block production use until the live contract proves the control. |
| A mapped review, label, pull-request, or rerequest trigger races with evaluation | Record the trigger, its pull-request generation, its shared-head generation, and pending exact-head invalidation in one transaction. Bind the fast path to that generation. Lease durable invalidation ahead of evaluation, and recheck lease ownership immediately before the reset. Before completion, verify the captured generation is current and invalidated. Recheck the evaluation lease immediately before and after the completed write while holding the head publication guard. Treat an error or cancellation during the write or post-publication verification as uncertainty and attempt a shielded reset to `in_progress` before releasing the guard. | GitHub may apply a write before its response is lost. A hard process stop or failed reset can leave that completed result visible until fast invalidation or durable retry reaches GitHub. |
| A policy label is renamed or deleted | Subscribe to label-definition events, fan out repository evaluation, and fetch current pull-request label names. | Success may remain visible while processing and fan-out finish, or until reconciliation recovers a missed delivery. |
| A rename moves content across ownership boundaries | Evaluate both the old and new path. | GitHub must provide the previous path. Incomplete rename evidence fails closed. |
| GitHub truncates a very large pull request | Paginate and reject evaluation at GitHub's 3,000-file API maximum because completeness can no longer be proved. | Such a pull request must be split before it can use Extra CODEOWNERS. |
| Adversarially large payloads or policies exhaust service resources | Bound webhook bodies, policy and CODEOWNERS size, review and membership evidence, GraphQL DCO pages, aggregate commit-message bytes, and path-pattern operations. Project sign-off and signature predicates instead of retaining raw messages or signature blobs. Reject unknown policy fields. | Work beyond a bound blocks authorization and may require splitting the pull request or policy. |
| An unenrolled bot copies a trusted App's name | Require the review bot's user ID and exact `<slug>[bot]` login. Independently call `GET /apps/{slug}` and match App ID and slug to organization policy, with expected-source checks. | GitHub review APIs do not expose every provenance field uniformly. Adapters still need live contract tests. |
| Automation uses a normal GitHub user account | Govern CODEOWNERS users and team membership outside this service. Reserve application delegation for actors GitHub identifies as Apps. | Actor type `User` does not prove personhood. A machine user with owner authority is treated like any other user. |
| Human or team ownership eligibility changes after approval | Revalidate direct-user repository permission, team visibility, repository access, and active membership. Subscribe to repository and organization authority events and reconcile open pull requests. | Success may remain stale while event delivery and fan-out run, or until reconciliation recovers a missed event. |
| App access is suspended or an ordinary target repository is removed from its installation | Keep native human enforcement until access changes finish, and restore it before intentional removal. Acknowledge a well-formed ordinary-target removal without pretending revocation succeeded. | Once access is gone, Extra CODEOWNERS cannot revoke an existing check in that repository. |
| A trusted application is compromised | Limit delegation by path and effective owner, then preserve non-delegable paths. Use labels for workflow routing, not as a separate trust boundary. | Pull-request write permission lets the application change labels as well as submit its review. Within the path-and-owner scope, the application is intentionally trusted to approve. |
| The operator loses GitHub API access or reaches a rate limit | Fail closed, retry indefinitely with a configured maximum ordinary backoff, honor separately bounded provider `Retry-After` or reset timing, and expose queue state and API failures. | Availability failures block merges while retries continue at bounded intervals. The service has no remaining-quota metric. |
| Another actor publishes a check with the same name | Require the Extra CODEOWNERS App as the expected source. Register the App with Commit statuses (`statuses`) write so GitHub can offer it as an organization-ruleset source, then omit that permission from runtime tokens. | A rule configured by name alone is vulnerable to source confusion. |
| A proxy, browser, or observer captures App Manifest setup material | Require HTTPS and signed, short-lived state; suppress access logs; return no-store pages with a restrictive content security policy; disable setup after use. | The one-time callback and displayed conversion response contain credentials. A compromised operator endpoint or browser can disclose them. |
| The service or database is compromised | Use least-privilege App permissions, short-lived installation tokens, a secret manager, encrypted transport, and restricted database access. | Service compromise can falsify checks within installed repositories. Rotate the App key and investigate every affected check. |

## Invariants

Implementation details may change. These properties may not:

1. Incomplete or contradictory evidence never yields success.
2. A review for an older head never satisfies the current head.
3. A repository cannot enroll its own trusted application.
4. A label is never approval evidence by itself.
5. Every distinct effective CODEOWNERS owner set is satisfied independently.
6. Both names of a renamed file are evaluated.
7. Check publication is bound to the exact evaluated head and the expected App
   source.
8. A worker never treats an uncertain completed write or post-publication
   generation check as current. It attempts a shielded reset to `in_progress`
   before releasing the writer guard and preserves the original exception or
   cancellation so durable work remains retryable.
9. Relevant pending or retrying authority fan-out prevents publication of a
   completed result.
10. A shared-head generation cannot publish until durable invalidation for that
    exact generation has finished.
11. Credentials and raw private payloads never appear in logs, metrics, checks,
    or audit details.
12. An independent DCO result identifies the repository, pull request, base
    SHA, and head SHA whose snapshot-bound commit connection produced it.

Invariant 7 has an important limit. GitHub does not offer a pull-request-scoped
required Check Run, so two pull requests can inherit the check attached to one
commit. Shared-head detection and durable exact-head invalidation close the
worker race after acceptance. They cannot eliminate the period before GitHub
delivers and Extra CODEOWNERS accepts the relevant event.

The opt-in [live GitHub contract fixture](../how-to/run-live-github-contract.md)
measures required-check invalidation, shared-head inheritance, retargeting,
expected-source rulesets, App reviews, and sanitized webhook payloads against a
disposable GitHub.com repository. A run is evidence for the tested API and
account at that recorded time. It cannot prove instant or reliable webhook
delivery, and it does not remove the production blocker while success can be
inherited before invalidation. Its delivery-log probe follows GitHub's
pagination metadata within fixed bounds. When another page remains, an unseen
delivery is incomplete evidence, not evidence that the delivery was absent.
The same rule applies to cleanup: after an ambiguous repository create,
repeated 404 responses trigger manual verification rather than a successful
cleanup claim.

## Why some paths cannot be delegated

Some files decide who may approve. Others decide what trusted automation will
do. If an App can approve changes to those files, it may be able to enlarge its
own authority.

Extra CODEOWNERS therefore has this built-in non-delegable set:

- every standard CODEOWNERS location
- the effective Extra CODEOWNERS policy path, which defaults to
  `.github/extra-codeowners.toml`
- Stampbot's root `/stampbot.toml`
- `.github/workflows/**`
- repository-local actions under `.github/actions/**`.

Organization policy may add paths, and repository policy cannot remove them.
When a changed, owned path matches the combined set, an App approval cannot
replace approval from an eligible human.

The service cannot discover every input used by a privileged workflow or an
approving App. Stampbot is one known case, not a complete inventory. Use
organization `guardrails.non_delegable_paths` for each enrolled App's local
configuration, rules, prompts, generated inputs, and decision code. Include
repository-specific release scripts, deployment helpers, action code outside
`.github/actions/`, and anything else that can change trusted behavior. Review
the transitive set whenever an App, workflow, or approval policy changes.

“Non-delegable” is about approval, not authorship or contents. Apps may appear
in workflows and configuration. They just cannot stand in for the appropriate
human when a pull request changes an owned protected path.

Nor does the list assign an owner. Repositories must still cover these paths in
standard CODEOWNERS. An unowned path creates no code-owner requirement in
GitHub's native model or in Extra CODEOWNERS.

## What the insecure-changes escape hatch changes

Setting `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` removes the built-in
non-delegable set for every installation served by that process. The setting's
name is deliberately blunt. While enabled, it produces a high-severity startup
warning and an always-on metric.

It does **not**:

- remove organization-defined non-delegable paths
- create or broaden repository delegation
- bypass path, owner, label, identity, or exact-head checks
- change GitHub's numeric review-count requirement
- bypass another required check.

Use the escape hatch only when a separate, independently enforced control
protects ownership files, Extra CODEOWNERS and Stampbot policy, workflows, and
local actions. Keep that deployment away from repositories that rely on the
built-in guardrails. Record the exception owner, reason, compensating control,
and expiry.

## Secrets

Secrets give the service its GitHub identity:

- Store the App private key and webhook secret in a managed secret store, not
  in a repository, image, policy file, command line, or log field.
- Prefer file-mounted secrets over multiline environment values when the
  platform supports them.
- Let the runtime identity read only the specific secret versions it needs.
- Rotate the webhook secret and App private key after suspected disclosure,
  operator departure, or service compromise.
- Treat installation access tokens as short-lived cache material. Never persist
  them in the durable queue or audit store.

After private-key compromise, remove its authority first: suspend the App or
revoke the key. Restore native human code-owner enforcement on affected
repositories, rotate credentials, and review every check published during the
exposure window.

## Boundaries not yet implemented

The implementation does not currently cover:

- GitHub Enterprise Server, until named server versions have been tested
- high-assurance merge queues, until `merge_group` reevaluation is implemented
  and tested
- a transfer or installation change that removes repository access before
  control returns to native enforcement
- tenant isolation or service-level commitments for a hosted multi-tenant
  service
- arbitrary third-party callers; the webhook endpoint authenticates GitHub,
  not a general API client.
