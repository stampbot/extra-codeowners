# Threat model

Extra CODEOWNERS helps decide whether a pull request may merge. The failure that
matters is a false success: the check says an owner approved work when no
eligible owner did. Treat that as a security incident, not a flaky-CI problem.

This threat model covers the self-hosted GitHub App. A multi-tenant hosted
service does not exist yet. Before one can launch, its design must add explicit
analysis for tenant isolation, billing, abuse, and privacy.

## Assets

The service protects five things:

- repository merge policy and the integrity of required checks
- GitHub App private keys, webhook secrets, setup-state secrets, and short-lived
  installation tokens
- organization App enrollment and repository delegation policy
- private repository metadata, including paths, ownership, reviews, and team
  membership
- durable queue and audit records that explain decisions

## Trust boundaries

GitHub authenticates an installation and signs each webhook request. That
request crosses the public boundary into the operator's service. Workers cross
back into GitHub with short-lived, installation-scoped tokens.

People cross a different boundary. Organization administrators decide which
App identities the organization trusts. Repository maintainers may delegate
those identities, but only inside the organization's guardrails.

The operator trusts the database and secret manager. Logs, metrics, and check
summaries have a wider audience, so they are lower-trust outputs. Credentials
and full private payloads must never reach them.

## Adversaries and failure modes

No single control carries this design. The table pairs each threat with the
control that narrows it and the risk that remains afterward. That last column
is part of the contract.

| Threat | Control | Residual risk |
| --- | --- | --- |
| A pull-request author edits delegation policy to authorize the same pull request | Load repository policy and CODEOWNERS from the exact base commit; assign policy paths to humans in CODEOWNERS and make them non-delegable by default | A merged policy change affects later pull requests, so its human review remains critical |
| Organization enrollment policy is changed maliciously | Keep enrollment in the separately governed organization-policy repository (`.github` by default) and retain native human CODEOWNER enforcement there | Compromise of organization-policy merge authority can expand application trust across repositories |
| The organization-policy repository or installation account is renamed, transferred, deleted, changes default branch, or the policy repository is removed from App selection | Subscribe to repository, organization, installation-target, and repository-selection events; treat malformed removal evidence as policy-source loss; durably fan out current evaluation; store an enqueue-time installation authority epoch; reject a queued route that differs from GitHub's authoritative base repository identity | Access loss can prevent revocation, and a displayed success may remain while a delivered event and fan-out are processed or until reconciliation after a missed delivery |
| A target repository is renamed or transferred | Subscribe to target-repository lifecycle events; advance the enqueue-time installation authority epoch; rediscover current repository names; reject delayed old-name jobs against the authoritative base repository identity; serialize Check Run writers by installation and head | A transfer can remove the App's access before it revokes an earlier success; use the safe access-removal sequence whenever destination access is not already assured |
| An archived repository with an earlier success is unarchived | Subscribe to `repository.unarchived`, durably schedule installation-wide current-state reevaluation, and keep native code-owner enforcement in place while that work finishes | A stale success may remain between unarchive, webhook processing, fan-out, and the Check Runs update, or until reconciliation after a missed delivery |
| An application expands its authority through workflow or local-action code | `.github/workflows/**` and `.github/actions/**` are non-delegable by default | Privileged workflows may invoke scripts elsewhere; organization guardrails must cover those repository-specific paths |
| An application changes its own approval policy or decision code | Make Stampbot's root `/stampbot.toml` non-delegable by default, and require organization guardrails for every other enrolled App's repository-local configuration and transitive decision inputs | Extra CODEOWNERS cannot infer arbitrary App-specific control files, so an incomplete inventory can permit self-expansion |
| A forged or modified webhook requests success | Verify HMAC-SHA256 over the raw body before parsing; fetch authorization evidence from GitHub | Compromise of the webhook secret permits forged triggers, but not forged GitHub API evidence |
| A crafted path, owner, or diagnostic forges trusted-looking Check Run content | Render controls visibly, escape Markdown prose, and HTML-escape code-like values inside a fixed evidence layout | Check details still disclose decision metadata to everyone who can view the repository |
| GitHub redelivers an event | Deduplicate `X-GitHub-Delivery` transactionally and prune IDs after a configurable retention interval | An expired ID can enqueue a fresh evaluation, but authorization evidence is re-fetched; the retention interval must cover the operational redelivery window |
| A webhook is missed | Subscribe to authority changes, periodically reconcile accessible open pull requests, and support operator-requested GitHub redelivery | A stale result can remain visible until reconciliation runs |
| A head or base-branch commit arrives during evaluation | Require exact-head reviews, re-fetch base/head before publishing, and enqueue direct or base-ref fan-out work | GitHub check display remains eventually consistent during rapid updates |
| Contributor-controlled branch names create an unbounded base-push queue | Coalesce the same base ref; retain at most 100 distinct base-ref rows per installation and repository; collapse overflow to one conservative repository-wide job; claim broader authority work first | A repository-wide collapse performs more GitHub API work than a base-specific job and can temporarily increase merge latency |
| Multiple pull requests share one head commit but require different decisions | Refuse to publish success when another open pull request already uses the head; invalidate on pull-request open and retarget events | A pull request created or retargeted after success can inherit the commit-scoped result until its webhook is processed; this blocks production use of the check |
| A mapped review, label, pull-request, or rerequest trigger races with evaluation | Durably record the trigger, attempt bounded immediate check invalidation, verify the database generation before and after completion, and restore `in_progress` after a publication race | The fast path is best-effort so GitHub receives a timely acknowledgement; when the Check Runs API is unavailable, a displayed success can remain until the durable worker reaches GitHub |
| A repository label used by policy is renamed or deleted | Subscribe to label-definition events, fan out repository evaluation, and fetch current pull-request label names | A displayed success can remain while the event and fan-out are processed or until reconciliation after a missed delivery |
| A rename moves content across ownership boundaries | Evaluate both the old and new path | GitHub must report the previous path; incomplete evidence fails closed |
| GitHub truncates a very large pull request | Paginate and reject evaluation at GitHub's 3,000-file API maximum because completeness cannot be proved | Very large pull requests cannot use Extra CODEOWNERS without being split |
| Adversarially large payloads or policies exhaust service resources | Bound webhook bodies, policy and CODEOWNERS size, review and membership evidence, and path-pattern operations; reject unknown policy fields | Work above a limit blocks authorization and may require the pull request or policy to be split |
| An unenrolled bot copies a trusted App's name | Require the review bot user ID and exact `<slug>[bot]` login, independently fetch `GET /apps/{slug}`, match App ID and slug to organization policy, and use expected-source checks | GitHub review APIs do not expose every provenance field uniformly, so adapters need live contract tests |
| Automation uses a normal GitHub user account | Govern CODEOWNERS users and team membership outside this service; reserve delegated application policy for actors GitHub identifies as Apps | Actor type `User` is not proof of personhood, and a machine user with owner authority is treated like any other user |
| Human or team ownership eligibility changes after approval | Revalidate direct-user repository permission, team visibility, repository access, and active membership during evaluation; subscribe to repository and organization authority events; reconcile open pull requests | Stale success may remain while delivery and fan-out are in progress or until reconciliation after a missed event |
| App access is suspended or an ordinary target repository is removed from its installation | Keep native human enforcement until access changes are complete, and restore it before intentional removal; acknowledge well-formed ordinary-target removal without pretending revocation succeeded | Once access is gone, Extra CODEOWNERS cannot revoke an existing check in that repository |
| A trusted application is compromised | Limit delegation by path, effective owner, and labels; preserve non-delegable paths | Within its delegated scope, the application is intentionally trusted to approve |
| An operator loses GitHub API access or reaches a rate limit | Fail closed; retry indefinitely with a configured maximum ordinary backoff; honor a separately bounded provider `Retry-After`; expose queue state and API failures | Availability failures block merges and continue consuming bounded retry capacity until evidence can be obtained; the service lacks a remaining-quota metric |
| Another actor publishes a check with the same name | Require the check from the Extra CODEOWNERS App as the expected source; grant installation-level Statuses write for organization ruleset discovery but omit it from runtime tokens | Rules configured by name alone are vulnerable to source confusion |
| A proxy, browser, or observer captures App Manifest setup material | Require HTTPS and signed short-lived state, suppress access logs, return no-store pages with a restrictive content security policy, and disable setup after use | The one-time callback and displayed conversion response contain credentials; a compromised operator endpoint or browser can disclose them |
| The service or database is compromised | Least-privilege App permissions, short-lived installation tokens, secret manager, encrypted transport, restricted database access | A service compromise can falsify checks within installed repositories; rotate the App key and investigate all affected checks |

## Security invariants

Controls can change as the implementation matures. These invariants cannot:

1. No incomplete or contradictory evidence yields success.
2. No review for an older head satisfies the current head.
3. No repository can enroll its own trusted application.
4. No label is approval evidence by itself.
5. Every distinct effective CODEOWNERS owner set is independently satisfied.
6. Both names of a renamed file are evaluated.
7. Check publication is bound to the exact evaluated head and the expected App source.
8. A known superseding database generation cannot leave the prior generation successful; the check remains or returns to `in_progress`.
9. Relevant pending or retrying authority fan-out work prevents an evaluation from publishing a completed result.
10. Credentials and raw private payloads do not appear in logs, metrics, checks, or audit details.

Invariant 7 deserves a careful reading. It binds publication to the evaluated
commit and the expected App identity, but GitHub offers no pull-request-scoped
required Check Run. Shared-head detection at publication time and fast webhook
invalidation make the mismatch smaller. They do not eliminate it.

## Non-delegable paths

Some files decide who may approve; others decide what trusted automation does.
Letting an App approve changes to those files could let it expand its own
authority. Extra CODEOWNERS therefore makes a built-in set non-delegable:

- every standard CODEOWNERS location
- the effective Extra CODEOWNERS policy path, which defaults to
  `.github/extra-codeowners.toml`
- Stampbot's root `/stampbot.toml`
- `.github/workflows/**`
- repository-local actions under `.github/actions/**`

Organization policy can add more paths, and repository maintainers cannot
remove them. On any owned path in the combined set, an App approval cannot
substitute for an eligible human approval.

The service cannot discover every file that a privileged workflow or approving
App executes. The built-in Stampbot rule is one known case, not a complete
inventory. Use organization `guardrails.non_delegable_paths` for each enrolled
App's local configuration, policy, rules, prompts, generated inputs, and
decision code. Add repository-specific release scripts, deployment helpers,
action code outside `.github/actions/`, and any other path that can change
trusted behavior. Revisit those transitive execution paths whenever an App,
workflow, or approval policy changes.

“Non-delegable” describes approval, not authorship or file contents. Apps may
still appear in workflows or configuration. They cannot substitute for an
appropriate human when a pull request changes an owned protected path.

The list also does not assign an owner. Each repository must cover these paths
in standard CODEOWNERS. An unowned path creates no code-owner requirement in
GitHub's native model or in Extra CODEOWNERS.

## Insecure-changes escape hatch

`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` removes the built-in
non-delegable set for every installation served by that process. The name is
blunt because the effect is blunt. While it is enabled, the service emits a
high-severity startup warning and keeps an always-on metric visible.

The setting does **not**:

- remove organization-defined non-delegable paths
- create or broaden any repository delegation
- bypass path, owner, label, identity, or exact-head checks
- change the standard GitHub numeric review count
- bypass other required checks.

Use the escape hatch only when another independently enforced control protects
ownership files, Extra CODEOWNERS and Stampbot policy, workflows, and local
actions. Isolate that deployment from repositories that depend on the built-in
guardrails. Record who owns the exception, why it exists, what compensates for
it, and when it expires.

## Secret handling

Secrets give the service its GitHub identity. Handle them accordingly:

- Store the App private key and webhook secret in a managed secret store, not a repository, image, policy file, command line, or log field.
- Prefer file-mounted secrets over multiline environment values where the platform supports them.
- Grant the runtime identity access only to the specific secret versions it needs.
- Rotate the webhook secret and App private key after suspected disclosure, operator departure, or service compromise.
- Installation access tokens are short-lived cache material and must not be persisted in the durable queue or audit store.

If a private key is compromised, stop its authority first: suspend the App or
revoke the key. Restore native human code-owner enforcement on affected
repositories, rotate credentials, and review every check published during the
exposure window.

## Boundaries not implemented

The current implementation does not cover:

- GitHub Enterprise Server compatibility, until named server versions have been
  tested
- high-assurance merge queues, until `merge_group` reevaluation is implemented
  and tested
- transfers or installation changes that remove repository access before rules
  are handed back to native enforcement
- isolation or service-level commitments for a multi-tenant hosted service
- arbitrary third-party callers; the webhook endpoint authenticates GitHub,
  not a general API client
