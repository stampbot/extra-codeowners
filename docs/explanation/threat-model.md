# Threat model

Extra CODEOWNERS participates in merge authorization. Treat a false success as a security incident, not a cosmetic CI defect.

This threat model covers the self-hosted GitHub App design. A future multi-tenant hosted service will require additional tenant-isolation, billing, abuse, and privacy analysis before launch.

## Assets

The system protects:

- repository merge policy and the integrity of required checks;
- GitHub App private keys, webhook secrets, setup-state secrets, and short-lived installation tokens;
- organization application enrollment and repository delegation policy;
- private repository metadata, paths, ownership, review, and team-membership evidence; and
- durable queue and audit records used to explain decisions.

## Trust boundaries

GitHub authenticates an installation and sends signed webhook requests. The public webhook endpoint crosses into the operator's service. Workers cross back into GitHub using installation-scoped tokens. Organization administrators define trusted App identities; repository maintainers may only delegate those identities within organization guardrails.

The database and secret manager are operator-controlled trusted dependencies. Logs, metrics, and check summaries are lower-trust outputs and must not contain credentials or full private payloads.

## Adversaries and failure modes

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
| Multiple pull requests share one head commit but require different decisions | Refuse to publish success when another open pull request already uses the head; invalidate on pull-request open and retarget events | A pull request created or retargeted after success can inherit the commit-scoped result until its webhook is processed; this blocks production use of the preview |
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
| An operator loses GitHub API access or reaches a rate limit | Fail closed; retry indefinitely with a configured maximum ordinary backoff; honor a separately bounded provider `Retry-After`; expose queue state and API failures | Availability failures block merges and continue consuming bounded retry capacity until evidence can be obtained; the preview lacks a remaining-quota metric |
| Another actor publishes a check with the same name | Require the check from the Extra CODEOWNERS App as the expected source; grant installation-level Statuses write for organization ruleset discovery but omit it from runtime tokens | Rules configured by name alone are vulnerable to source confusion |
| A proxy, browser, or observer captures App Manifest setup material | Require HTTPS and signed short-lived state, suppress access logs, return no-store pages with a restrictive content security policy, and disable setup after use | The one-time callback and displayed conversion response contain credentials; a compromised operator endpoint or browser can disclose them |
| The service or database is compromised | Least-privilege App permissions, short-lived installation tokens, secret manager, encrypted transport, restricted database access | A service compromise can falsify checks within installed repositories; rotate the App key and investigate all affected checks |

## Security invariants

The implementation and tests must preserve these invariants:

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

Invariant 7 binds publication to the evaluated commit and App identity, not permanently to one pull request. GitHub does not provide a pull-request-scoped required Check Run. Publication-time shared-head detection and webhook invalidation reduce but do not eliminate that platform mismatch.

## Non-delegable paths

The built-in list covers all standard CODEOWNERS locations, the effective configured policy path (by default `.github/extra-codeowners.toml`), Stampbot's root `/stampbot.toml`, `.github/workflows/**`, and repository-local actions under `.github/actions/**`. Organization policy can add paths that repository maintainers cannot remove. These controls prevent the approving application from substituting for a human on an owned policy or execution surface that grants its authority.

The service cannot infer every file that a privileged workflow or approving application executes. Beyond the built-in Stampbot policy, use organization `guardrails.non_delegable_paths` to cover every enrolled App's repository-local configuration, policy, rules, prompts, generated inputs, and decision code, plus repository-specific release scripts, deployment helpers, action code outside `.github/actions/`, or any other path that can affect trusted behavior. Review these transitive execution paths whenever an App, workflow, or approval policy changes.

The contents of these files are not limited to humans. The restriction means an application approval cannot substitute for an appropriate human when a pull request changes them.

The built-in list does not assign owners. Repositories must explicitly cover these files in standard CODEOWNERS; an unowned path creates no code-owner requirement in either the native model or Extra CODEOWNERS.

## Insecure-changes escape hatch

Setting `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` disables the built-in non-delegable paths for every installation served by that process. The service must emit a high-severity startup warning and expose an always-on metric while the setting is enabled.

The setting does **not**:

- remove organization-defined non-delegable paths;
- create or broaden any repository delegation;
- bypass path, owner, label, identity, or exact-head checks;
- change the standard GitHub numeric review count; or
- bypass other required checks.

Use it only when another independently enforced control protects ownership, Extra CODEOWNERS and Stampbot policy, workflow, and local-action changes. Run such installations separately from repositories that rely on the built-in guardrails. Record the exception, owner, justification, compensating control, and expiration date.

## Secret handling

- Store the App private key and webhook secret in a managed secret store, not a repository, image, policy file, command line, or log field.
- Prefer file-mounted secrets over multiline environment values where the platform supports them.
- Grant the runtime identity access only to the specific secret versions it needs.
- Rotate the webhook secret and App private key after suspected disclosure, operator departure, or service compromise.
- Installation access tokens are short-lived cache material and must not be persisted in the durable queue or audit store.

If a private key is compromised, suspend the App or revoke the key first, restore native human code-owner enforcement on affected repositories, rotate credentials, and review checks published during the exposure window.

## Out of scope for the initial release

- GitHub Enterprise Server compatibility until tested against named server versions.
- High-assurance merge-queue support until `merge_group` reevaluation is implemented and tested.
- Transfers or installation changes that remove the App's repository access before repository rules are handed back to native enforcement.
- Multi-tenant hosted-service isolation and service-level commitments.
- Authentication or authorization for arbitrary third-party callers; the webhook endpoint is for GitHub only.
