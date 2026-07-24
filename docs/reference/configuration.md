# Configuration reference

This page defines the typed settings and policy models for version 0.1. The checked-in models, validation tests, and current schema are authoritative. Compatibility may change before 1.0.

Configuration has three scopes:

- **Runtime settings** configure an operator's deployment.
- **Organization policy** enrolls applications and defines guardrails.
- **Repository policy** opts a repository in and delegates specific paths.

The runtime `EXTRA_CODEOWNERS_GITHUB_APP_ID` identifies the checker that publishes the required Check Run. Entries under organization `apps` identify applications whose existing pull-request approvals may substitute for humans, such as Stampbot. The checker App ID belongs in an enrollment only if that App also submits reviews independently. Extra CODEOWNERS does not submit reviews.

## Policy locations

The default policy path is `.github/extra-codeowners.toml`. `EXTRA_CODEOWNERS_POLICY_PATH` changes it for the entire deployment. Both policy scopes use the same validated literal path. A repository cannot override it.

| Scope | Repository and revision | Purpose |
| --- | --- | --- |
| Organization | `<organization>/.github`, default branch | Enroll immutable application identities and add organization guardrails. |
| Repository | Pull request's base repository, exact base commit | Enable evaluation and delegate paths to an enrolled application. |

Organization policy is not copied into target repositories and does not opt them in. Every target repository needs an enabled repository policy. Repository policy may narrow organization authority. It cannot enroll an application or weaken an organization guardrail.

Version 0.1 uses one configured policy path for both scopes. The organization-policy repository uses that path for organization policy, so it cannot also use the path as its own repository policy. The default organization-policy repository is the organization's `.github` repository.

Extra CODEOWNERS does not reconcile or evaluate pull requests for the organization-policy repository. It does not publish checks there. Pull-request webhooks for that repository are authenticated and acknowledged without retention.

The following organization-policy repository events are retained and fan out reevaluation to installed target repositories:

- a relevant policy push to the default branch
- a default-branch change
- rename, transfer, or deletion
- removal from the App's repository selection
- a malformed repository-removal event.

The organization-policy repository must retain GitHub's native human code-owner enforcement. Extra CODEOWNERS must not be a required check there in version 0.1. Separate organization and repository policy paths are not supported.

## Organization policy

The following example enrolls one application and adds a non-delegable path:

```toml
schema_version = 1

[apps.example-automation]
slug = "example-automation"
app_id = 123456
bot_user_id = 234567

[guardrails]
non_delegable_paths = [
  "terraform/production/**",
]
```

### Organization fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Policy schema. Version `1` is accepted. Unknown versions fail closed. |
| `apps` | table | no | Map of at most 50 local aliases to trusted application identities. Aliases contain letters, digits, internal hyphens or underscores, are normalized to lowercase, and are referenced by repository policy. Defaults to an empty table. |
| `apps.<alias>.slug` | string | yes | GitHub App slug containing letters, digits, and internal hyphens, normalized to lowercase. Slugs must be unique across entries and are used for independent identity verification, not by themselves as authentication. |
| `apps.<alias>.app_id` | positive integer | yes | Immutable GitHub App ID recorded by the organization administrator. IDs must be unique across entries. Boolean and string values are rejected. |
| `apps.<alias>.bot_user_id` | positive integer | yes | Immutable numeric ID of the App's bot account. IDs must be unique across entries. Boolean and string values are rejected. Pull-request reviews identify this actor. |
| `guardrails.non_delegable_paths` | array of strings | no | At most 100 additional CODEOWNERS-compatible patterns that always require an appropriate human approval. Defaults to an empty array. These are additive and cannot be removed by repository policy or the runtime escape hatch. |

An application alias is local policy vocabulary; changing it requires updating repositories that reference it. Numeric IDs are the trust anchors. A slug mismatch, missing identity, or conflicting alias fails closed.

## Repository policy

```toml
schema_version = 1
enabled = true

[[delegations]]
app = "example-automation"
paths = [
  "docs/**",
  "**/*.lock",
  "renovate.json",
]
for_owners = ["@example-org/platform"]
required_labels = ["automation-approved"]
forbidden_labels = ["needs-security-review"]
```

### Repository fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Policy schema. Version `1` is accepted. Unknown versions fail closed. |
| `enabled` | boolean | yes | Explicitly opts the repository in or out. A committed policy that omits `enabled` is invalid. An absent file in a repository with no managed check produces no check and no noise. An explicitly disabled file produces failure; removing policy after a check exists also updates that managed check to failure when evaluated. |
| `delegations` | array of tables | no | At most 100 application delegations. With no entries, only appropriate human approvals can satisfy owned paths. |
| `delegations[].app` | string | yes | Alias from the organization's `apps` table. Repository policy cannot introduce an application. |
| `delegations[].paths` | array of strings | yes | Between 1 and 100 eligible changed-file patterns. A repository policy may contain at most 1,000 patterns across all delegations. All changed paths remain subject to standard `CODEOWNERS` ownership. |
| `delegations[].for_owners` | array of strings | yes | Between 1 and 100 `@user` or `@organization/team` CODEOWNERS identities, normalized case-insensitively. Use `"*"` alone and explicitly to cover any owner set; omission, duplicates, or combining `"*"` with names is invalid. |
| `delegations[].required_labels` | array of strings | no | At most 50 labels that must all be present before this delegation is eligible. Matching is case-insensitive. Labels gate evaluator behavior but are not independent authority: an App with pull-request write permission can change them. |
| `delegations[].forbidden_labels` | array of strings | no | At most 50 labels that must all be absent. Matching is case-insensitive and defaults to an empty array. A label cannot be both required and forbidden. Treat this as workflow routing, not containment for a compromised App. |

Multiple delegation entries are additive alternatives. For entries that overlap on an application, path, and owner set, any one entry with satisfied label conditions makes the application eligible. Restrictions from separate entries are not combined.

Every condition that must apply together belongs in one entry. A broader overlapping entry is not constrained by a narrower entry. Each entry must independently identify an enrolled application, eligible path, applicable owner, and label conditions. No entry can override a non-delegable path.

## Path pattern rules

Delegation and guardrail patterns follow standard `CODEOWNERS`-compatible matching:

- Paths are relative to the repository root and use `/` separators.
- Matching is case-sensitive.
- A leading `/` anchors a pattern at the repository root.
- A non-terminal `/` also makes a pattern root-relative: `docs/*` addresses the root `docs` directory. A trailing directory pattern such as `apps/` can match an `apps` directory anywhere; write `/apps/` to restrict it to the root.
- A directory pattern ending in `/`, such as `/docs/`, matches files in that directory and all descendants.
- A single `*` does not cross `/`; `docs/*` matches direct children but not `docs/guides/start.md`.
- A double `**` can cross directory boundaries; `docs/**` matches both direct children and nested descendants.
- A `?` matches exactly one non-`/` character.
- Negation with `!` and character ranges with `[]` are not supported by CODEOWNERS and are invalid here.

An ownerless CODEOWNERS rule is valid and clears ownership for its matched path when it is the last matching rule. Extra CODEOWNERS therefore creates no code-owner requirement for that path, although ordinary review counts and other checks still apply.

GitHub supports some CODEOWNERS email identities. Extra CODEOWNERS version 0.1 does not. The evaluator cannot safely resolve an email entry to a review actor, so a relevant email owner fails closed. Supported identities are `@user` and `@organization/team`.

Policy files must be UTF-8 TOML and cannot exceed 1,000,000 bytes. Unknown fields are rejected. Policy should remain small enough for reviewers to inspect the complete authorization boundary. Standard `CODEOWNERS` has a separate 3 MiB maximum. A larger file fails evaluation because GitHub does not use it.

For a rename, Extra CODEOWNERS evaluates both the old and new path. A delegation must cover both names; otherwise the uncovered name requires an appropriate human approval.

See GitHub's [CODEOWNERS syntax documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-syntax) for the baseline syntax.

## Built-in non-delegable paths

The following paths reject application substitution by default:

```text
/CODEOWNERS
/.github/CODEOWNERS
/docs/CODEOWNERS
/.github/extra-codeowners.toml
/stampbot.toml
/.github/workflows/**
/.github/actions/**
```

The restriction controls who may satisfy review policy for a change. It does not restrict file contents. Policy may list applications. Workflows and local actions may invoke applications.

The `.github/extra-codeowners.toml` entry above is the default value of `EXTRA_CODEOWNERS_POLICY_PATH`. If an operator configures another validated literal path, that actual repository-policy path replaces the default entry in the built-in list and remains non-delegable.

Non-delegable patterns do not assign ownership. Standard `CODEOWNERS` must give these paths an effective human user or team owner. Otherwise, Extra CODEOWNERS reports the path as unowned and creates no code-owner requirement. The CODEOWNERS file itself must be protected. GitHub's CODEOWNERS error view reports ownership errors that would weaken this boundary.

Organization `guardrails.non_delegable_paths` entries are added to this list. Repository policy cannot remove either list.

The built-in root `/stampbot.toml` entry protects Stampbot's repository policy because Stampbot is the first supported integration. Built-ins cannot discover every control file used by other enrolled applications. Organization policy must add these paths to `guardrails.non_delegable_paths` for each application:

- policy and configuration
- rules and prompts
- generated-policy inputs
- transitive decision code.

Without these guardrails, an application could approve a change that expands its future authority.

Organization guardrails must also cover repository-specific release, deployment, and helper paths that can alter privileged workflow behavior. A workflow can invoke code outside `.github/actions/**`. Extra CODEOWNERS cannot infer that transitive execution graph.

## Runtime settings

Runtime settings use Pydantic Settings. Environment variables use the `EXTRA_CODEOWNERS_` prefix. A local `.env` file is loaded when present. The `serve` command can override the host and port.

Unknown keys loaded from `.env` are rejected. Values outside documented bounds are also rejected. Unrelated or unrecognized process environment variables are ignored.

### Service settings

| Environment variable | Type | Default | Constraints and effect |
| --- | --- | --- | --- |
| `EXTRA_CODEOWNERS_ENVIRONMENT` | string | `development` | One of `development`, `test`, or `production`. Production refuses to start without the GitHub App ID, private key, and webhook secret. |
| `EXTRA_CODEOWNERS_LOG_LEVEL` | string | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. Avoid debug logging for private production repositories unless its data handling has been reviewed. |
| `EXTRA_CODEOWNERS_HOST` | string | `127.0.0.1` | Bind address. Use `0.0.0.0` only inside an appropriately isolated container or host. |
| `EXTRA_CODEOWNERS_PORT` | integer | `8000` | Inclusive range `1` through `65535`. |
| `EXTRA_CODEOWNERS_PUBLIC_URL` | absolute HTTP(S) URL or null | null | Public origin used to construct App Manifest webhook, callback, and completion URLs. Setup mode requires an `https://` origin with no credentials, no path other than `/`, and no query or fragment; otherwise this setting is optional. |
| `EXTRA_CODEOWNERS_DATABASE_URL` | SQLAlchemy URL | `sqlite:///./extra-codeowners.db` | Durable queue and audit store. Production requires PostgreSQL and one explicit host or Unix-socket path; comma-separated hosts are rejected. Every non-local connection must set `sslmode=verify-full`, which verifies both the certificate chain and database hostname; `require` and `verify-ca` are rejected. An effective `localhost`, `127.0.0.1`, `::1`, or Unix-socket `host` may omit TLS. Any `hostaddr` or `service` routing override requires `verify-full`. SQLite remains available for development and tests. Treat the complete value as a secret. |

Locality is determined from the effective libpq route, not only the URL authority. A query-string `host` takes precedence over the authority host. A remote override therefore requires `sslmode=verify-full` even when the authority looks local. `hostaddr` and `service` always count as routing overrides and require verified TLS.

PostgreSQL access has fixed fail-fast budgets:

| Operation | Timeout |
| --- | --- |
| Establish a connection | 3 seconds |
| Obtain a pooled connection | 2 seconds |
| Execute an ordinary statement | 3 seconds |

Advisory-lock acquisition replaces the statement timeout with that operation's bounded guard wait. These values are not runtime settings. A database path that cannot reliably meet them causes webhook acceptance or worker operations to fail closed and retry where applicable.

### GitHub settings

| Environment variable | Type | Default | Constraints and effect |
| --- | --- | --- | --- |
| `EXTRA_CODEOWNERS_GITHUB_APP_ID` | positive integer or null | null | Numeric ID of this Extra CODEOWNERS App. Required for GitHub processing. |
| `EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY` | secret string or null | null | Inline PEM private key. Literal `\n` sequences are converted to newlines. Mutually exclusive with the file setting. |
| `EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE` | path or null | null | File containing the PEM private key. Preferred for deployed workloads. Mutually exclusive with the inline setting. |
| `EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET` | secret string or null | null | Inline webhook HMAC secret. Production requires at least 32 UTF-8 bytes. Mutually exclusive with the file setting. |
| `EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE` | path or null | null | File containing the webhook HMAC secret. Production requires at least 32 bytes after one terminal line ending is removed. Preferred for deployed workloads. Mutually exclusive with the inline setting. |
| `EXTRA_CODEOWNERS_GITHUB_API_URL` | absolute HTTP(S) URL | `https://api.github.com` | REST API origin. Production requires HTTPS. Alternate GitHub deployments are not supported until version-specific integration tests exist. |
| `EXTRA_CODEOWNERS_GITHUB_API_VERSION` | string | `2026-03-10` | Value of `X-GitHub-Api-Version`, currently a [supported GitHub REST API version](https://docs.github.com/en/rest/about-the-rest-api/api-versions). Change only after compatibility testing. |
| `EXTRA_CODEOWNERS_GITHUB_IDENTITY_PROBE_INTERVAL_SECONDS` | number | `30` | Seconds between authenticated App identity probes; inclusive range `5` through `300`. Each probe calls `GET /app` with the configured private key and requires the returned App ID to equal `EXTRA_CODEOWNERS_GITHUB_APP_ID`. |
| `EXTRA_CODEOWNERS_GITHUB_IDENTITY_FRESHNESS_SECONDS` | number | `90` | Maximum age in seconds of the last successful identity probe; inclusive range `10` through `900`. It must be at least twice the probe interval. Readiness fails after this window without a successful refresh. |

Secret-file readers support projected Kubernetes Secret symlinks while limiting
resolution to 16 symlinks and 256 path operations. The resolved target must be
a regular UTF-8 file no larger than 64 KiB. The service opens every path
component with no-follow descriptor flags and rejects a file that changes
while it is read.

Readers remove at most one terminal LF or CRLF, as commonly added by secret
tooling, and preserve all other bytes. Inline private keys may use literal
`\n` sequences for PEM line breaks; webhook secrets are not newline-expanded.
Empty credential values do not make the service ready.

GitHub connect, pool, read, and write waits each use a fixed 20-second
inactivity timeout. The client also applies a 20-second wall-clock deadline to
each non-streaming request, including the reconciliation requests used during
graceful shutdown. These limits are not runtime settings.

The service attempts an identity probe during startup and continues in the
background. A failed refresh does not erase a still-fresh success, which
avoids dropping readiness for one transient request. Once the freshness window
expires, `/health/ready` reports `github_credentials: false` until an
authenticated `GET /app` succeeds with the exact configured App ID. Liveness
does not depend on this probe.

### Queue and reconciliation settings

| Environment variable | Type | Default | Constraints and effect |
| --- | --- | --- | --- |
| `EXTRA_CODEOWNERS_WORKER_ENABLED` | boolean | `true` | Runs the pull-request evaluation and authority fan-out worker in this service process. At least one worker must share the durable store. |
| `EXTRA_CODEOWNERS_WORKER_POLL_SECONDS` | number | `0.5` | Queue poll interval in seconds; inclusive range `0.05` through `60`. |
| `EXTRA_CODEOWNERS_WORKER_LEASE_SECONDS` | integer | `120` | Job lease in seconds; inclusive range `30` through `3600`. Must exceed normal evaluation time. |
| `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS` | integer | `60` | Maximum ordinary exponential-backoff delay in seconds; inclusive range `5` through `3600`. Evaluation and authority failures retry indefinitely because abandoning invalidation or reevaluation work could leave a stale success visible. A GitHub rate-limit response instead uses the provider's bounded `Retry-After` delay and does not advance the ordinary backoff attempt. |
| `EXTRA_CODEOWNERS_WEBHOOK_INVALIDATION_TIMEOUT_SECONDS` | number | `5.0` | Inclusive range `0.1` through `8.0`. Bounds both the best-effort direct-trigger GitHub API fast path and the wait that orders authority-event acceptance against an in-flight Check Run, keeping both below GitHub's 10-second response deadline. A direct-trigger fast-path timeout does not discard the queued evaluation. An authority-guard timeout prevents acceptance and returns `503` so an operator can redeliver the event. |
| `EXTRA_CODEOWNERS_RECONCILE_ENABLED` | boolean | `true` | Periodically requests absent evaluation work for open pull requests visible to the installation. Disabling it also disables automatic delivery-ID pruning. |
| `EXTRA_CODEOWNERS_RECONCILE_INTERVAL_SECONDS` | integer | `300` | Reconciliation interval in seconds; inclusive range `60` through `86400`. |
| `EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS` | integer | `30` | Retain accepted GitHub delivery IDs for replay deduplication; inclusive range `1` through `3650` days. The elected reconciler prunes older IDs on each run. |

### Policy and security settings

| Environment variable | Type | Default | Constraints and effect |
| --- | --- | --- | --- |
| `EXTRA_CODEOWNERS_ORG_CONFIG_REPOSITORY` | string | `.github` | Literal repository name used for organization policy: `1`–`100` characters, with no `/` or `\`, and not `.` or `..`. Changing it creates a different trust-policy location and changes which repository is excluded from evaluation. |
| `EXTRA_CODEOWNERS_POLICY_PATH` | string | `.github/extra-codeowners.toml` | Literal relative POSIX path used for organization and repository policy. Empty, absolute, wildcard, backslash, `.`-segment, and `..`-segment forms are rejected. The effective path is automatically non-delegable unless insecure mode is enabled. Coordinate any change across both policy scopes. |
| `EXTRA_CODEOWNERS_CHECK_NAME` | string | `Extra CODEOWNERS / approval` | Printable Check Run name after surrounding whitespace is removed; length `1` through `255`. A change must be coordinated with every required-check rule. |
| `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES` | boolean | `false` | When `true`, suppresses only the built-in non-delegable path list for every installation served by that process. It emits a startup warning and sets the insecure-mode metric to `1`. Organization-added guardrails and normal delegation matching still apply. |

### App setup settings

| Environment variable | Type | Default | Constraints and effect |
| --- | --- | --- | --- |
| `EXTRA_CODEOWNERS_SETUP_ENABLED` | boolean | `false` | Enables the GitHub App Manifest setup routes. Keep disabled after registration when they are not needed. |
| `EXTRA_CODEOWNERS_SETUP_STATE_SECRET` | secret string or null | null | HMAC key for short-lived setup state. Setup-mode startup requires at least 32 UTF-8 bytes. Use a value distinct from the webhook secret. |
| `EXTRA_CODEOWNERS_SETUP_STATE_TTL_SECONDS` | integer | `600` | Setup state lifetime in seconds; inclusive range `60` through `3600`. |

Do not place App private keys or webhook secrets in TOML committed to a repository. Runtime secrets belong in the deployment's secret manager.

## Loading and failure behavior

- Repository `CODEOWNERS` and repository policy are read from the exact pull-request base commit, not from the proposed head.
- Organization policy is read from the default branch of the configured organization-policy repository (`.github` by default).
- A pull request cannot grant itself authority by modifying its policy file.
- A repository delegation that references an application alias absent from organization policy makes the combined policy invalid and produces a diagnostic failure.
- Invalid TOML, an unsupported schema version, or ambiguous policy fails evaluation and produces a diagnostic check result. An enrolled App identity mismatch makes that App's review ineligible and emits a sanitized warning; independent appropriate human or application evidence can still satisfy the owner set.
- A repository with no policy and no managed Extra CODEOWNERS check is not enrolled: the service publishes no check and does not load organization policy for it. Organization configuration alone never opts repositories in.
- An explicitly disabled repository policy produces a failing check and never causes an application approval to count. If policy disappears after the App has already created its named check on the current head, a later evaluation updates that managed check to failure instead of leaving a stale success.
- Production service startup requires complete GitHub credentials, a webhook secret of at least 32 bytes, an HTTPS GitHub API URL, and PostgreSQL using `sslmode=verify-full` over every non-local connection or an operator-controlled loopback or Unix-socket transport.
- Setup-mode startup requires an HTTPS public URL and a setup-state secret of at least 32 bytes.

Safe disablement has this order:

1. Restore GitHub's native **Require review from Code Owners** rule.
2. Remove the expected-source Extra CODEOWNERS required check.
3. Set `enabled = false` or remove repository policy.

A disabled file leaves a still-required gate failing. A missing required check also does not satisfy the gate.
