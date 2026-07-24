# Evaluation beta preflight

`tools/evaluation_beta_bootstrap.py preflight` collects fail-closed evidence
for the disposable, non-required evaluation beta. It reads a reviewed source
checkout, GitHub.com, one running service, and PostgreSQL. It then writes one
sanitized JSON report.

The preflight is an inspection tool, not the beta itself. It does not submit a
review, send a webhook, publish a Check Run, or change repository rules.

The command targets GitHub.com with REST API version `2026-03-10`. GitHub
Enterprise Server is not supported.

See [Preflight a disposable evaluation beta](../how-to/preflight-evaluation-beta.md)
for the operator procedure.

## Command

Run the bootstrap from the reviewed Extra CODEOWNERS source root. Set
`UV_PROJECT_ENVIRONMENT` to a directory outside that checkout before
bootstrapping or running the command:

```text
python -I -S -B tools/evaluation_beta_bootstrap.py preflight \
  [--config PATH] [--report PATH]
```

Use `uv run --no-sync` to run that command from the already-bootstrapped
external environment. The launcher refuses to run without isolated, no-site,
and no-bytecode interpreter modes. Before importing third-party or checkout
code, it uses fixed `/usr/bin/git` commands to reject untracked and ignored
content. It appends the external environment after the standard library and
the reviewed checkout last; it does not process `.pth` files or site
customization. The source probe then compares the index and tracked files with
the signed tree.

| Option | Default | Meaning |
| --- | --- | --- |
| `--config PATH` | `EXTRA_CODEOWNERS_BETA_CONFIG_FILE`, then `evaluation-beta-preflight.toml` | Non-secret TOML configuration. |
| `--report PATH` | `EXTRA_CODEOWNERS_BETA_REPORT_FILE`, then `evaluation-beta-preflight-report.json` | New JSON report path. The parent directory must already exist. |

An explicit option takes precedence over its environment-variable default.

## Secret inputs

The TOML file contains no credentials. Four environment variables supply the
secret inputs:

| Variable | Required value | Use |
| --- | --- | --- |
| `EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE` | Path to the checker App's PEM private key | Signs a GitHub App JSON Web Token (JWT). |
| `EXTRA_CODEOWNERS_BETA_APPROVER_PRIVATE_KEY_FILE` | Path to a different App's PEM private key | Signs the approver App's JWT. |
| `EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE` | Path to a dedicated fine-grained personal access token (PAT) beginning with `github_pat_` | Reads Actions permissions and classic branch protection for the target repository. |
| `EXTRA_CODEOWNERS_BETA_DATABASE_URL` | A `postgresql+psycopg` URL with one explicit host, database, username, and nonempty password | Opens a bounded, read-only database probe. |

The preflight never reads `GH_TOKEN` or `GITHUB_TOKEN`. It rejects an operator
PAT that is also present in either variable.

Local input files have these requirements:

| File | Size | Ownership and mode |
| --- | --- | --- |
| Configuration | 1 byte to 64 KiB | Current user, one hard link, regular file, exact mode `0400` or `0600` |
| Each App private key | 1 byte to 64 KiB | Current user, one hard link, regular file, exact mode `0600` |
| Operator PAT | 1 byte to 4 KiB | Current user, one hard link, regular file, exact mode `0400` or `0600` |
| SSH allowed-signers file | 1 byte to 64 KiB | Current user, one hard link, regular file, not writable by group or other users |

Final-component symbolic links and non-regular files are rejected. Each file is
read through an open descriptor and checked again for changes. The operator PAT
must be printable ASCII on one line; one final line feed is accepted and
removed.

## Configuration file

The configuration is strict TOML. Unknown fields and values of the wrong type
are errors. The
[checked-in example](https://github.com/stampbot/extra-codeowners/blob/main/examples/evaluation-beta/preflight.toml)
contains every field and no secrets.

| Field | Required | Constraint and meaning |
| --- | --- | --- |
| `schema_version` | No | Integer `1`; defaults to `1`. A Boolean is not an integer here. |
| `source_revision` | Yes | Full 40- or 64-character hexadecimal commit ID expected at checkout `HEAD`; normalized to lowercase. |
| `source_signer_fingerprint` | Yes | Full 40- or 64-character OpenPGP fingerprint, normalized to uppercase, or an exact case-sensitive SSH `SHA256:` fingerprint with 43 base64 characters. |
| `source_ssh_allowed_signers_file` | For SSH signatures | SSH public-key trust file. A relative path is based at the configuration file's directory. Required for an SSH fingerprint and forbidden for an OpenPGP fingerprint. |
| `source_checkout` | No | Reviewed source directory with no untracked or ignored files; defaults to `.`. A relative path is based at the configuration file's directory. |
| `python_version` | Yes | Exact running Python version, such as `3.12.7`. |
| `uv_version` | Yes | Exact version parsed from `uv --version`. |
| `extra_codeowners_version` | Yes | Exact imported package version. The package must load from `source_checkout`. |
| `postgres_server_version_num` | Yes | Positive five- or six-digit integer returned by PostgreSQL `SHOW server_version_num`. |
| `organization_id` | Yes | Positive numeric ID of the disposable GitHub organization. |
| `target_repository` | Yes | Public `owner/repository` used for beta pull requests. It cannot be `.github`. |
| `target_repository_id` | Yes | Positive numeric ID of the target repository. |
| `organization_policy_repository` | Yes | Public `owner/.github` repository under the same owner as the target. |
| `organization_policy_repository_id` | Yes | Positive numeric ID of the `.github` repository. It must differ from `target_repository_id`. |
| `target_default_branch` | Yes | Exact target default branch. Unsafe or ambiguous Git ref names are rejected. |
| `target_default_branch_sha` | Yes | Full 40-character commit ID pinned for the target default branch. |
| `organization_policy_default_branch` | Yes | Exact `.github` default branch, with the same branch-name restrictions. |
| `organization_policy_default_branch_sha` | Yes | Full 40-character commit ID pinned for the `.github` default branch. |
| `checker_app_id` | Yes | Positive numeric ID of the Extra CODEOWNERS checker App. |
| `checker_app_slug` | Yes | Lowercase checker slug containing letters, digits, and internal hyphens. |
| `checker_installation_id` | Yes | Positive checker installation ID. |
| `approver_app_id` | Yes | Positive numeric ID of the App that submits the delegated review. |
| `approver_app_slug` | Yes | Lowercase approver slug containing letters, digits, and internal hyphens. |
| `approver_installation_id` | Yes | Positive approver installation ID. |
| `approver_bot_user_id` | Yes | Positive numeric ID of the approver App's bot account. |
| `service_url` | Yes | One HTTPS origin with no credentials, path, query, or fragment. A final slash is removed. |
| `checker_webhook_url` | Yes | The exact `service_url` origin followed by `/webhooks/github`. |
| `check_name` | No | Check context that must remain non-required; defaults to `Extra CODEOWNERS / approval`. Length is 1 to 100 characters; C0 controls are rejected. |
| `policy_path` | No | Literal relative path used in both repositories; defaults to `.github/extra-codeowners.toml`. |
| `delegation_test_path` | Yes | Existing harmless file below `docs/`. The beta delegation must name this exact path, not a glob. |
| `delegation_test_labels` | Yes | One to ten unique labels that the one beta delegation must require together. Labels are normalized to lowercase. |

Tool-version strings contain at most 64 letters, digits, `.`, `+`, `_`, or `-`
characters and start with a letter or digit. Repository names are normalized
to lowercase. Policy paths contain only ASCII letters, digits, `_`, `.`, and
`-` in slash-separated segments. They cannot contain empty, `.` or `..`
segments and cannot exceed 255 characters.

The target and `.github` repositories must share one organization. Repository
IDs, App IDs, App slugs, and installation IDs must identify distinct objects
where their roles differ. `checker_webhook_url` and `service_url` must share
the exact origin.

For SSH signatures, the preflight ignores Git's global configuration. It
passes the configured allowed-signers descriptor to Git explicitly and
rejects a trust file that changes during either signature check.

## GitHub App contracts

The preflight requires exact App and installation permissions. Extra
permissions fail the check; missing permissions do too.

| App | Exact permissions | Exact subscribed events |
| --- | --- | --- |
| Checker | Checks read/write; Contents read; Pull requests read; Commit statuses read/write; Metadata read; organization Members read | Check run, Installation target, Label, Member, Membership, Organization, Pull request, Pull request review, Push, Repository, Team, Team add |
| Approver | Contents read; Pull requests read/write; Metadata read | None |

Both Apps must be owned by the configured organization. Each App must have
exactly one current installation and no pending installation requests. The
installations must be active, use **Only select repositories**, and contain
these exact sets:

| Installation | Exact repositories |
| --- | --- |
| Checker | Target and organization-policy `.github` repository |
| Approver | Target repository |

The checker hook must use `checker_webhook_url`, JSON content, TLS certificate
verification, and a nonempty secret. The approver bot account must have the
exact configured numeric ID and `<approver-slug>[bot]` login.

GitHub's API does not expose the App registration choice **Only on this
account** or whether the configured checker hook is active. Those remain
manual prerequisites.

## Checks

A normal report contains all 11 checks. A failure in one check does not skip
the other independent checks.

| Check ID | Passing evidence |
| --- | --- |
| `source` | Fixed `/usr/bin/git` sees a current-user-owned, non-shared-writable, standalone, non-shallow checkout without alternates, replacement refs, linked-worktree metadata, gitlinks, or tracked, untracked, or ignored changes. `HEAD` is the pinned commit, strict `fsck` succeeds, and `show` plus `verify-commit` report a good signature from the exact fingerprint. Each of two observations requires safe index flags and modes, exact index equality with the signed commit tree, no ignored content, and matching worktree Git blob hashes. Evidence records the tracked-file count, byte count, `untracked_and_ignored_content: absent-at-both-observations`, and `tracked_content: hashed-twice-against-signed-tree`. |
| `tool_versions` | Python, uv, and Extra CODEOWNERS versions match. Python imported the package from the configured checkout. |
| `app_installations` | Both keys match their exact App identities, permissions, events, organization ownership, single-installation inventories, and repository selections. No installation request is pending. The checker hook configuration and approver bot identity match. Each short-lived probe token contains only Metadata read. |
| `public_repositories` | Both configured repositories are public, available, organization-owned objects with the expected numeric IDs, full names, default branches, and branch commits. |
| `branch_safety` | Active rules or classic protection require native code-owner review and at least one approving review. The configured Extra CODEOWNERS context is not required, and no merge queue is active. |
| `codeowners` | GitHub reports no errors for `.github/CODEOWNERS` at the pinned target commit. The bounded UTF-8 file parses locally, contains a rule, and owns the test path. |
| `policy` | The pinned repository and organization policy files parse and compile with built-in non-delegable paths enabled. Organization policy enrolls exactly the configured approver and no other App. Repository policy contains one delegation and no other delegation; it names the exact test path, exact CODEOWNER set, exact App, and exact required-label set. Each configured label must be present for eligibility. |
| `service_health` | `/`, `/api/runtime-identity`, `/health/live`, and `/health/ready` match a production source deployment of the configured checker. The service reports PostgreSQL, the exact policy and check settings, enabled and healthy worker and reconciler tasks, and a recent successful GitHub authentication as the configured App ID. A source deployment must report `build_revision: null`. |
| `postgresql` | The URL uses the exact `postgresql+psycopg` driver and one explicit host, database, username, and nonempty password. The connection enforces read-only transactions, `search_path=public`, and five-second statement, lock, and idle-transaction timeouts. The server version, Alembic head, and `required-release-contract` match the running code. Evidence reports `schema_contract: required-release-contract`. |
| `insecure_changes_metric` | `/metrics` contains exactly one unlabelled `extra_codeowners_insecure_changes_enabled` sample with value `0`. |
| `final_branch_refs` | Both repository identities, availability states, default branches, and branch commits still match after the other checks finish. |

The signed source tree must contain 1 to 10,000 unique, stage-0 regular blobs
with mode `100644` or `100755`. Paths may be at most 4,096 bytes and use only
ASCII letters, digits, `_`, `.`, `-`, and slash-separated safe segments. Every
worktree file must be a current-user-owned, single-link, non-group- or
world-writable regular file no larger than 64 MiB. Its executable state must
match the signed mode. The total tracked content cannot exceed 512 MiB.

Every untracked path is rejected, whether or not Git ignore rules hide it.
Keep virtual environments, build output, editor state, and operator inputs
outside the checkout. This prevents an ignored module in the source root from
shadowing a reviewed dependency while still producing a passing report.

At both observations, every index tag must be exact uppercase `H`; this
rejects `assume-unchanged`, `skip-worktree`, and fsmonitor-valid state. The
preflight opens each path through checkout-anchored, no-follow descriptors,
requires stable file and path metadata while reading, and hashes the Git blob
with the repository's SHA-1 or SHA-256 object format. The result must match the
object ID in the signed tree.

The source check requires Linux facilities including `/proc/self/fd`,
`O_NOFOLLOW`, and `/usr/bin/git`. Git commands run with bounded output and
time, a small environment, disabled hooks and prompts, and no system or global
Git configuration.

Remote PostgreSQL connections require `sslmode=verify-full`. A direct
loopback address or operator-controlled Unix-socket proxy may omit TLS.
An optional `hostaddr` requires an explicit host and `verify-full`.
`sslrootcert`, when present, must name a nonempty absolute path. Service-file
routing, unknown query parameters, ambient libpq connection variables,
hostless and comma-separated routes, an authority host combined with a
query-string `host`, and caller-supplied libpq `options` are rejected. The URL
must carry its own password, so `.pgpass` and `PGPASSFILE` are not used.

GitHub and service requests time out after 10 seconds, do not follow redirects,
and ignore ambient proxy and certificate environment variables. Responses,
remote files, command output, configuration, keys, metrics, and the report all
have fixed size limits.

## Report

The report writer creates a new mode-`0600` file and refuses to replace any
existing path. Its parent must already exist, belong to the current user, and
not be writable by group or other users. The destination cannot be inside the
source checkout or collide with the configuration, key, PAT, or SSH trust
file.

Publication uses an exclusive temporary file, verifies the published inode and
metadata, synchronizes the parent directory, and removes partial output when
post-publication verification fails. The encoded report cannot exceed 128 KiB.

A completed evaluation has these top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Exact report schema; currently `1`. |
| `kind` | `extra-codeowners-disposable-evaluation-beta-preflight`. |
| `run_nonce` | Random 32-character hexadecimal identifier for this invocation. |
| `captured_at` | UTC report-construction time in ISO 8601 format, written after the checks. |
| `result` | `passed` when every check passed; otherwise `failed`. |
| `preflight_passed` | Boolean result. Consumers must require literal `true`. |
| `source_revision` | Configured source commit. |
| `scope` | Repository, App, hook, policy, test-fixture, and source-deployment identity. |
| `checks` | Ordered array of 11 check results. |
| `limitations` | Facts that the preflight did not establish. |

Each check result contains `id` and `outcome`. A pass adds a bounded
check-specific `evidence` object. A failure adds one sanitized `failure`
string. Control characters are escaped, and failure text is limited to 300
characters.

A configuration failure writes a smaller report with
`result: "configuration_error"`, `preflight_passed: false`, and a sanitized
field-and-error-type summary when the report destination is safe. A setup
failure writes `result: "failed"` and a sanitized exception class. An absent
`checks` array means that evaluation never ran.

The report excludes keys, installation tokens, the operator PAT, the database
URL, authorization headers, source policy contents, raw provider responses,
and webhook payloads. It is sanitized, not anonymous. Repository names, App
identities, installation IDs, versions, timestamps, paths, and counts remain
visible.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Configuration loaded, all 11 checks passed, and the report was created. |
| `1` | Evaluation or setup failed, or an evaluated report could not be created. |
| `2` | Command-line or configuration input was invalid. A configuration-error report is created when possible. |

Terminal output only identifies the report and gives a short failure
direction. The JSON report is the evidence record.

## Read and write boundary

The preflight reads:

- local source, Git metadata, tools, and trust files
- public repository metadata, refs, active rules, labels, files, and
  `CODEOWNERS` errors
- the two App registrations, installation inventories, and installation
  requests
- checker hook configuration and classic branch protection
- service identity, liveness, readiness, and metrics
- PostgreSQL version and schema metadata.

It creates one local report. PostgreSQL connections use read-only
transactions. The only GitHub `POST` requests mint short-lived,
Metadata-read installation tokens; the tokens remain in memory. The command
does not create or modify a repository, rule, pull request, review, Check Run,
file, App, installation, or database object.

## What a pass does not prove

A pass records sequential observations, not one atomic snapshot. It does not
prove:

- that the running source process loaded `source_revision`; runtime identity is
  an unauthenticated self-report, and source deployments deliberately report
  `build_revision: null`
- that the database URL reaches the same PostgreSQL instance as the service
- the operator PAT's exact repository selection or absence of write
  permissions; GitHub offers no token-introspection endpoint
- the Apps' **Only on this account** setting
- that the checker hook is active, that the service and App share the same
  webhook secret, or that a delivery reaches the service
- branch-rule bypass actors, administrator enforcement, or unrelated rule
  settings outside the properties checked above
- behavior after the starting snapshot, including a real App review, Check Run
  source, stale-review invalidation, human review, missed delivery,
  reconciliation, shared-head handling, or merge blocking
- independent authority from labels. Pull requests write access lets the
  approver App change labels, so labels route the workflow while path,
  CODEOWNER, App identity, and non-delegable rules limit authority
- production, release, or hosted-service readiness.

Native code-owner enforcement must remain enabled throughout the beta. The
manual acceptance and cleanup record lives in
[issue #76](https://github.com/stampbot/extra-codeowners/issues/76).
