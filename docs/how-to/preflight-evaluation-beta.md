# Preflight a disposable evaluation beta

Run this preflight immediately before testing an App approval on a real pull
request. It catches drift in the reviewed source, two disposable GitHub Apps,
repository rules, exact beta policy, running service, and PostgreSQL schema.

It does not exercise the approval flow. A passing report is the starting
record for the manual beta in
[issue #76](https://github.com/stampbot/extra-codeowners/issues/76).

!!! danger "Keep GitHub's native enforcement in charge"
    Use a disposable organization, public test repositories, and disposable
    credentials. Leave **Require review from Code Owners** enabled, require at
    least one approving review, and keep `Extra CODEOWNERS / approval`
    non-required for the entire beta. Do not use a beta result to merge
    production work.

## Prepare the test boundary

Run the preflight on a trusted Linux workstation. It needs Bash, a mounted
`/proc`, `/usr/bin/git`, `jq`, and the tools installed by `mise`. From a
standalone Extra CODEOWNERS clone, run:

```bash
mise run bootstrap
```

The source check rejects shallow clones, linked worktrees, alternate object
stores, Git submodules, and group- or world-writable checkout content and
metadata. Remove group and world write permission throughout the checkout
tree. A normal standalone clone is the least surprising choice.

Prepare these resources under one disposable GitHub.com organization:

- a public target repository
- that organization's public `.github` repository
- a checker GitHub App installed on those two repositories
- a separate approver GitHub App installed on the target only
- a source deployment with its worker and reconciler enabled
- a PostgreSQL database migrated by the reviewed source.

The target branch must meet four conditions:

1. Native code-owner review is required.
2. At least one approving review is required.
3. `Extra CODEOWNERS / approval` is not a required check.
4. No merge queue applies.

The preflight checks those four properties across active rules and classic
branch protection. Record the complete rule configuration yourself, including
bypass actors and whether administrators are subject to enforcement. The API
evidence does not prove those settings, and the beta must not change them.

Configure one harmless file below `docs/` as the beta path. Its standard
`CODEOWNERS` rule must name the humans or teams whose approval the App may
replace. Organization policy must enroll only the approver App, and repository
policy must contain one delegation with:

- that exact file path, not a glob
- the exact effective CODEOWNER set, without `*`
- the approver App
- the exact labels used by the test as `required_labels`.

The [configuration guide](configure.md) explains the policy format. The
preflight rejects any broader beta enrollment or delegation.

## Register the two Apps

Create both Apps under the disposable organization. In each registration, set
**Where can this GitHub App be installed?** to **Only on this account**.
GitHub's API does not expose that choice, so capture it in the manual beta
record.

Give the checker these exact permissions:

| Permission | Access |
| --- | --- |
| Repository: Checks | Read and write |
| Repository: Contents | Read |
| Repository: Pull requests | Read |
| Repository: Commit statuses | Read and write |
| Repository: Metadata | Read |
| Organization: Members | Read |

Subscribe the checker to these exact events:

- Check run
- Installation target
- Label
- Member
- Membership
- Organization
- Pull request
- Pull request review
- Push
- Repository
- Team
- Team add.

Set its webhook URL to the service origin followed by `/webhooks/github`.
Select JSON content, enable TLS certificate verification, and generate a
disposable webhook secret.

Give the approver these exact permissions:

| Permission | Access |
| --- | --- |
| Repository: Contents | Read |
| Repository: Pull requests | Read and write |
| Repository: Metadata | Read |

Do not subscribe the approver to events, and disable its webhook. The
repository's beta fixture uses this App only to submit a review.

Install each App once. Choose **Only select repositories**, then select:

- the target and `.github` repositories for the checker
- the target repository for the approver.

Clear any pending installation requests. The preflight requires exactly one
current installation for each App, no pending requests, the exact permissions
and events above, and no extra selected repositories. It also verifies the
checker hook URL, JSON content type, TLS verification, and presence of a
secret. You must still confirm that the hook is active and that the approver
hook is disabled.

Record both Apps' numeric IDs, slugs, and installation IDs. Record the
approver's numeric bot user ID too.

## Store the local inputs

Create an operator-only directory outside the source checkout:

```bash
export BETA_DIR="$HOME/.config/extra-codeowners/evaluation-beta"
install -d -m 0700 -- "$BETA_DIR"
```

Set `CHECKER_KEY_DOWNLOAD` and `APPROVER_KEY_DOWNLOAD` to the private-key files
downloaded from GitHub. Copy each key once, then remove the shell variables:

```bash
test ! -e "$BETA_DIR/checker.pem"
test ! -e "$BETA_DIR/approver.pem"
install -m 0600 -- "$CHECKER_KEY_DOWNLOAD" "$BETA_DIR/checker.pem"
install -m 0600 -- "$APPROVER_KEY_DOWNLOAD" "$BETA_DIR/approver.pem"
unset CHECKER_KEY_DOWNLOAD APPROVER_KEY_DOWNLOAD
```

Do not reuse a key between the Apps.

Copy the non-secret example configuration:

```bash
test ! -e "$BETA_DIR/preflight.toml"
install -m 0600 -- examples/evaluation-beta/preflight.toml \
  "$BETA_DIR/preflight.toml"
```

The configuration reader accepts exact mode `0400` or `0600`. It rejects
symbolic links, hard-linked files, files owned by another user, and files that
change while being read. App keys require exact mode `0600`.

## Pin the reviewed source

Choose the signed commit you reviewed. Before editing the configuration,
inspect the checkout:

```bash
git status --porcelain=v1 --untracked-files=all
git show -s --show-signature \
  --format='commit=%H%nsignature_status=%G?%nsigner_fingerprint=%GF' \
  HEAD
git verify-commit HEAD
```

The status command must print nothing. `signature_status` must be `G`, and
`git verify-commit` must exit `0`. Decide which signing key you trust before
you copy its full fingerprint. The preflight verifies an exact match; it
cannot make that trust decision for you.

The signed tree may contain 1 to 10,000 tracked files and 512 MiB in total.
Each file must be no larger than 64 MiB. The preflight rejects tracked
symlinks, submodules, unusual modes, unsafe path characters, index flags that
hide changes, files not owned by the current user, and files with more than
one hard link. It compares the index with the signed tree and hashes every
tracked file twice. A checkout that only appears clean because of
`assume-unchanged`, `skip-worktree`, or fsmonitor state fails.

For an SSH-signed commit, copy a reviewed allowed-signers file beside the
configuration:

```bash
allowed_signers_source="$(git config --path --get gpg.ssh.allowedSignersFile)"
test -n "$allowed_signers_source"
test ! -e "$BETA_DIR/allowed_signers"
install -m 0600 -- "$allowed_signers_source" "$BETA_DIR/allowed_signers"
unset allowed_signers_source
```

Review the public keys in the copy. Set
`source_ssh_allowed_signers_file = "allowed_signers"` in the TOML file. The
path is relative to that file. The preflight ignores Git's global
configuration and passes this trust file to Git explicitly.

For an OpenPGP-signed commit, put the complete 40- or 64-character fingerprint
in `source_signer_fingerprint` and remove
`source_ssh_allowed_signers_file`. The preflight requires the trust-file field
for SSH and forbids it for OpenPGP.

Edit `$BETA_DIR/preflight.toml` and replace every example value. Set
`source_checkout` to the absolute path of the standalone clone. Record the
local versions from the same shell that will run the preflight:

```bash
uv run python --version
uv --version
uv run python -c \
  'import extra_codeowners; print(extra_codeowners.__version__)'
```

Pin both public repositories by numeric ID, default-branch name, and full
default-branch commit. Enter the App and installation identities recorded
earlier. `check_name` and `policy_path` must match the running service.
`checker_webhook_url` must be `service_url` followed by
`/webhooks/github`.

The [configuration reference](../reference/evaluation-beta-preflight.md#configuration-file)
defines every field and cross-field rule. Keep credentials out of this file.

## Supply the four secret inputs

Point the preflight at the two key files:

```bash
export EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE="$BETA_DIR/checker.pem"
export EXTRA_CODEOWNERS_BETA_APPROVER_PRIVATE_KEY_FILE="$BETA_DIR/approver.pem"
```

Create a dedicated fine-grained PAT for the target repository. Grant
Repository administration read access and no write access. Do not reuse a
general operator or automation token.

Save the token in a new mode-`0600` file:

```bash
operator_token_file="$BETA_DIR/operator-token"
test ! -e "$operator_token_file"
install -m 0600 /dev/null "$operator_token_file"
IFS= read -r -s -p 'Fine-grained operator token: ' operator_token
printf '\n'
printf '%s' "$operator_token" >"$operator_token_file"
unset operator_token
export EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE="$operator_token_file"
unset operator_token_file
```

The value must start with `github_pat_`. The preflight can prove that it reads
repository-administration endpoints, but GitHub has no token-introspection
endpoint. Confirm the PAT's repository selection and read-only permissions in
GitHub, then retain that evidence with the run.

Read the disposable PostgreSQL URL without terminal echo:

```bash
IFS= read -r -s -p 'Disposable PostgreSQL URL: ' \
  EXTRA_CODEOWNERS_BETA_DATABASE_URL
printf '\n'
export EXTRA_CODEOWNERS_BETA_DATABASE_URL
```

Use the exact `postgresql+psycopg` driver and include one host, database,
username, and password. A remote connection must use
`sslmode=verify-full`. A direct loopback address or an operator-controlled
Unix-socket proxy may omit TLS.

Prefer a separate probe role with connect access, `USAGE` on the `public`
schema, and read access to the schema metadata used by the check. The
preflight forces read-only transactions, `search_path=public`, and
five-second statement, lock, idle-transaction, and connection bounds. It
validates the server version, migration head, and the complete required schema
contract.

The URL must reach the service's disposable database, but the preflight cannot
establish that relationship. Verify it in the deployment platform.

Secret environment variables are visible to sufficiently privileged local
processes. Run this on a workstation where untrusted processes do not share
your account.

## Run the preflight

Use one HTTPS origin for the service and checker webhook. Apply path-level
ingress controls at that origin:

- GitHub may reach only `POST /webhooks/github` without operator
  authentication.
- The workstation may reach `/`, `/api/runtime-identity`, `/health/live`,
  `/health/ready`, and `/metrics` through an operator-only route.
- Keep documentation and setup routes operator-only as well.

The application does not authenticate its operator endpoints. Do not expose
them to the public Internet merely to make the preflight work.

Reports are create-once. Choose a new path for every attempt:

```bash
export BETA_REPORT="$BETA_DIR/preflight-$(date -u +%Y%m%dT%H%M%SZ).json"
test ! -e "$BETA_REPORT"
uv run python -m tools.evaluation_beta preflight \
  --config "$BETA_DIR/preflight.toml" \
  --report "$BETA_REPORT"
```

A passing run exits `0` and creates a mode-`0600` report. Require the exact
schema, source deployment kind, 11 check IDs, and passing outcomes:

```bash
jq -e '
  .schema_version == 1 and
  .kind == "extra-codeowners-disposable-evaluation-beta-preflight" and
  .result == "passed" and
  .preflight_passed == true and
  .scope.deployment_kind == "source" and
  ([.checks[].id] | sort) == [
    "app_installations",
    "branch_safety",
    "codeowners",
    "final_branch_refs",
    "insecure_changes_metric",
    "policy",
    "postgresql",
    "public_repositories",
    "service_health",
    "source",
    "tool_versions"
  ] and
  ([.checks[].outcome] | all(. == "passed")) and
  ([.checks[] | select(.id == "service_health") |
    .evidence.self_reported_build_revision] == [null])
' "$BETA_REPORT"
```

The command must print `true` and exit `0`. A source deployment reports
`build_revision: null`; that is intentional. The runtime endpoint is a
self-report, not proof that the process loaded the local reviewed commit.

Inspect the report before sharing it. It excludes credential values and raw
provider responses, but it includes repository names, App identities,
versions, paths, and operational evidence. Keep the report with the beta
record.

GitHub reads happen one after another. Do not change App, installation,
repository, branch-rule, label, or policy state during the run.

## Diagnose a failed run

The preflight continues through independent checks, so one report may contain
several failures. Start with each failed check ID:

- `source` and `tool_versions`: use a standalone clean checkout at the signed
  commit, restore the expected trust file, and match every pinned version.
- `app_installations`: restore the exact permission and event contracts,
  single-installation inventories, repository selections, checker hook, and
  approver bot identity. Clear pending installation requests.
- `public_repositories` and `final_branch_refs`: verify organization and
  repository IDs, public availability, default branches, and pinned commits.
- `branch_safety`: restore native code-owner review and a minimum review count
  of one. Remove the Extra CODEOWNERS required context and any merge queue.
- `codeowners` and `policy`: fix GitHub's `.github/CODEOWNERS` errors and
  restore the one exact App, delegation, file, owner set, and required-label
  set.
- `service_health`: compare the entire runtime identity with the TOML file.
  Confirm production mode, PostgreSQL, recent checker-App authentication, and
  healthy worker and reconciler tasks.
- `postgresql`: check the route, TLS mode, credentials, read-only session
  settings, server version, migration head, and schema.
- `insecure_changes_metric`: disable
  `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES` and confirm the unlabelled metric
  is exactly `0`.

Exit `2` means the command line or configuration was invalid. Exit `1` means
setup or evaluation failed, or the report could not be created. The
[exit-status reference](../reference/evaluation-beta-preflight.md#exit-status)
defines the complete contract.

The report writer never overwrites an earlier attempt. Fix the cause, choose a
new report path, and run the whole preflight again. Do not waive a failed
check or weaken native enforcement.

## Complete the manual beta

A pass proves the configured starting boundary. Before opening the beta pull
requests, add the facts that GitHub and the service cannot prove themselves:

1. Capture both Apps' **Only on this account** setting. Confirm the checker
   hook is active and the approver hook is disabled.
2. Capture the complete target-branch rules, bypass actors, and administrator
   enforcement. Compare them with the baseline after the beta.
3. Bind the running source process to the reviewed `source_revision` with
   deployment-platform evidence. Also prove that the service uses the
   inspected checker key, webhook secret, and PostgreSQL database.
4. Deliver a signed GitHub webhook and confirm that GitHub, ingress, the
   service, and the durable queue record the same delivery.
5. Add a dated acceptance note with the GitHub plan, public repositories, App
   IDs and slugs, installation-selection mode, PostgreSQL version, and relevant
   non-secret configuration. Attach the unchanged preflight JSON beside it;
   the report has a fixed schema and is not a place for operator notes.

Then complete the pull-request matrix in
[issue #76](https://github.com/stampbot/extra-codeowners/issues/76). It covers
the real approver review and Check Run, human review, stale review, missing
labels, non-delegable and mixed paths, shared heads, missed webhooks, and
reconciliation.

Treat labels as routing input. The approver needs Pull requests write access
to submit a review, and that permission also lets it change labels. The actual
limits are the exact path, effective CODEOWNER set, App identity, and
non-delegable rules.

Keep the native rule enabled and the Extra CODEOWNERS check non-required until
every negative case behaves as expected. A passing preflight is not merge
authority.

## Clean up

If you stop after preflight, revoke the dedicated PAT and both App keys. Remove
the local keys, PAT, and edited configuration unless your evidence-retention
policy requires them. Keep only the sanitized report you intend to retain.

Clear all four secret inputs from the current shell:

```bash
unset EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE
unset EXTRA_CODEOWNERS_BETA_APPROVER_PRIVATE_KEY_FILE
unset EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE
unset EXTRA_CODEOWNERS_BETA_DATABASE_URL
```

After the full beta, close its pull requests without merging and disable the
repository policy. Stop the service and public webhook route, remove both App
installations, revoke every disposable credential, and destroy the database,
repositories, Apps, and organization. Confirm that native enforcement and the
recorded branch rules never changed.
