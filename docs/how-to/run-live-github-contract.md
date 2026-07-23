# Run the live GitHub contract fixture

Use this fixture to measure GitHub behavior that a simulated API cannot prove.
It creates live resources, changes repository rules, attempts merges, and then
deletes the resources it owns.

!!! danger
    Run this only in an organization reserved for disposable tests. Never point
    it at production Apps, repositories, credentials, or policy. The fixture
    deliberately creates and deletes an organization ruleset and a private
    repository.

The fixture normally cleans up after a successful observation, a failed
assertion, or `Ctrl+C`. A forced process kill, power loss, host failure, or
loss of operator access can leave resources behind. The report and terminal
output name what you must delete manually.

One run creates a private repository, an organization ruleset scoped to that
repository, one or more repository rulesets, branches, pull requests, Check
Runs, and an optional App-authored review. It also attempts a merge to prove
that an `in_progress` check blocks the API. Cleanup deletes the
organization ruleset first and then the repository, which removes the
repository-scoped resources with it.

## What the fixture measures

The tool answers these GitHub.com contract questions:

- Does changing this App's successful Check Run back to `in_progress`
  block the pull request?
- Do repository and organization rulesets retain the expected App source?
- Does a second or retargeted pull request initially inherit a success attached
  to the same head commit?
- Does invalidating that commit-scoped check block both pull requests?
- When a separate approver App is configured, does its review satisfy an
  ordinary required-approval count of one?
- Which field names appear in the App's `pull_request` and
  `installation_repositories` deliveries?

The fixture does not deploy Extra CODEOWNERS, verify a webhook signature, or
test a service's delivery and reconciliation timing. Those checks are separate.

## Prerequisites

Prepare:

- a GitHub organization used only for disposable integration tests
- an operator token limited to that organization and authorized to create and
  delete private repositories, repository rulesets, organization rulesets,
  branches, contents, and pull requests
- a checker App installed in that organization
- the checker's App ID, installation ID, and a disposable private-key file
- optionally, a separate approver App with Pull requests write.

The operator token needs repository Administration, Contents, and Pull
requests write, plus organization Administration write. Prefer a short-lived
fine-grained personal access token restricted to the disposable organization.
The organization's GitHub plan must support rulesets on private repositories.

The checker App needs:

- Checks and Commit statuses write
- Contents and Pull requests read
- an active webhook
- the normal
  [Extra CODEOWNERS subscriptions](../reference/github-permissions.md#webhook-subscriptions).

The fixture pins GitHub REST API version `2026-03-10`. Its calls follow the
GitHub contracts for [organization rulesets][org-rulesets],
[repository rulesets][repository-rulesets],
[installation repository selection][app-repositories],
[App-authored reviews][pull-reviews], and
[App webhook deliveries][app-deliveries].

Installation creation, suspension, permission acceptance, and uninstallation
remain manual tests because they can affect every repository in an
installation.

### Prefer all-repositories test installations

An all-repositories installation automatically gains access to the new fixture
repository. GitHub may not emit an
`installation_repositories.added` delivery in that mode.

Use selected-repositories mode only when you need to test that event. GitHub's
repository-selection endpoint accepts only a classic personal access token
(PAT) with the broad `repo` scope. It rejects fine-grained PATs and GitHub
App tokens.

If either App uses selected repositories:

1. Create a separate short-lived classic PAT from a dedicated test account.
2. Give that account administrator access to the new fixture repository,
   normally through an owner role in the disposable organization.
3. Authorize single sign-on when the organization requires it.
4. Revoke the PAT as soon as the run ends.

Do not reuse the fine-grained operator token or any production credential for
repository selection.

## 1. Record a clean source revision

Use a trusted workstation and a POSIX-compatible Bash shell. Review
`mise.toml`, then run all commands from the repository root.

Confirm that the checkout contains no tracked or untracked changes:

```bash
test -z "$(git status --porcelain)"
```

The command must exit with no output. Commit, remove, or set aside every change
before continuing.

Export the non-secret fixture values:

```bash
export EXTRA_CODEOWNERS_LIVE_ORGANIZATION='disposable-org'
export EXTRA_CODEOWNERS_LIVE_CONFIRM='delete-disposable-repository-in:disposable-org'
export EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION="$(git rev-parse HEAD)"
export EXTRA_CODEOWNERS_LIVE_CHECKER_APP_ID='123456'
export EXTRA_CODEOWNERS_LIVE_CHECKER_INSTALLATION_ID='23456789'
export EXTRA_CODEOWNERS_LIVE_CHECKER_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/test.pem"
```

Replace the organization, numeric IDs, and private-key path. The confirmation
string must include the exact organization name. The source revision must be a
full 40-character commit SHA.

Read the operator token without terminal echo or shell-history exposure:

```bash
IFS= read -r -s -p 'Disposable-organization operator token: ' \
  EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
printf '\n'
export EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
```

Environment variables remain readable to sufficiently privileged local
processes. Do this only on a trusted workstation without untrusted processes
sharing the operator account. The fixture does not accept tokens or private
keys as command-line arguments.

If an App uses selected repositories, prompt for its separate classic PAT:

```bash
IFS= read -r -s -p 'Disposable repository-selection classic PAT: ' \
  EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN
printf '\n'
export EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN
```

Do not set that variable for all-repositories installations. The fixture never
falls back to the operator token.

To test the numeric review rule, configure all three approver values:

```bash
export EXTRA_CODEOWNERS_LIVE_APPROVER_APP_ID='345678'
export EXTRA_CODEOWNERS_LIVE_APPROVER_INSTALLATION_ID='45678901'
export EXTRA_CODEOWNERS_LIVE_APPROVER_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/approver.pem"
```

Without them, the report records the App-review assertions as `null`.

## 2. Run the fixture

Review the checked-out revision and `mise.toml` first. `mise trust` permits
repository configuration and tasks to execute locally. Then install the pinned
toolchain and locked dependencies and start the test:

```bash
mise trust
mise install
mise run bootstrap
mise run test:github-contract
```

The fixture waits up to 90 seconds for each mergeability transition. It also
leaves a possible inherited success untouched for five seconds after opening
or retargeting a shared-head pull request.

To measure a longer eventual-consistency window, set an observation period no
greater than 30 seconds:

```bash
export EXTRA_CODEOWNERS_LIVE_OBSERVATION_SECONDS=15
mise run test:github-contract
```

The command exits nonzero when configuration or setup fails, GitHub returns an
indeterminate response, an observation never settles, or cleanup fails. A
determinate unsafe result is recorded as `false` and does not by itself
make the fixture fail.

Setting `EXTRA_CODEOWNERS_LIVE_KEEP_REPOSITORY=true` deliberately skips
cleanup for fixture development. Never use it for a routine evidence run.

## 3. Confirm cleanup and interpretation

A completed observation prints the disposable repository URL, removes the
organization ruleset and repository, writes
`live-github-contract-report.json`, and exits zero.

Check only that the observation completed and cleanup succeeded:

```bash
jq -e '.result == "observed" and .cleanup_succeeded == true' \
  live-github-contract-report.json
```

Then inspect the safety interpretation:

```bash
jq '.interpretation, .assertions' live-github-contract-report.json
```

`result: observed` means the tool obtained determinate answers. It does
not mean the GitHub contract failed closed.

The report always sets `interpretation.production_warning_required` to
`true`. Even a true `github_contract_fail_closed` value covers only
the repository-rule and Check Run probes. Delayed and lost delivery tests
against a deployed service remain mandatory.

If cleanup fails, use the printed repository URL and ruleset name. Delete the
named organization ruleset first, then the repository. Do not assume a failed
process removed either one.

## 4. Review the sanitized report

The report contains:

- booleans and timestamps
- the pinned API version and source revision
- checker and approver installation-selection modes
- webhook payload key sets
- cleanup status.

It omits credentials, delivery IDs, signatures, raw payload values, repository
IDs, actor names, and raw API responses.

Before attaching the report to an issue:

1. Inspect it for unexpected private metadata.
2. Confirm that `source_revision` matches the reviewed commit.
3. Record the GitHub plan separately.
4. Confirm both installation-selection modes.
5. Distinguish `true`, `false`, and `null`. A null
   App-review assertion means approver credentials were not supplied.
6. Keep the production warning while either shared-head inheritance assertion
   is true or any delivery interval can expose that success.

This report is not end-to-end service evidence. The fixture writes Check Runs
directly so it can isolate GitHub's contract.

## 5. Test delayed and lost delivery

Run this separate procedure only against a disposable Extra CODEOWNERS
deployment and repository that passed the
[configuration negative tests](configure.md#5-test-the-boundary).
You need control of webhook ingress and access to App delivery logs, service
metrics, and current-head checks.

Create two protected base branches with equivalent Extra CODEOWNERS required
checks and expected App sources. GitHub will not open two pull requests with
the same head and base, so point each pull request at a different base branch.
Use fictional content and delete both branches after the test.

Choose and record a reconciliation interval long enough to observe a delayed
event but short enough to finish the recovery test. Keep the worker and
database available.

### Delay and redeliver an event

1. Produce a successful check on the first disposable pull request.
2. Block only the deployment's webhook route at the reverse proxy.
3. Open a second pull request with the same head. Confirm GitHub recorded a
   failed `pull_request.opened` delivery, and record whether the new pull
   request inherited the first success.
4. Restore ingress before the next reconciliation run.
5. In **Advanced → Recent deliveries**, redeliver the failed event.
6. Confirm that the service accepts it, moves the shared commit's check to
   `in_progress`, and then fails it because two open pull requests share
   the head.

### Lose an event and recover by reconciliation

Repeat the setup with a fresh shared head, but do not redeliver the failed
event. Restore ingress and wait through one complete reconciliation interval.
Confirm:

- `extra_codeowners_reconciliation_last_success_timestamp_seconds`
  advances
- reconciliation enqueues both open pull requests
- the inherited success moves to `in_progress` and then failure
- neither pull request is mergeable while the shared head remains
- the queue returns to baseline with no dead job.

If the check does not become blocking, restore native human code-owner
enforcement before debugging. Preserve only sanitized timestamps, state
transitions, aggregate metrics, and the tested source revision. Do not retain
raw deliveries or private repository metadata.

## 6. Complete manual lifecycle checks

Exercise these transitions one at a time in the disposable App:

| Transition | Expected event | Service behavior |
| --- | --- | --- |
| Install the App | `installation.created` | Retain the event, advance the authority epoch, and fan out. |
| Resume a suspended installation | `installation.unsuspend` | Retain the event, advance the authority epoch, and fan out. |
| Accept newly requested permissions | `installation.new_permissions_accepted` | Retain the event, advance the authority epoch, and fan out. |
| Add a selected repository | `installation_repositories.added` | Retain the event, advance the authority epoch, and fan out. |
| Remove only ordinary selected repositories | `installation_repositories.removed` | Authenticate and acknowledge without work because access is already gone. |
| Remove the organization-policy repository | `installation_repositories.removed` | Retain the event, advance the authority epoch, and fan out to still-accessible targets. |
| Uninstall the App | `installation.deleted` | Authenticate and acknowledge without work because no target remains accessible. |

After each transition, inspect **Advanced → Recent deliveries** or the App
delivery API. Retain only a sanitized field-name record. Confirm the behavior
listed in the table. For fan-out events, wait for authority work to drain and
verify every still-accessible open pull request.

An access-removal event may arrive after the App can no longer revoke a check.
Restore native human enforcement before removing any repository whose merges
matter.

## 7. Remove local credentials

Unset tokens when the run and cleanup checks finish:

```bash
unset EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
unset EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN
```

Revoke the operator token and any repository-selection PAT. If either private
key existed only for this test, revoke it in the App settings and securely
remove the local file.

Keep the sanitized report, source commit, GitHub plan, and
installation-selection modes. Do not keep credentials or raw deliveries with
the evidence.

[app-deliveries]: https://docs.github.com/en/rest/apps/webhooks?apiVersion=2026-03-10
[app-repositories]: https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#add-a-repository-to-an-app-installation
[org-rulesets]: https://docs.github.com/en/rest/orgs/rules?apiVersion=2026-03-10#create-an-organization-repository-ruleset
[pull-reviews]: https://docs.github.com/en/rest/pulls/reviews?apiVersion=2026-03-10#create-a-review-for-a-pull-request
[repository-rulesets]: https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#create-a-repository-ruleset
