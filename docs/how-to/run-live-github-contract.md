# Run the live GitHub contract fixture

Use this procedure when you need evidence about GitHub behavior that a
simulated API cannot provide. The repository fixture creates real pull
requests, rulesets, and Check Runs. A second tool captures selected GitHub App
lifecycle delivery shapes.

!!! danger
    Use an organization and Apps reserved for disposable tests. Never point
    these tools at production credentials, repositories, or policy. The
    repository fixture creates and deletes a private repository and an
    organization ruleset.

The fixture cleans up after a normal result, an error, or `Ctrl+C`. A power
loss, forced process kill, host failure, or loss of operator access can still
leave resources behind. Before it sends the create request, the fixture prints
the repository owner, high-entropy name, and URL. Keep those recovery
coordinates until the report confirms cleanup.

This procedure gives you three different kinds of evidence:

1. The automated repository fixture measures GitHub's ruleset, Check Run,
   shared-head, retarget, webhook-log, and optional App-review behavior.
2. The lifecycle collector records whether selected App lifecycle deliveries
   appeared and which payload fields GitHub supplied.
3. Manual deployed-service tests measure webhook delay, loss, reconciliation,
   fan-out, and access-loss handback.

You need all three before treating the contract work as complete. See
[Live GitHub evidence reports](../reference/live-github-evidence-reports.md)
for the JSON schemas and machine-readable checks.

## Before you start

Prepare a GitHub organization used only for disposable integration tests. Its
plan must support rulesets on private repositories.

You also need:

- a short-lived operator token restricted to the disposable organization
- a checker App installed in that organization
- the checker's App ID, installation ID, and a disposable private-key file
- optionally, an approver App for the numeric review probe
- `jq`, `mise`, and a trusted POSIX-compatible shell.

The operator token needs enough organization and repository administration to
create and delete private repositories, organization and repository rulesets,
branches, contents, and pull requests. Prefer a short-lived fine-grained
personal access token restricted to the disposable organization.

The checker App needs:

- Checks write
- Commit statuses write at App registration
- Contents read
- Pull requests read
- an active webhook
- the normal
  [Extra CODEOWNERS subscriptions](../reference/github-permissions.md#webhook-subscriptions).

GitHub requires Commit statuses write before an App can be selected as the
expected source for an organization ruleset. The fixture's installation token
does not request that permission, and the fixture never writes a commit status.

The optional approver App needs Contents read and Pull requests write. Keep it
separate from the checker when you want the test to establish review identity
independently from check identity.

The tools pin GitHub REST API version `2026-03-10`. Review the current
[organization ruleset][org-rulesets], [repository ruleset][repository-rulesets],
[App review][pull-reviews], and [App delivery][app-deliveries] contracts before
a formal evidence run.

### Choose the installation mode

An all-repositories installation gains access to the newly created fixture
repository without another token. GitHub may not emit an
`installation_repositories.added` delivery in this mode, so that assertion is
recorded as not run.

A selected-repositories installation lets you measure the add event, but the
fixture must add its new repository to the installation. GitHub's
repository-selection endpoint requires a classic personal access token with
the broad `repo` scope; it does not accept a fine-grained PAT or App token.

If either test App uses selected repositories:

1. Create a separate, short-lived classic PAT from a dedicated test account.
2. Give that account administrator access to the disposable repository,
   normally through an owner role in the test organization.
3. Authorize single sign-on if the organization requires it.
4. Revoke the PAT as soon as the fixture has cleaned up.

Do not reuse the fine-grained operator token or a production credential for
repository selection.

## Run the repository fixture

### 1. Bind the run to a clean commit

Run every command in this guide from the repository root. First make sure the
checkout has no tracked or untracked changes:

```bash
test -z "$(git status --porcelain)"
```

The command must exit without output. Commit, remove, or set aside every
change before continuing.

Export the non-secret fixture values:

```bash
export EXTRA_CODEOWNERS_LIVE_ORGANIZATION='disposable-org'
export EXTRA_CODEOWNERS_LIVE_CONFIRM='delete-disposable-repository-in:disposable-org'
export EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION="$(git rev-parse HEAD)"
export EXTRA_CODEOWNERS_LIVE_CHECKER_APP_ID='123456'
export EXTRA_CODEOWNERS_LIVE_CHECKER_INSTALLATION_ID='23456789'
export EXTRA_CODEOWNERS_LIVE_CHECKER_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/checker.pem"
```

Replace the organization, IDs, and key path. The confirmation string must
contain the exact organization name. The revision must resolve to a full
40-character commit SHA.

Read the operator token without terminal echo:

```bash
IFS= read -r -s -p 'Disposable-organization operator token: ' \
  EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
printf '\n'
export EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
```

Environment variables are visible to sufficiently privileged local processes.
Use a trusted workstation without untrusted processes sharing your account.
The fixture does not accept tokens or private keys on the command line.

For a selected-repositories installation, read the separate classic PAT:

```bash
IFS= read -r -s -p 'Disposable repository-selection classic PAT: ' \
  EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN
printf '\n'
export EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN
```

Leave that variable unset for all-repositories installations. The fixture
never falls back to the operator token.

To include the numeric approval probe, configure all three approver values:

```bash
export EXTRA_CODEOWNERS_LIVE_APPROVER_APP_ID='345678'
export EXTRA_CODEOWNERS_LIVE_APPROVER_INSTALLATION_ID='45678901'
export EXTRA_CODEOWNERS_LIVE_APPROVER_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/approver.pem"
```

When these values are absent, all three App-review observations are explicitly
recorded as not run.

### 2. Start the fixture

Review the checked-out `mise.toml` before trusting it. Then install the pinned
toolchain and locked dependencies:

```bash
mise trust
mise install
mise run bootstrap
mise run test:github-contract
```

Before creating anything, the fixture prints the generated repository's owner,
name, and URL. It checks that the name is unused, then sends the create
request. Keep that block until cleanup is confirmed. It is the recovery path
if GitHub creates the repository but the response is lost or cannot be
decoded.

Each mergeability transition can take up to 90 seconds. The fixture also
leaves a possible inherited success untouched for five seconds after it opens
or retargets a pull request with a shared head.

To use a longer observation window, choose a value no greater than 30 seconds:

```bash
export EXTRA_CODEOWNERS_LIVE_OBSERVATION_SECONDS=15
mise run test:github-contract
```

The command exits nonzero for invalid configuration, an indeterminate GitHub
response, a transition that never settles, or cleanup failure. A determinate
unsafe result is written as `false`; the command does not hide it by turning
the observation into a fixture error.

The webhook-log probe follows GitHub's validated `rel="next"` cursor. Each
poll reads at most 300 summaries in three requests of up to 100 summaries.
When the probe reaches that bound while another page remains, it can still
record a delivery it found. It cannot conclude that an unseen delivery was
absent. The affected observation is marked `incomplete`, and the configured
run is incomplete.

`EXTRA_CODEOWNERS_LIVE_KEEP_REPOSITORY=true` skips all GitHub resource cleanup
for fixture development. It retains both the repository and the active
organization ruleset, and it prevents `configured_run_complete` from becoming
true. Do not use it for an evidence run.

### 3. Verify cleanup and completeness

The default report path is `live-github-contract-report.json`. Require the
schema, completed observation, cleanup, and configured probe coverage:

```bash
jq -e '
  .schema_version == 2 and
  .result == "observed" and
  .cleanup_succeeded == true and
  .evidence_completeness.configured_run_complete == true and
  .evidence_completeness.webhook_capture_metadata_valid == true and
  .evidence_completeness.incomplete == [] and
  .webhook_capture.incomplete_observations == []
' live-github-contract-report.json
```

If this command passes, the configured automated probes returned determinate
answers. It does not mean that those answers were safe.

Inspect the interpretation and raw values:

```bash
jq '{
  interpretation,
  assertions,
  observed_false: .evidence_completeness.observed_false,
  not_run: .evidence_completeness.not_run,
  missing: .evidence_completeness.missing,
  invalid: .evidence_completeness.invalid,
  incomplete: .evidence_completeness.incomplete,
  repository_creation: .fixture.repository_creation_state,
  webhook_capture,
  manual: .evidence_completeness.manual_evidence_required
}' live-github-contract-report.json
```

Pay attention to the distinction:

- `observed_false` means the probe ran and returned false.
- `not_run` means an optional or inapplicable probe was deliberately skipped.
- `missing` means the run ended before recording the probe.
- `invalid` means the report contains a value outside the schema.
- `incomplete` means the delivery-list bound prevented a reliable
  present-or-absent answer.

If you need the complete automated provider evidence set, configure the
approver App and require:

```bash
jq -e \
  '.evidence_completeness.full_automated_observations_complete == true' \
  live-github-contract-report.json
```

That field measures presence, not safety. Review each assertion and keep the
manual evidence list open.

The fixture prints the organization ruleset's recovery name before it creates
the rule. After creation, it also prints the numeric ruleset ID. If cleanup
failed, delete that organization ruleset before deleting the printed
repository.

Check `fixture.repository_creation_state` before closing the incident:

- `not_attempted` means the fixture never sent the repository create request.
- `response_confirmed_cleaned`, `response_unknown_cleaned`, and
  `response_unknown_resolved_absent` are terminal cleanup states.
- `manual_cleanup_required` means the fixture could not prove the repository
  absent or delete it. Use the printed URL.
- A state ending in `_retained` means cleanup was deliberately disabled.
- `attempted_response_unknown` means the report was written before recovery
  reached a conclusion.

Do not assume that a failed or interrupted process removed either resource.

### 4. Inspect the report before sharing it

The fixture retains assertions, timestamps, installation selection modes, and
payload key sets. It omits credentials, delivery IDs, signatures, raw webhook
payloads, repository IDs, actor names, and raw API responses.

Before attaching the report to an issue:

1. Inspect it for unexpected private metadata.
2. Confirm `source_revision` matches the reviewed commit.
3. Record the GitHub plan separately.
4. Record which installation-selection modes were exercised.
5. Preserve false and not-run results. Do not rewrite them as absent.
6. Keep the production warning and manual evidence list with the report.

The fixture writes Check Runs directly. It is not end-to-end evidence for a
deployed Extra CODEOWNERS service.

## Capture a lifecycle delivery contract

Use the lifecycle collector immediately after one manual transition. It reads
the App's delivery history with an App JWT and writes field names rather than
payload values.

The App private key grants App-level access to delivery history. Use a
disposable key on a trusted workstation and remove it when the capture is
finished.

### 1. Record the start of the capture window

Set the revision and record the current UTC second before making the change:

```bash
export EXTRA_CODEOWNERS_LIFECYCLE_SOURCE_REVISION="$(git rev-parse HEAD)"
export EXTRA_CODEOWNERS_LIFECYCLE_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Now perform exactly one transition in the disposable App or repository. For an
installation-created event, record the timestamp first, install the App, then
copy the new installation ID from the disposable installation settings. For
an uninstall event, retain the old installation ID until capture is complete.

Configure the App identity and the exact event/action pair:

```bash
export EXTRA_CODEOWNERS_LIFECYCLE_APP_ID='123456'
export EXTRA_CODEOWNERS_LIFECYCLE_INSTALLATION_ID='23456789'
export EXTRA_CODEOWNERS_LIFECYCLE_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/checker.pem"
export EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED='installation.unsuspend'
```

The expected value can contain a comma-separated list, but one transition per
capture is easier to review and less likely to exceed a bound.

### 2. Run and gate the capture

The command has no positional arguments. Its help text lists the required
environment and makes the shell exit contract explicit:

```bash
uv run python -m tools.capture_github_lifecycle_contract --help
```

Run the capture, then check the report:

```bash
mise run capture:github-lifecycle-contract
jq -e '
  .schema_version == 1 and
  .result == "observed" and
  .capture_complete == true and
  all(.observations[]; .state == "observed")
' live-github-lifecycle-report.json
```

The collector itself exits nonzero unless every expected event was observed
inside a complete bounded capture. Keep the `jq` check anyway: it makes the
evidence contract explicit in a transcript or later automation.

The collector reads at most 100 delivery summaries across no more than eight
page requests, then fetches at most 24 matching details. It follows only the
cursor from GitHub's `rel="next"` link and sends that cursor back to the fixed
GitHub delivery endpoint. It never follows a response-supplied URL.

A full page without `rel="next"` is complete. A short page with `rel="next"`
is not; the collector continues until GitHub omits that relation. If another
page remains when either list bound is reached, the report marks the delivery
window incomplete. A malformed, ambiguous, duplicate, or off-host next link
fails the capture instead of being followed.

Use a fresh, low-traffic disposable App whose delivery history fits within the
list bounds. If more than 24 matching deliveries fall inside the selected
window, repeat one transition with a shorter window. Do not raise the bounds
and call the result equivalent. The report records the limits and number of
pages read, but not pagination URLs or cursors.

An expected event can be `not_observed` even when `result` is `observed`. That
means the bounded window was complete but the event was absent. The command
still exits nonzero because `capture_complete` is false. An `incomplete` state
means the page or detail bound prevented either conclusion.

### 3. Verify service behavior separately

The lifecycle report proves only what appeared in GitHub's App delivery log.
It does not prove that ingress received the event or that Extra CODEOWNERS
retained and processed the right work.

For each transition, confirm both the delivery contract and the deployed
service result:

| Transition | Expected pair | Deployed-service check |
| --- | --- | --- |
| Install the App | `installation.created` | Installation-wide authority work is retained and drains. |
| Resume an installation | `installation.unsuspend` | Installation-wide authority work is retained and drains. |
| Accept new permissions | `installation.new_permissions_accepted` | Installation-wide authority work is retained and drains. |
| Add a selected repository | `installation_repositories.added` | Installation-wide authority work discovers the new target. |
| Remove an ordinary selected target | `installation_repositories.removed` | The authenticated delivery is acknowledged without unreachable-target work. |
| Remove the organization-policy repository | `installation_repositories.removed` | The authority epoch advances and still-accessible targets are fanned out. |
| Rename an installation account | `installation_target.renamed` | Work is rediscovered under current repository names. |
| Rename or transfer a repository | `repository.renamed` or `repository.transferred` | The authority epoch advances and current names are rediscovered. |
| Archive a repository | `repository.archived` | GitHub records the event; no fan-out is required while the repository cannot merge. |
| Unarchive a repository | `repository.unarchived` | Current open pull requests are reevaluated before merging resumes. |
| Delete the policy repository | `repository.deleted` | The authority epoch advances and still-accessible targets are fanned out. |
| Delete an ordinary target | `repository.deleted` | GitHub records the event; the deleted target needs no work. |
| Suspend or uninstall the App | `installation.suspend` or `installation.deleted` | GitHub records the event; the service cannot substitute for the prior native-enforcement handback. |

Follow [Change repository access safely](operate.md#change-repository-access-safely)
before suspension, uninstallation, removal, or a transfer that may lose App
access. Once access is gone, the App may be unable to revoke an earlier
success.

## Test delayed and lost delivery

Run this part only against a disposable Extra CODEOWNERS deployment and a
repository that has passed the
[configuration boundary tests](configure.md#5-test-the-boundary). You need
control of webhook ingress and access to the App delivery log, service
metrics, current checks, and queues.

Create two protected base branches with equivalent Extra CODEOWNERS required
checks and expected App sources. GitHub will not open two pull requests with
the same head and base, so point each pull request at a different base. Use
fictional content and remove both branches after the test.

Choose and record a reconciliation interval that gives you time to observe a
delayed event. Keep the worker and database available.

### Delay and redeliver

1. Produce a successful check on the first disposable pull request.
2. Block only the deployment's webhook route at the reverse proxy.
3. Open a second pull request with the same head. Confirm GitHub recorded a
   failed `pull_request.opened` delivery, and record whether the second pull
   request inherited the first success.
4. Restore ingress before the next reconciliation run.
5. In **Advanced → Recent deliveries**, redeliver the failed event.
6. Confirm the service accepts it, moves the shared commit's check to
   `in_progress`, and then fails it because two open pull requests share the
   head.

### Lose and reconcile

Repeat the setup with a fresh shared head, but do not redeliver the failed
event. Restore ingress and wait through one complete reconciliation interval.
Confirm:

- `extra_codeowners_reconciliation_last_success_timestamp_seconds` advances
- reconciliation enqueues both open pull requests
- the inherited success moves to `in_progress` and then failure
- neither pull request is mergeable while the head remains shared
- the queue returns to baseline without a dead job.

If the check does not become blocking, restore native human code-owner
enforcement before debugging. Retain only sanitized timestamps, state
transitions, aggregate metrics, and the tested source revision.

## Remove credentials and local state

After GitHub resources are gone and the reports are inspected, unset the
credentials:

```bash
unset EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
unset EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN
unset EXTRA_CODEOWNERS_LIVE_CHECKER_APP_ID
unset EXTRA_CODEOWNERS_LIVE_CHECKER_INSTALLATION_ID
unset EXTRA_CODEOWNERS_LIVE_CHECKER_PRIVATE_KEY_FILE
unset EXTRA_CODEOWNERS_LIVE_APPROVER_APP_ID
unset EXTRA_CODEOWNERS_LIVE_APPROVER_INSTALLATION_ID
unset EXTRA_CODEOWNERS_LIVE_APPROVER_PRIVATE_KEY_FILE
unset EXTRA_CODEOWNERS_LIFECYCLE_APP_ID
unset EXTRA_CODEOWNERS_LIFECYCLE_INSTALLATION_ID
unset EXTRA_CODEOWNERS_LIFECYCLE_PRIVATE_KEY_FILE
unset EXTRA_CODEOWNERS_LIFECYCLE_SOURCE_REVISION
unset EXTRA_CODEOWNERS_LIFECYCLE_SINCE
unset EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED
```

Revoke the operator token and any repository-selection PAT. Revoke disposable
App keys in the App settings, then securely remove their local files.

Keep the sanitized reports, source commit, GitHub plan, and installation
selection modes. Do not store credentials or raw deliveries with the evidence.

[app-deliveries]: https://docs.github.com/en/rest/apps/webhooks?apiVersion=2026-03-10
[org-rulesets]: https://docs.github.com/en/rest/orgs/rules?apiVersion=2026-03-10#create-an-organization-repository-ruleset
[pull-reviews]: https://docs.github.com/en/rest/pulls/reviews?apiVersion=2026-03-10#create-a-review-for-a-pull-request
[repository-rulesets]: https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#create-a-repository-ruleset
