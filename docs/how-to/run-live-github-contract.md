# Run the live GitHub contract fixture

Use this fixture to measure the GitHub behavior that Extra CODEOWNERS cannot
prove with a simulated API. It creates a private disposable repository, one
organization ruleset, repository rulesets, branches, and pull requests. It
then deletes the organization ruleset and repository after success, a failed
assertion, or an interactive interruption. A forced process kill, host failure,
or loss of operator access can still prevent cleanup.

The fixture answers these questions against GitHub.com:

- Does changing this App's completed successful Check Run back to
  `in_progress` make the pull request unmergeable?
- Do repository and organization rulesets preserve the expected App source?
- Does a second pull request or a retargeted pull request initially inherit a
  success attached to the same head commit?
- Does invalidating that one commit-scoped check block both pull requests?
- When separate approver-App credentials are supplied, does its review satisfy
  an ordinary required-approval count of one?
- Which field names appear in the App's `pull_request` and
  `installation_repositories` deliveries?

This is a destructive operator test, not ordinary CI. Run it only in a
disposable organization and App installation. It does not deploy the Extra
CODEOWNERS service, simulate a webhook signature, or prove that a particular
deployment met its invalidation or reconciliation objective.

## Prerequisites

Prepare:

- an organization reserved for disposable integration tests
- an operator token authorized to create and delete repositories, repository
  rulesets, and narrowly targeted organization rulesets
- an Extra CODEOWNERS test App installed in that organization, with Checks
  write and Contents read
- the test App ID, installation ID, and a disposable private-key file
- optionally, a separate approver App installed in the organization with Pull
  requests write, to exercise the numeric-review contract.

The operator token must have repository Administration, Contents, and Pull
requests write, plus organization Administration write. A fine-grained token
should select only the disposable organization. The fixture creates a private
repository; the organization's GitHub plan must support rulesets for private
repositories.

GitHub's REST reference defines the permission and payload contracts used by
the fixture for [organization rulesets][org-rulesets], [repository
rulesets][repository-rulesets], [installation repository selection][app-repositories],
[App-authored reviews][pull-reviews], and [App webhook deliveries][app-deliveries].
The fixture pins the `2026-03-10` API version and records it in every report.

If an App installation is limited to selected repositories, the operator
token must also be allowed to add the newly created fixture repository. That
operation should produce `installation_repositories.added`. An installation
covering all repositories may gain access automatically without producing
that action. Installation creation, suspension, permission acceptance, and
uninstallation remain manual lifecycle tests because changing them can affect
every repository in an installation.

## 1. Export credentials without putting them on the command line

Set these variables in an operator-controlled shell. The confirmation value
must include the exact organization name:

```bash
test -z "$(git status --porcelain)"
```

That command must exit successfully with no output. Commit, remove, or set
aside every tracked and untracked change before recording the revision.

```bash
export EXTRA_CODEOWNERS_LIVE_ORGANIZATION='disposable-org'
export EXTRA_CODEOWNERS_LIVE_CONFIRM='delete-disposable-repository-in:disposable-org'
export EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION="$(git rev-parse HEAD)"
export EXTRA_CODEOWNERS_LIVE_CHECKER_APP_ID='123456'
export EXTRA_CODEOWNERS_LIVE_CHECKER_INSTALLATION_ID='23456789'
export EXTRA_CODEOWNERS_LIVE_CHECKER_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/test.pem"
IFS= read -r -s -p 'Disposable-organization operator token: ' \
  EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
printf '\n'
export EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
```

Don't paste the real values into an issue, pull request, shell history,
workflow input, or report. Prefer a short-lived fine-grained operator token and
a private-key file from a secret manager. The fixture does not accept tokens or
keys as command-line arguments.

The hidden Bash prompt keeps the token text out of shell history and terminal
echo. Environment variables remain readable to sufficiently privileged local
processes. Use a trusted workstation without untrusted processes sharing the
operator account.

To test the ordinary numeric approval count, also set all three approver
variables:

```bash
export EXTRA_CODEOWNERS_LIVE_APPROVER_APP_ID='345678'
export EXTRA_CODEOWNERS_LIVE_APPROVER_INSTALLATION_ID='45678901'
export EXTRA_CODEOWNERS_LIVE_APPROVER_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/approver.pem"
```

## 2. Run the fixture

From a reviewed source checkout:

```bash
mise trust
mise install
mise run bootstrap
mise run test:github-contract
```

The command waits up to 90 seconds for each mergeability transition. It also
leaves the inherited success untouched for five seconds after opening and
retargeting the shared-head pull request. Increase that observation interval,
up to 30 seconds, only when measuring eventual behavior:

```bash
export EXTRA_CODEOWNERS_LIVE_OBSERVATION_SECONDS=15
mise run test:github-contract
```

The command exits nonzero when setup, a contract assertion, or cleanup fails.
If cleanup fails, follow the printed repository URL and delete both the named
organization ruleset and repository. To inspect live resources during tool
development, `EXTRA_CODEOWNERS_LIVE_KEEP_REPOSITORY=true` deliberately skips
cleanup; never use that setting in a routine evidence run.

A successful run prints the disposable repository URL, deletes the fixture,
writes the report, and exits with status zero. Confirm the report result and
cleanup state:

```bash
jq -e '.result == "observed" and .cleanup_succeeded == true' \
  live-github-contract-report.json
```

## 3. Review and retain the sanitized report

The default report is `live-github-contract-report.json`, which Git ignores.
It contains booleans, timestamps, the pinned API version, webhook payload key
sets, the source revision, installation-selection modes, and cleanup status. It
omits credentials, delivery IDs, signatures, raw payload values, repository
IDs, actor names, and raw responses.

Before attaching a report to an issue:

1. inspect it manually for unexpected private metadata
2. confirm `source_revision` matches the reviewed commit and record the GitHub
   plan separately
3. confirm the recorded checker and approver installation-selection modes
4. distinguish `true`, `false`, and `null`; a `null` App-review assertion means
   approver credentials were not supplied
5. keep the production warning while either shared-head inheritance assertion
   is `true` or any delivery/reconciliation interval can expose that success.

Do not reinterpret a successful run as end-to-end service evidence. The tool
directly controls the Check Run so it can isolate GitHub's repository-rule
contract. Test a deployed service separately with delayed webhook delivery,
intentional webhook loss, redelivery, and one full reconciliation interval.

## 4. Exercise delayed and lost delivery against a deployment

Run this separate test only against a disposable Extra CODEOWNERS deployment
and repository that passed the [configuration negative tests](configure.md#5-verify-with-a-test-pull-request).
You need control of the webhook ingress route and access to App delivery logs,
service metrics, and the current-head Check Run.

Prepare two protected base branches with equivalent Extra CODEOWNERS required
checks and expected App sources. GitHub won't open two pull requests with the
same head and base, so the shared head must target one base branch from each
pull request. Use fictional content and remove both branches with the fixture.

Choose a reconciliation interval long enough to observe a deliberate webhook
delay but short enough to complete the recovery test. Record the configured
interval before starting. Keep the worker and database available throughout.

For a delayed delivery:

1. Produce a successful Extra CODEOWNERS check on the first disposable pull
   request.
2. Deny only the deployment's webhook ingress route at the reverse proxy.
3. Open a second pull request with the same head commit and confirm GitHub's
   first delivery failed. Record whether the second pull request inherited the
   success before the service received an event.
4. Restore webhook ingress before the next reconciliation run.
5. In the App's **Advanced → Recent deliveries** view, redeliver the failed
   `pull_request.opened` event.
6. Confirm the service accepts the delivery, moves the shared commit's check to
   `in_progress`, and then publishes failure because two open pull requests use
   the head.

For a lost delivery, repeat the setup with a fresh shared head, but do not
redeliver the failed event. Restore ingress and wait through one full
reconciliation interval. Confirm these outcomes:

- `extra_codeowners_reconciliation_last_success_timestamp_seconds` advances
- reconciliation enqueues both open pull requests
- the inherited success becomes `in_progress` and then failure
- neither pull request is mergeable while the shared head remains
- the queue returns to its normal baseline without a dead job.

If the check does not become blocking, restore native human code-owner
enforcement before changing the fixture or debugging further. Preserve
sanitized timestamps, state transitions, aggregate metrics, and the tested
source revision. Do not retain raw deliveries or private repository metadata.

## 5. Complete lifecycle checks that cannot be safely automated

In the disposable App's settings, perform each transition separately. After
each one, inspect **Advanced → Recent deliveries** or the App webhook-delivery
API and retain only a sanitized field-shape record:

| Transition | Expected event and action |
| --- | --- |
| install the App | `installation.created` |
| resume a suspended installation | `installation.unsuspend` |
| accept newly requested permissions | `installation.new_permissions_accepted` |
| add a selected repository | `installation_repositories.added` |
| remove a selected repository | `installation_repositories.removed` |
| uninstall the App | `installation.deleted` |

Verify that the deployed service accepts the supported actions, advances its
authority fence, and reevaluates every still-accessible open pull request. An
access-removal event can arrive after the App has lost the ability to revoke a
check. Restore native human enforcement before any removal test involving a
repository whose merges matter.

## 6. Remove local credential material

After the report and cleanup checks pass, remove the token from the shell:

```bash
unset EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN
```

Revoke the short-lived operator token when the evidence run is complete. If
the checker or approver private key was created only for this fixture, revoke
that key in the App settings and securely remove its local file. Preserve the
sanitized report, tested source commit, GitHub plan, and installation-selection
mode; do not preserve credentials or raw deliveries with the evidence.

[app-deliveries]: https://docs.github.com/en/rest/apps/webhooks?apiVersion=2026-03-10
[app-repositories]: https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#add-a-repository-to-an-app-installation
[org-rulesets]: https://docs.github.com/en/rest/orgs/rules?apiVersion=2026-03-10#create-an-organization-repository-ruleset
[pull-reviews]: https://docs.github.com/en/rest/pulls/reviews?apiVersion=2026-03-10#create-a-review-for-a-pull-request
[repository-rulesets]: https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#create-a-repository-ruleset
