# Troubleshoot a check

Use this guide when `Extra CODEOWNERS / approval` is missing, pending, or
failed on a pull request. Start with the check's own summary. It is written for
the pull-request author and repository maintainer; service operators have a
separate [recovery runbook](operate.md#investigate-a-missing-or-stale-check).

Don't publish a replacement success or weaken repository rules to clear the
symptom.

## Confirm the current head

Read the pull request's current head commit:

```bash
gh pr view NUMBER --repo OWNER/REPOSITORY --json headRefOid --jq .headRefOid
```

Replace `NUMBER`, `OWNER`, and `REPOSITORY`. Compare that SHA with the commit
shown beside the Extra CODEOWNERS check. A success on an older commit does not
apply to the current head.

List the checks GitHub associates with the pull request:

```bash
gh pr checks NUMBER --repo OWNER/REPOSITORY
```

The expected check name is `Extra CODEOWNERS / approval` unless the operator
changed it. A repository rule should also select the Extra CODEOWNERS App as
the expected source; another workflow can reuse the same text.

## If the check is missing

Extra CODEOWNERS stays silent when all three of these facts are true:

- repository policy is absent at the configured path
- the repository has no Extra CODEOWNERS check for the current head
- organization policy alone is the only configuration.

Read repository policy from the pull request's **base commit**, not from the
proposed change. The default path is `.github/extra-codeowners.toml`. It must
contain:

```toml
schema_version = 1
enabled = true
```

If policy exists and the check is still missing, ask a repository administrator
to confirm that the App can access both the target repository and the
organization policy repository. The latter is the organization's `.github`
repository by default.

The organization policy repository itself never receives an Extra CODEOWNERS
check in schema version 1. It must keep native human code-owner enforcement.

## If the check failed

Open **Details** beside the check. Match the summary to the next action.

| Summary or condition | What to do |
| --- | --- |
| A human owner is unresolved | Ask one of the listed users, or a member of a listed team, to approve the current head. |
| An App approval is missing | Confirm that the enrolled App approved the current head. A comment is not an approval. |
| An App approval is ineligible | Check the delegated path, owner, required labels, forbidden labels, and enrolled App identity. |
| The approval names an older commit | Pushes make earlier approval evidence stale. Ask the owner or App to approve the new head. |
| A path is non-delegable | An App cannot substitute on that path. Ask an eligible human CODEOWNER to approve. |
| Policy is disabled or missing after enrollment | Restore valid enabled policy, or follow the safe disablement order below. |
| Policy or CODEOWNERS is invalid | Validate both policy files and inspect GitHub's CODEOWNERS errors. |
| Several open pull requests share the head | Give each pull request a distinct commit, then wait for reevaluation. |
| The changed-file limit was reached | Split or reduce the pull request. Extra CODEOWNERS will not authorize a truncated file list. |

Labels change whether an App delegation is eligible. Adding a label never
counts as approval. An eligible human approval can still satisfy an owner set
when an App delegation's label conditions do not match.

An approving App already has permission to change pull-request labels, so
label conditions are not an independent defense against that App being
compromised. Investigate the App and rotate its credentials; do not try to
contain the incident with labels.

### Validate policy

From a reviewed Extra CODEOWNERS checkout with dependencies installed, run:

```bash
mise exec -- uv run python -m extra_codeowners validate-policy \
  --repository /path/to/repository-policy.toml \
  --organization /path/to/organization-policy.toml
```

Success prints:

```text
Policy files are valid.
```

The command checks TOML, field constraints, path patterns, App aliases, and
cross-file enrollment. Live evaluation also checks repository access, current
labels, App identity, CODEOWNERS, and reviews.

Check GitHub's view of the standard file separately:

```bash
BASE_SHA="$(
  gh pr view NUMBER --repo OWNER/REPOSITORY \
    --json baseRefOid --jq .baseRefOid
)"
gh api --method GET repos/OWNER/REPOSITORY/codeowners/errors \
  -f ref="$BASE_SHA" \
  --jq '.errors'
```

Replace the pull-request number and repository. An error-free file at that
exact base commit prints `[]`.

## If the check stays pending

An `in_progress` result blocks merging while Extra CODEOWNERS invalidates stale
evidence, reevaluates the pull request, fans out an authority change, or waits
for GitHub or the database to recover.

Wait through the deployment's normal evaluation interval. If the result lasts
longer than that interval, give the operator:

- repository and pull-request number
- exact head SHA
- check name and current status
- sanitized check summary
- GitHub webhook delivery ID, if an administrator can see it
- the time of the last relevant push, review, or label change in UTC.

Do not include a private key, webhook secret, installation token,
authorization header, complete webhook payload, private repository contents,
or a database URL.

The operator should continue with
[Investigate a missing or stale check](operate.md#investigate-a-missing-or-stale-check).
A long-lived pending check needs service recovery, not a manufactured result.

## Test a correction

After changing policy, labels, or review state, confirm all of these facts on
the exact current head:

1. The expected Extra CODEOWNERS App published the check.
2. The check summary names the paths and owners you expected.
3. Every approval shown as satisfying policy belongs to the current head.
4. The repository's ordinary approval count and other required checks still
   pass independently.

Run a negative case before expanding App authority. Remove a required label,
dismiss the App review, or change an undelegated path. The check must stop
succeeding. If it does not, restore native code-owner enforcement and stop the
rollout.

## Disable the check without leaving a gap

If a repository must stop using Extra CODEOWNERS:

1. Restore GitHub's native **Require review from Code Owners** rule.
2. Wait until GitHub shows that rule as active.
3. Remove the required Extra CODEOWNERS check.
4. Disable or remove repository policy.
5. Remove App access only after the native rule is working.

The order matters. Once the App loses repository access, it may be unable to
replace an earlier success with a blocking result.
