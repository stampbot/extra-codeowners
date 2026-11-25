# Configure a one-at-a-time merge queue

Use a required merge queue when Extra CODEOWNERS replaces native code-owner
review. Several PRs can wait in the queue. GitHub builds one candidate at a
time, and the App evaluates the PR at the front against that candidate.
The next PR needs its own result.

!!! warning
    Use an alpha only for a disposable queue test. The production procedure
    requires a supported 1.0 or later release. If your repository can't use
    the settings below, keep native code-owner review on and leave Extra
    CODEOWNERS advisory. See the [support limits][support].

## Before you begin

- Start in a disposable GitHub.com repository eligible for
  [GitHub Merge Queue][github-queue]. Use an App registration you can change.
  Limit that installation to the test repository and its organization-policy
  repository. Each deployment can opt in one repository for candidate checks.
- For a disposable test, use a release that includes candidate rechecks,
  starting with [alpha.115][alpha]. Follow the [upgrade guide](upgrade.md)
  if you have an existing database. Keep a valid `CODEOWNERS` file and an
  eligible human owner for the path you'll test.
- Arrange access to the App's settings and delivery log and to the rulesets
  that apply to the test branch. Record those rules before editing them,
  including organization rules, bypass actors, and other required checks.

## 1. Turn on candidate checks

Add **Merge queues: Read-only** to the App's repository permissions.
Subscribe to the [`merge_group` event][merge-group-event], and have the
installation owner accept the updated permissions. The default App Manifest
doesn't request either setting.

Set `EXTRA_CODEOWNERS_EXPERIMENTAL_MERGE_QUEUE_REPOSITORY` and
`EXTRA_CODEOWNERS_EXPERIMENTAL_MERGE_QUEUE_REPOSITORY_ID` on every receiver
and worker replica. Use `owner/repository` and that repository's numeric
GitHub ID. The `EXPERIMENTAL` names are unchanged for compatibility. Leave
the [recheck interval][settings] at its default unless you've measured a
different interval in your deployment. For Helm, set both variables in
`extraEnv` as string values. The database migration Job doesn't need them.

Verify service readiness and run the normal
[policy tests](configure.md#5-test-the-boundary) before changing any rule.
Record the configured check name and the numeric ID of the App that posts it.
The App doesn't need permission to submit reviews or merge.

## 2. Set and verify the queue rules

Use a repository ruleset for the target branch. Keep the ordinary pull-request
requirement and its approving-review count. For the disposable test, require
at least one ordinary approval. Leave existing checks and restrictions in
place. Every required CI check must report on GitHub's candidate commit, not
only the PR head. For GitHub Actions, add the `merge_group` trigger.

Require the queue and the Extra CODEOWNERS check from the installed App.
Set the queue to squash merging, one build slot, a minimum and maximum of
one PR per merge, and **Only merge non-failing pull requests**. Allow no
bypass actors. Set the status check timeout long enough for candidate checks
to finish. Verify the App as the expected source before you disable
native code-owner review on the disposable branch. If the rules span multiple
settings, keep native review active until the queue and App check are
confirmed. Don't change the review count.

To inspect active rules, run this read-only command in Bash from any
directory with `gh` and `jq` installed. Authenticate `gh` to GitHub.com
as a user who can read the repository. Replace the example `REPOSITORY`
and `TARGET_BRANCH` with your repository and branch:

```bash
REPOSITORY=example-org/disposable-repo
TARGET_BRANCH=test-queue
branch_path=$(jq -nr --arg branch "$TARGET_BRANCH" '$branch | @uri')
gh api --paginate --slurp \
  "repos/$REPOSITORY/rules/branches/$branch_path?per_page=100" |
  jq 'add | map(select(.type == "merge_queue" or .type == "pull_request"
    or .type == "required_status_checks")
    | {ruleset_id, type, parameters})'
```

Expect one active `merge_queue` rule with `SQUASH`, `ALLGREEN`, and
`max_entries_to_build`, `min_entries_to_merge`, and
`max_entries_to_merge` all set to `1`. Verify that the required status check
has your configured name and the App's ID as `integration_id`, not a
name-only or any-source requirement. Check the ordinary approval count
against the recorded baseline. Review the rulesets themselves for bypass
actors, which the [effective-rules response][github-rules] doesn't expose.
Stop if a rule is missing, unreadable, or doesn't match the test plan.

## 3. Prove the gate works

Run these tests in the disposable repository with synthetic changes and no
bypass. Add a separate required fixture check to hold a candidate for
negative or timing tests. Pass that check on the PR head only; it must stay
absent from the held candidate. Don't add the fixture check to production.

1. With no ordinary approval, confirm that a green PR-head check doesn't let
   the PR enter GitHub's queue. On an approved PR, read a real App delivery
   and verify that GitHub built a candidate commit distinct from the PR head.
2. Without a candidate result from the expected App, verify that GitHub
   waits. The App doesn't discover a candidate if its first event is lost.
   GitHub waits until its queue timeout, unless you redeliver the matching
   event or requeue. Don't copy an earlier result to a new candidate.
3. Let the worker confirm a pass while the fixture check holds the candidate.
   A timer recheck should leave the same Check Run green if the review is
   still valid. Dismiss the eligible review and confirm that the worker
   changes that Check Run to failure and that the branch doesn't move.
4. While the first candidate is held, queue a second eligible PR. Verify
   that it waits without a candidate. After the first entry leaves the queue,
   verify that GitHub creates a different candidate and requires a result
   for that commit. The first result can't satisfy it.
5. With a fresh eligible PR, verify that GitHub can merge once the ordinary
   review count, candidate check, and every other rule are satisfied.

Don't treat a response from the webhook receiver or a green check on the PR
head as proof of a passing candidate. Record the head and candidate commit
separately. If any expected rejection instead merges, stop the experiment
and restore native review.

## 4. Switch a protected branch to candidate checks

Do not use a prerelease for this step. After the disposable tests pass,
deploy the supported release and configure the production repository using
steps 1 and 2. Record its rules before changing them and keep native review
on. Confirm a human-approved PR gets a candidate result from the expected
App and that the other required checks report on that candidate. If GitHub
doesn't enforce the queue and App requirement or you can't verify the result,
stop and leave native review in place.

When the queue and required check are active, disable only **Require review
from Code Owners**. Read back the rules to confirm the review count, queue,
and other protections stayed in place. If a candidate check is missing, use
the delivery log to redeliver the matching event or requeue the PR. Don't
copy a check from the old candidate or bypass the queue.

## Return to native review

Stop adding PRs to the queue. Remove queued entries and verify the
queue is empty before changing protections. If a merge is already in
progress, don't assume that a rule change can cancel it.

1. Verify that the target still has a valid `CODEOWNERS` file with eligible
   human owners. Restore GitHub's native **Require review from Code Owners**
   rule and the original approval count. Preserve unrelated checks and
   restrictions.
2. Verify that GitHub lists the restored rule on the target. Use a test PR
   whose author isn't a code owner of the changed path. Give it a green App
   check and enough ordinary approvals, but no review from an eligible code
   owner. Confirm GitHub reports the missing code-owner review. Neither a
   successful queue admission nor a PR blocked by an unrelated check proves
   the restored rule works. Don't proceed if you can't confirm it.
3. Remove the required Extra CODEOWNERS check and restore the recorded
   queue configuration. Leave unrelated protections alone. Clear the two
   candidate repository settings on every replica if the App will no
   longer check that repository's queue.
4. Only then remove repository access, suspend the installation, or remove
   test-only permissions and subscriptions.

Clearing the settings or taking away access doesn't erase checks GitHub already recorded. In the [native-review handback test](../maintainers/evidence/2026-11-23-native-review-restored-with-queue.md), GitHub refused to queue a PR without code-owner review. The App check still passed, and Stampbot's approval was still on the PR.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.115
[github-queue]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue
[github-rules]: https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch
[merge-group-event]: https://docs.github.com/en/webhooks/webhook-events-and-payloads#merge_group
[settings]: ../reference/configuration.md#policy-and-security-settings
[support]: ../reference/project-status.md#production-enforcement-blocker
