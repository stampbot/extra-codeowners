# Test the experimental merge queue

Use this procedure to check a merge queue in one disposable GitHub.com
repository. Keep GitHub's native code-owner review on in production. The
worker is experimental; a passing test doesn't change the
[production support boundary](../reference/project-status.md#production-enforcement-blocker).

## Before you begin

- Use an App registration and an installation you can change for the test.
  Limit the installation to the test repository and its organization-policy
  repository. The repository must be eligible for
  [GitHub Merge Queue][github-queue].
- Use a release that includes candidate rechecks, starting with
  [alpha.115][alpha]. Follow the [upgrade guide](upgrade.md) if you have an
  existing database. Work on a branch with a valid `CODEOWNERS` file and
  at least one eligible human owner for the path you'll test.
- Arrange access to the App's settings and delivery log and to the rulesets
  that apply to the test branch. Record those rules before editing them,
  including organization rules, bypass actors, and other required checks.

## 1. Turn on the worker for the fixture

Add **Merge queues: Read-only** to the test App's repository permissions.
Subscribe to the [`merge_group` event][merge-group-event], and have the
installation owner accept the updated permissions. The default App Manifest
doesn't request either setting.

Set the [experimental repository route and ID][settings] to the same
test repository on every receiver and worker replica. Leave all other
repositories out of the experiment. Keep the recheck interval at its
default unless you're measuring it separately.

Verify service readiness and run the normal
[policy tests](configure.md#5-test-the-boundary) before changing any rule.
Record the configured check name and the numeric ID of the App that posts it.
The App doesn't need permission to submit reviews or merge.

## 2. Set and verify the queue rules

On the disposable target branch, keep the ordinary pull-request requirement
and its approving-review count. For the test, require at least one ordinary
approval. Leave existing checks and restrictions in place. If another check
is required, make sure it also runs on GitHub's candidate commit.

Require the queue and the Extra CODEOWNERS check from the installed App.
Set the queue to squash merging, one build slot, a minimum and maximum of
one PR per merge, and **Only merge non-failing pull requests**. Allow no
bypass actors. Verify the App as the expected source before you disable
native code-owner review on the test branch. If the rules span multiple
settings, keep native review active until the queue and App check are
confirmed. Don't change the review count.

To inspect active rules, run this read-only command in Bash from any
directory with `gh` and `jq` installed. Authenticate `gh` to GitHub.com
as a user who can read the test repository. Replace the example
`FIXTURE_REPOSITORY` and `TARGET_BRANCH` with your repository and branch:

```bash
FIXTURE_REPOSITORY=example-org/disposable-repo
TARGET_BRANCH=test-queue
branch_path=$(jq -nr --arg branch "$TARGET_BRANCH" '$branch | @uri')
gh api --paginate --slurp \
  "repos/$FIXTURE_REPOSITORY/rules/branches/$branch_path?per_page=100" |
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

Run the tests with synthetic changes and no bypass. Add a separate required
fixture check to hold a candidate for negative or timing tests. Pass that
check on the PR head only; it must stay absent from the held candidate.

1. With no ordinary approval, confirm that a green PR-head check doesn't let
   the PR enter GitHub's queue. On an approved PR, read a real App delivery
   and verify that GitHub built a candidate commit distinct from the PR head.
2. Without a candidate result from the expected App, verify that GitHub
   waits. Losing the first candidate delivery doesn't start a timer: GitHub
   waits until the check expires, or until you redeliver the matching event
   or requeue. Don't copy an earlier result to a new candidate.
3. Let the worker confirm a pass while the fixture check holds the candidate.
   A timer recheck should leave the same Check Run green if the review is
   still valid. Dismiss the eligible review and confirm that the worker
   changes that Check Run to failure and that the branch doesn't move.
4. With a fresh eligible PR, verify that GitHub can merge once the ordinary
   review count, candidate check, and every other rule are satisfied.

Don't treat a response from the webhook receiver or a green check on the PR
head as proof of a passing candidate. Record the head and candidate commit
separately. If any expected rejection instead merges, stop the experiment
and restore native review.

## Return to native review

Stop adding test PRs to the queue. Remove queued entries and verify the
queue is empty before changing protections. If a merge is already in
progress, don't assume that a rule change can cancel it.

1. Verify that the target still has a valid `CODEOWNERS` file with eligible
   human owners. Restore GitHub's native **Require review from Code Owners**
   rule and the original approval count. Preserve unrelated checks and
   restrictions.
2. Verify that GitHub lists the restored rule on the target. Use a test PR
   with a green App check and enough ordinary approvals, but no review from
   an eligible code owner. Confirm GitHub reports the missing code-owner
   review. A PR blocked only by a queued check or the ordinary review count
   isn't evidence that native review works. Don't proceed if you can't
   confirm the native rule.
3. Remove the fixture's required App check and any queue rule added for
   the experiment. Return the rest of the rules to the captured baseline.
   Clear both experimental repository settings on every replica.
4. Only then remove repository access, suspend the installation, or remove
   test-only permissions and subscriptions.

Clearing the settings or taking away access doesn't erase checks GitHub
already recorded. The [handback evidence](../maintainers/evidence/2026-11-23-candidate-checks-during-delivery-loss.md#hand-back-enforcement-before-removing-access)
shows GitHub blocking a PR after native review was restored while its old
App result was still passing.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.115
[github-queue]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue
[github-rules]: https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch
[merge-group-event]: https://docs.github.com/en/webhooks/webhook-events-and-payloads#merge_group
[settings]: ../reference/configuration.md#policy-and-security-settings
