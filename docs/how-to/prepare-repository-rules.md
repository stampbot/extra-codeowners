# Prepare repository rules

Replace only GitHub's native code-owner approval rule with the Extra CODEOWNERS check. Keep every other pull-request rule intact.

## Prerequisites

- Install Extra CODEOWNERS for the repository.
- Configure organization and repository policy, then pass the negative tests in the [configuration guide](configure.md#5-verify-with-a-test-pull-request).
- Obtain permission to administer the repository's ruleset or branch protection.
- Have the App publish `Extra CODEOWNERS / approval` at least once, so GitHub can offer it as an expected check source.

## 1. Capture the current rules

Before changing a rule, export or record the current ruleset. Identify the rule for the target branch and record:

- the required approving review count
- stale-review dismissal
- approval of the most recent push
- native code-owner review
- required status checks and their expected sources
- bypass actors.

Keep this record for rollback.

## 2. Change only the code-owner rule

!!! warning
    Don't replace native code-owner enforcement on a production repository yet. GitHub can initially show a previous pull request's success when another pull request uses the same head commit. Extra CODEOWNERS invalidates that commit-scoped success after the new event arrives, but the delay remains a production blocker.

If the repository requires a merge queue, stop and preserve its current rules. The initial App neither subscribes to nor evaluates `merge_group`, so it can't replace native code-owner enforcement for a high-assurance merge queue.

In the applicable GitHub ruleset or branch protection:

1. Keep **Require a pull request before merging** enabled.
2. Keep the desired **Required approvals** count, commonly `1` or greater.
3. Keep stale-review dismissal and most-recent-push approval if your policy uses them.
4. Disable **Require review from Code Owners**.
5. Add `Extra CODEOWNERS / approval` as a required check and select the Extra CODEOWNERS App as its expected source. For organization-level rulesets, the App installation needs Statuses write before GitHub offers it in this selector. Extra CODEOWNERS removes that capability from runtime tokens.
6. Preserve unrelated checks, signed-commit rules, merge-queue policy, and bypass restrictions.

GitHub App reviews have counted toward the ordinary numeric approval requirement in observed integrations, even though they don't satisfy GitHub's native code-owner rule. GitHub's public documentation isn't explicit about third-party App approvals. Verify this behavior in a non-production repository and keep a live contract test.

## 3. Verify the conjunction

Exercise every case before applying the rules more broadly:

| Pull request | Expected result |
| --- | --- |
| Delegated path, current-head application approval, all label restrictions met | Extra CODEOWNERS succeeds; ordinary review and other checks still apply. |
| Delegated path, no approving review | Extra CODEOWNERS blocks. |
| Delegated path, application approval on an older head | Extra CODEOWNERS blocks. |
| Undelegated owned path, application approval only | Extra CODEOWNERS blocks pending an appropriate human. |
| Mixed delegated and undelegated owned paths | Every owner set must be satisfied; uncovered paths remain blocked. |
| A second open pull request already uses the same head commit | Extra CODEOWNERS fails rather than publishing a pull-request-specific decision on a shared commit. |
| Owned non-delegable path, such as an ownership file, Extra CODEOWNERS or approving-App policy, workflow, local action, or organization guardrail | Application substitution is rejected pending the appropriate human. |
| GitHub returns 3,000 changed files | Extra CODEOWNERS publishes a diagnostic failure because it cannot prove the list is complete. |
| GitHub or database evidence is temporarily unavailable | The check stays blocking and the job retries. |

Confirm that the required check names the expected App as its source. A workflow or another App can publish the same check name, but it must not satisfy the rule.

After a successful test, open or retarget another disposable pull request to the same head commit. Observe the result before and after webhook handling. GitHub can initially display the prior commit-scoped success; the service invalidates it when the new event arrives.

## Roll back safely

If evaluation is unavailable, incorrect, or being retired, restore GitHub's native **Require review from Code Owners** rule first. Wait until that protection applies, then remove the Extra CODEOWNERS check requirement. Only after both steps should you set repository policy to `enabled = false` or remove it.

Don't remove the required check before restoring equivalent human enforcement.
