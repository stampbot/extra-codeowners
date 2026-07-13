# Prepare repository rules

Use this guide to replace only GitHub's native code-owner approval rule with the Extra CODEOWNERS check. Keep the rest of the pull-request policy intact.

## Prerequisites

- Extra CODEOWNERS is installed for the repository.
- Organization and repository policy are configured and have passed the negative tests in the [configuration guide](configure.md#5-verify-with-a-test-pull-request).
- You can administer the repository's ruleset or branch protection.
- The App has published `Extra CODEOWNERS / approval` at least once, so GitHub can offer it as an expected check source.

## 1. Capture the current rules

Export or record the current ruleset before changing it. Identify the rule that applies to the target branch and note:

- required approving review count;
- stale-review dismissal;
- approval of the most recent push;
- native code-owner review;
- required status checks and their expected sources; and
- bypass actors.

Keep this record for rollback.

## 2. Change only the code-owner rule

In the applicable GitHub ruleset or branch protection:

1. Keep **Require a pull request before merging** enabled.
2. Keep the desired **Required approvals** count, commonly `1` or greater.
3. Keep stale-review dismissal and most-recent-push approval if they are part of your policy.
4. Disable **Require review from Code Owners**.
5. Add `Extra CODEOWNERS / approval` as a required check and select the Extra CODEOWNERS App as its expected source. Organization-level rulesets require the App installation to have Statuses write before GitHub offers it in this selector; Extra CODEOWNERS removes that capability from runtime tokens.
6. Preserve all unrelated checks, signed-commit rules, merge-queue policy, and bypass restrictions.

If the repository requires a merge queue, stop after preserving its current rules. The initial App does not subscribe to or evaluate `merge_group`, so it is not ready to replace native code-owner enforcement for a high-assurance merge queue.

GitHub App reviews have been observed to count toward the ordinary numeric approval requirement even though they do not satisfy GitHub's native code-owner rule. Treat this as an integration contract: verify it in a non-production repository and retain a live contract test because GitHub's public documentation is not explicit about third-party App approvals.

## 3. Verify the conjunction

Exercise at least these cases before applying the rules broadly:

| Pull request | Expected result |
| --- | --- |
| Delegated path, current-head application approval, all label restrictions met | Extra CODEOWNERS succeeds; ordinary review and other checks still apply. |
| Delegated path, no approving review | Extra CODEOWNERS blocks. |
| Delegated path, application approval on an older head | Extra CODEOWNERS blocks. |
| Undelegated owned path, application approval only | Extra CODEOWNERS blocks pending an appropriate human. |
| Mixed delegated and undelegated owned paths | Every owner set must be satisfied; uncovered paths remain blocked. |
| A second open pull request already uses the same head commit | Extra CODEOWNERS fails rather than publishing a pull-request-specific decision on a shared commit. |
| Owned non-delegable ownership, Extra CODEOWNERS or approving-App policy, workflow, local-action, or organization-guardrail path | Application substitution is rejected pending the appropriate human. |
| At least 3,000 returned changed files or incomplete GitHub evidence | Extra CODEOWNERS fails closed. |

Confirm the required check shows the expected App as its source. A check with the same name from another workflow or App must not satisfy the rule.

After a successful test, open or retarget another disposable pull request to the same head commit and observe the result before and after webhook handling. GitHub can initially display the prior commit-scoped success. The service invalidates it when the new event arrives, but that delay is a production-blocking limitation of the preview. Do not remove native enforcement for production repositories while this condition remains.

## Roll back safely

If evaluation is unavailable, incorrect, or being retired, first restore GitHub's native **Require review from Code Owners** rule. After that protection applies, remove the Extra CODEOWNERS check requirement. Only then set repository policy to `enabled = false` or remove it. This disables application substitution while retaining human code-owner enforcement.

Do not remove the required check without restoring an equivalent human policy first.
