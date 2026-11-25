# Prepare repository rules

Test Extra CODEOWNERS as an alternative to native code-owner review in a
disposable repository. Keep the ordinary approval count, stale-review rules,
signed commits, merge restrictions, and other required checks in place.

!!! warning
    Use this procedure only in a disposable repository for now. A GitHub Check
    Run belongs to a commit, not one pull request, so another pull request can
    briefly inherit an earlier success for the same head. For enforcement,
    1.0 requires a separate check on the queue's candidate commit.

## Before you begin

- Install Extra CODEOWNERS on the test repository.
- Configure both policy scopes and pass every negative test in the
  [configuration guide](configure.md#5-test-the-boundary).
- Obtain permission to administer the applicable ruleset or branch protection.
- Let the App publish `Extra CODEOWNERS / approval` at least once so GitHub can
  offer the App as the check's expected source.

If the repository uses a merge queue, or you plan to enforce policy in
production, use the [one-at-a-time queue procedure](test-merge-queue.md)
instead. Keep native code-owner review active if the repository can't use
that setup or you're running a prerelease.

## 1. Record the current protection

Export the ruleset or otherwise capture the complete rule for the target
branch. At minimum, record:

- required approval count
- stale-review dismissal
- approval of the most recent push
- native code-owner review
- every required check and its expected source
- bypass actors
- merge-queue, signed-commit, and branch-update requirements.

Keep the record with the test plan. It is your rollback baseline.

## 2. Replace only native code-owner review

In the applicable ruleset or branch-protection rule:

1. Keep **Require a pull request before merging** enabled.
2. Keep the desired **Required approvals** count, including `1` or more.
3. Keep stale-review dismissal and latest-push approval rules.
4. Require `Extra CODEOWNERS / approval`, selecting the Extra CODEOWNERS App as
   its expected source.
5. Verify that GitHub applies the App requirement to the test branch. Only
   then disable **Require review from Code Owners** on that branch.
6. Verify that every unrelated check, bypass restriction, and merge rule
   still applies.

GitHub's public documentation does not promise that a third-party App review
counts toward the ordinary numeric approval rule. Verify that behavior in this
disposable repository. Extra CODEOWNERS neither requires nor recommends
removing the numeric count.

Organization-level rulesets require Commit statuses (`statuses`) write on the
App registration before GitHub offers the App in the expected-source selector.
Runtime installation tokens omit that permission and cannot write commit
statuses.

The resulting merge policy is:

```text
ordinary approval count is satisfied
AND Extra CODEOWNERS / approval succeeds from the expected App
AND every other required rule succeeds
```

## 3. Exercise the complete rule

Run each case before expanding the experiment:

| Pull request | Expected Extra CODEOWNERS result |
| --- | --- |
| Delegated path, current-head App approval, label restrictions met | Success; ordinary approval count and other checks still apply. |
| Delegated path with no approval | Blocking. |
| Delegated path with an App approval on an older head | Blocking. |
| Undelegated owned path with only an App approval | Blocking until an eligible human approves. |
| Mixed delegated and undelegated owned paths | Blocking until every effective owner set is satisfied. |
| A second open pull request already uses the same head | Blocking rather than publishing a pull-request-specific decision on a shared commit. |
| Owned non-delegable path, including ownership policy, approving-App controls, workflows, local actions, or organization guardrails | Blocking until an eligible human approves. |
| GitHub reports the 3,000-file API maximum | Diagnostic failure because the service cannot prove that the file list is complete. |
| GitHub or database evidence is unavailable | Blocking while durable work retries. |

Confirm that the required rule names the Extra CODEOWNERS App as its expected
source. A workflow or another App can publish the same check name; a name-only
rule would accept the wrong publisher.

After an ordinary success, open or retarget another disposable pull request to
the same head. Observe the inherited result before and after webhook handling.
That inherited result is why the current check cannot protect production
merges.

The [live GitHub contract fixture](run-live-github-contract.md) makes the Check
Run transition, source selection, shared-head, retargeting, App-review, and
webhook-payload field checks repeatable. It does not simulate delayed or missed
delivery to the deployed service, so keep those failure tests in the operator
plan too.

## Roll back without leaving a gap

Use this order if evaluation is unavailable, wrong, or being retired:

1. Restore GitHub's native **Require review from Code Owners** rule.
2. Wait until GitHub shows that protection as active. Use a test PR whose
   author doesn't own the changed path. Confirm GitHub reports a missing
   code-owner review even though the App check and ordinary approval count
   are already satisfied.
3. Remove the `Extra CODEOWNERS / approval` requirement.
4. Disable or remove repository policy.
5. Only then remove the repository from the App installation or suspend the
   App.

Restoring human enforcement first prevents a period in which neither system
protects code-owner obligations. It also gives Extra CODEOWNERS a chance to
revoke its own managed result while it still has repository access.
The [suspension test](../maintainers/evidence/2026-11-19-installation-suspend-resume.md)
observed that an old passing check remained visible after GitHub blocked App
access. For an installation-wide change, follow the
[operator handback steps](operate.md#suspend-or-uninstall-an-installation).
