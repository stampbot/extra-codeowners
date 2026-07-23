# Why Extra CODEOWNERS uses a separate check

GitHub's code-owner rule answers a useful question: did an owner of this code
approve the change? For people and teams, that is usually enough.

Automation needs a smaller exception. “Stampbot may approve this lockfile for
the platform team” has four parts—an App, a path, an owner, and a reason—and
standard `CODEOWNERS` has nowhere to put most of them.

## Keep people in CODEOWNERS

GitHub documents code owners as users or teams with explicit write access. It
does not document GitHub App bot accounts as a supported owner type. We
therefore don't rely on a bot login in `CODEOWNERS`. The separate policy makes
that undocumented behavior irrelevant to the authorization design.

This separation also solves a bigger problem. A login by itself would not say
which organization administrator trusted the App, which paths it may approve,
or which human owner it may stand in for.

Extra CODEOWNERS keeps those decisions in two places:

```text
CODEOWNERS                         extra-codeowners.toml
people and teams                  enrolled App + delegated paths
          \                       /
           Extra CODEOWNERS evaluator
                         |
              required GitHub check
```

The evaluator begins with the effective `CODEOWNERS` result for every changed
path. It accepts an App review only when organization and repository policy
delegate that exact path and owner set to the App's immutable identity.

Continue to check ordinary CODEOWNERS errors after any ownership change:

```bash
gh api --method GET repos/OWNER/REPOSITORY/codeowners/errors \
  -f ref=BRANCH_OR_COMMIT \
  --jq '.errors'
```

Replace the repository and ref. An error-free file returns an empty array.
That command checks the exact `CODEOWNERS` version GitHub sees; it is not
evidence that an undocumented App identity works as a native code owner.

## What changes—and what does not

| Concern | GitHub's native rule | Extra CODEOWNERS |
| --- | --- | --- |
| Human ownership | Standard `CODEOWNERS` | The same standard `CODEOWNERS` |
| App identity | No documented App-bot owner contract | App ID, bot user ID, and slug enrolled separately |
| App scope | Not expressible in CODEOWNERS | Repository path, effective owner, and optional labels |
| Human approval | Evaluated by GitHub | Evaluated again by the Extra CODEOWNERS check |
| Mixed owner sets | Native sufficiency rules | Every distinct effective owner set represented by changed paths must be satisfied |
| Policy changes | Protected by repository rules | Built-in and organization guardrails reject App substitution; CODEOWNERS still assigns ownership |
| Result | GitHub's review state | A Check Run with unresolved-owner and delegation diagnostics |

The extra result is a Check Run on a commit. Its evidence belongs to one pull
request: the base commit, changed paths, labels, and reviews. That mismatch is
the project's main unresolved platform constraint.

A second pull request can briefly inherit a success already attached to the
same commit. Shared-head detection and durable invalidation reduce that window,
but they cannot act before GitHub delivers the event. This is why the project
still warns against production enforcement.

## How repository rules compose

Minimum approval count and code-owner approval answer different questions:

- Has the pull request collected enough approvals overall?
- Did an eligible owner satisfy every owned path?

Keep the numeric approval rule for the first question. In a disposable test
repository, disable only **Require review from Code Owners** and require
`Extra CODEOWNERS / approval` from the expected App for the second.

```text
minimum approval count is satisfied
AND Extra CODEOWNERS / approval succeeds
AND every other required rule succeeds
```

GitHub's public documentation does not promise that a third-party App review
satisfies the numeric approval count. Issue
[#1](https://github.com/stampbot/extra-codeowners/issues/1) tracks a live probe
for that behavior. Test it with your GitHub account and repository rules; don't
remove the numeric rule because you assume an App review will count.

Do not use this composition for production enforcement until the
[commit-scoped check blocker](../reference/project-status.md#production-enforcement-blocker)
is closed.

## Why identity needs policy

An App login still leaves the important questions unanswered:

- Which GitHub App did an organization administrator enroll?
- Which paths may it approve?
- Which human owner group may it replace?
- Which labels further restrict that authority?
- Which control files must always return to a human?

Organization policy records the App's immutable identity and mandatory
guardrails. Repository policy opts in and grants a subset of that authority.
`CODEOWNERS` continues to use GitHub's documented syntax, so GitHub and other
tools can interpret it without knowing about Extra CODEOWNERS.

For native behavior, see GitHub's
[About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
and
[CODEOWNERS errors API](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors)
documentation.
