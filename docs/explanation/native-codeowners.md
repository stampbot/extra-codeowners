# Why Extra CODEOWNERS uses a separate check

GitHub's native code-owner rule is built around people and teams. That is the
right default, but it cannot express a narrower exception such as “Stampbot may
approve this lockfile for the platform team.” Extra CODEOWNERS adds that
exception without changing the meaning of the standard `CODEOWNERS` file.

## The gap

A GitHub App has a bot account, but that account is not a valid CODEOWNERS
identity. If a line contains an invalid owner, GitHub skips the line. Human
owners written beside the bot are not retained as a fallback.

Check a repository after every ownership change:

```bash
gh api repos/OWNER/REPOSITORY/codeowners/errors --jq '.errors'
```

An error-free file returns an empty array. GitHub also highlights problems when
you open the `CODEOWNERS` file in its web interface.

Putting `@example-app[bot]` in that file would therefore weaken ownership
rather than extend it. Extra CODEOWNERS keeps the two kinds of authority in
their own places:

```text
CODEOWNERS                         extra-codeowners.toml
people and teams                  enrolled App + delegated paths
          \                       /
           Extra CODEOWNERS evaluator
                         |
              required GitHub check
```

The evaluator starts with the standard CODEOWNERS result for every changed
path. It accepts an App review only when organization and repository policy
delegate that exact path and owner set to the App's immutable identity.

## What changes—and what does not

| Concern | GitHub's native rule | Extra CODEOWNERS |
| --- | --- | --- |
| Human ownership | Standard `CODEOWNERS` | The same standard `CODEOWNERS` |
| App identity | App bot is invalid as an owner | App ID, bot user ID, and slug are enrolled separately |
| App scope | Not expressible | Limited by repository path, effective owner, and optional labels |
| Human approval | Evaluated by GitHub | Evaluated by the Extra CODEOWNERS check |
| Mixed owner sets | Native sufficiency rules | Every distinct effective owner set represented by changed paths must be satisfied |
| Policy changes | Protected by repository rules | Built-in and organization guardrails prevent App substitution; CODEOWNERS must still assign a human owner |
| Result | GitHub's review state | A Check Run with unresolved-owner and delegation diagnostics |

The Extra CODEOWNERS result is a Check Run on the head commit. Its input,
however, belongs to one pull request: base commit, paths, labels, and reviews.
That scope mismatch is the project's main unresolved platform constraint. A
new pull request can briefly inherit a success already attached to the same
commit. Shared-head detection, a durable generation across pull requests, and
event-driven invalidation reduce the window but do not remove it before the
service accepts the relevant event.

## How repository rules compose

Minimum approval count and code-owner approval answer different questions:

- Has this pull request collected enough approvals overall?
- Did an eligible owner satisfy every owned path?

Keep the numeric approval rule for the first question. In a disposable test
repository, disable only **Require review from Code Owners** and require
`Extra CODEOWNERS / approval` from the expected App for the second.

```text
minimum approval count is satisfied
AND Extra CODEOWNERS / approval succeeds
AND every other required rule succeeds
```

An eligible App review can count toward the numeric rule in observed GitHub
integrations while also satisfying a delegated owner obligation. A human
review can satisfy both as well. GitHub's public documentation does not promise
the numeric behavior for every third-party App, so test it against the GitHub
deployment and account model you use.

Do not use this composition for production enforcement until the
[commit-scoped check blocker](../reference/project-status.md#production-enforcement-blocker)
is closed.

## Why the policy split matters

A bot login alone does not answer the security questions:

- Which GitHub App did an organization administrator enroll?
- Which paths may it approve?
- Which human owner group may it replace?
- Which labels further restrict that authority?
- Which control files must always return to a human?

Organization policy establishes the App's immutable identity and mandatory
guardrails. Repository policy opts in and grants a subset of that authority.
`CODEOWNERS` continues to carry only GitHub's standard syntax, so GitHub and
other tooling interpret it consistently.

For the native behavior, see GitHub's
[About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
and
[CODEOWNERS errors API](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors)
documentation.
