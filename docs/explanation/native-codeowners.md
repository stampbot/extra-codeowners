# How Extra CODEOWNERS differs from native CODEOWNERS

Extra CODEOWNERS leaves the standard `CODEOWNERS` file alone. It neither
replaces that file nor invents new syntax for it. Instead, it answers one
repository-rule question differently: has each applicable owner set approved
this pull request?

## The gap

GitHub's native **Require review from Code Owners** setting speaks in users and
teams. A GitHub App's bot account does not fit that model. GitHub
[skips a line with invalid CODEOWNERS syntax](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-syntax),
and the
[CODEOWNERS errors endpoint](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors)
reports an App bot on a mixed line as `Invalid owner`. Put
`@example-app[bot]` on a line and the whole line is unusable. The human owners
beside it are not a fallback.

Check a repository after every ownership change:

```bash
gh api repos/OWNER/REPOSITORY/codeowners/errors --jq '.errors'
```

The expected result is an empty array. GitHub also highlights errors when you
view the CODEOWNERS file in its web interface.

For most repositories, refusing bot owners is a sound default. The gap appears
when an organization has already decided to trust an App within a narrow scope.
GitHub still cannot express “Stampbot may approve these dependency files, but
nothing else.”

Extra CODEOWNERS separates the two kinds of authority. Humans stay in
`CODEOWNERS`; an App's immutable identity and delegated paths live in explicit
Extra CODEOWNERS policy.

```text
CODEOWNERS                         extra-codeowners.toml
human ownership                   trusted App identity + delegated paths
          \                       /
           Extra CODEOWNERS evaluator
                         |
             required GitHub check
```

In prose, the evaluator starts with human ownership from `CODEOWNERS`. It adds
only the App identities and paths that policy delegates, then publishes one
required check.

## Behavior comparison

| Concern | GitHub native code-owner review | Extra CODEOWNERS |
| --- | --- | --- |
| Human ownership source | Standard `CODEOWNERS` | The same standard `CODEOWNERS` |
| Application identities in `CODEOWNERS` | Reported as an invalid owner; the affected line is skipped | Not added to `CODEOWNERS`; enrolled separately by immutable App and bot IDs |
| Application path scope | Not available | Explicit repository delegation, optionally limited by owner and labels |
| Human approval | Native code-owner rule | Evaluated by the required check |
| Result scope | Pull-request ownership state | A commit-scoped Check Run calculated from pull-request evidence; a newly opened or retargeted pull request can briefly inherit an earlier result for the same head |
| Mixed owner groups | GitHub's native rule determines sufficiency | Every distinct effective owner set represented by changed paths must be satisfied |
| Policy changes | Governed by repository rules | Built-in non-delegable paths reject application substitution; standard CODEOWNERS must assign the human owner |
| Failure diagnostics | GitHub review status | Check summary explains unresolved owner sets and delegation conditions |

## Repository-rule composition

There are two different questions here. Has the pull request collected enough
approvals overall? And has each code-owner obligation been satisfied? Keep the
ordinary numeric approval requirement for the first question. For the second,
disable only native **Require review from Code Owners** and require the
expected-source `Extra CODEOWNERS / approval` check.

The result is:

```text
minimum approval count >= repository policy
AND Extra CODEOWNERS / approval == success
AND every other required check == success
```

A delegated App's approving review may count toward the numeric rule and
satisfy Extra CODEOWNERS for eligible paths. A human approval may satisfy both
rules too. Test that composition against each GitHub deployment before relying
on it. GitHub's public documentation does not promise how every third-party App
review interacts with the numeric approval rule.

GitHub attaches the required check to a head commit, not uniquely to a pull
request. Before publishing success, Extra CODEOWNERS looks for another open pull
request that uses the same head. It cannot see the future: a pull request opened
or retargeted afterward can briefly display the existing success until its
event is processed. This unresolved platform mismatch blocks
production-equivalent enforcement.

## Why separate policy is safer

A bot login looks like an owner, but it says too little. It does not tell the
evaluator which immutable App identity the organization enrolled, where that
App may act, or which labels narrow its authority.

Separate policy makes that trust visible. Organization policy enrolls the App;
repository policy delegates a subset of the organization's grant. Standard
`CODEOWNERS` continues to mean what GitHub says it means, with no private syntax
for GitHub to reject or another tool to misunderstand.

For native behavior, see GitHub's [About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) and [List CODEOWNERS errors](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors) documentation.
