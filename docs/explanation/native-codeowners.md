# How Extra CODEOWNERS differs from native CODEOWNERS

Extra CODEOWNERS does not replace the standard `CODEOWNERS` file or extend its syntax. It replaces one repository-rule decision: whether code-owner policy has been satisfied.

## The gap

GitHub's native **Require review from Code Owners** setting is designed around users and teams named in `CODEOWNERS`. GitHub [documents that a line containing invalid CODEOWNERS syntax is skipped](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-syntax), and its [CODEOWNERS errors endpoint](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors) reports a mixed line containing an App bot account as `Invalid owner`. Taken together, an entry such as `@example-app[bot]` makes the affected line unusable; do not assume human owners on the same line are partially salvaged.

Check a repository after every ownership change:

```bash
gh api repos/OWNER/REPOSITORY/codeowners/errors --jq '.errors'
```

An empty array is the expected result. GitHub also highlights errors while viewing the CODEOWNERS file in the web interface.

That limitation is useful for most repositories, but it prevents narrowly trusted review automation from satisfying code-owner policy even when another system has already constrained what that automation may approve.

Extra CODEOWNERS keeps human ownership in `CODEOWNERS` and places application authority in a separate, explicit policy:

```text
CODEOWNERS                         extra-codeowners.toml
human ownership                   trusted App identity + delegated paths
          \                       /
           Extra CODEOWNERS evaluator
                         |
             required GitHub check
```

Text equivalent: the evaluator combines human ownership from `CODEOWNERS` with application identity and path delegation from Extra CODEOWNERS policy, then publishes one required check.

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

Extra CODEOWNERS is not an alternative to an ordinary pull-request approval count. Keep that numeric requirement enabled. Disable only native **Require review from Code Owners**, then require the expected-source `Extra CODEOWNERS / approval` check.

The result is:

```text
minimum approval count >= repository policy
AND Extra CODEOWNERS / approval == success
AND every other required check == success
```

A delegated application's approving review may satisfy the ordinary numeric review count and the Extra CODEOWNERS check for its eligible paths. A human can satisfy both as well. This integration behavior must be contract-tested in each GitHub deployment because GitHub's public documentation does not explicitly guarantee how every third-party App review interacts with numeric review rules.

The required check is attached to a head commit, not uniquely to one pull request. Extra CODEOWNERS checks for other open pull requests using the head before publishing success, but it cannot prevent a later pull request from briefly displaying that existing success before its opening or retargeting event is processed. This is a material preview limitation rather than native-equivalent enforcement.

## Why separate policy is safer

An App name in `CODEOWNERS` would not describe which automation is trusted, how its immutable identity is verified, or which labels constrain it. Separate organization and repository policy provides those controls without inventing syntax that GitHub itself would misinterpret.

For native behavior, see GitHub's [About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) and [List CODEOWNERS errors](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors) documentation.
