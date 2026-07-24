# Why use an extra check?

A routine dependency update exposes the gap.

Suppose `@example-org/platform` owns `/uv.lock`.
[Stampbot](https://github.com/dannysauer/stampbot) recognizes an allowed
dependency pull request and approves its current head. The change has the
review your automation policy asked for, but GitHub's native **Require review
from Code Owners** rule still waits for a person.

## Keep people in CODEOWNERS

You could try adding the App's bot login to `CODEOWNERS`. Extra CODEOWNERS
deliberately doesn't depend on that approach. GitHub documents code owners as
users or teams with explicit write access; it doesn't document a GitHub App bot
account as a supported owner type.

The extra check leaves human ownership where GitHub expects it and records App
authority somewhere that can express the missing limits.

## The decision in one pull request

For each changed path, Extra CODEOWNERS applies the last matching `CODEOWNERS`
rule and groups paths by their effective owner set. It then looks for one of
two kinds of evidence:

```text
Appropriate human approved the exact current head
                            \
                             -> owner set is satisfied
                            /
Enrolled App approved the exact current head
and a delegation covers the path and owner
```

Every distinct owner set represented by the pull request must be satisfied. In
the implemented evaluator contract, a human can cover an ordinary application
change while an enrolled App covers a delegated lockfile in the same pull
request. The project has not yet recorded a dated live GitHub run of the
App-review and required-check behavior.

The result is a Check Run named `Extra CODEOWNERS / approval`. The service
doesn't submit a review, change branch protection, merge the pull request, or
grant an App access.

## Why the App policy is separate

A bot login alone doesn't answer the questions that matter:

- Which GitHub App did an organization administrator enroll?
- Which paths may that App cover in this repository?
- Which human owner may it stand in for?
- Which labels narrow the delegation?
- Which paths reject App substitution altogether?

Extra CODEOWNERS answers them in two policy scopes.

Organization policy enrolls the App by App ID, bot user ID, and slug. It also
adds organization guardrails: path patterns where no enrolled App may replace
a human approval.

Repository policy opts one repository in and delegates a smaller set of paths
and effective owners. It may add required or forbidden labels. It can't enroll
a new App or remove an organization guardrail.

```text
CODEOWNERS: people and teams --------+
Organization policy: App + guards ---+-> evaluator -> required check
Repository policy: delegation -------+
```

This split means `/uv.lock` can be delegated to Stampbot for the platform team
without making Stampbot a general replacement for that team.

## What “human-only” means

Extra CODEOWNERS calls a path non-delegable when an App approval may not
satisfy its code-owner requirement. That rule controls approval evidence, not
the file's contents.

A workflow may invoke an App. Repository policy may list an enrolled App.
`CODEOWNERS` continues to list its human users and teams. But when a pull
request changes one of those protected files, an enrolled App can't stand in
for the effective human owner.

The built-in non-delegable set covers standard `CODEOWNERS` locations, the
effective repository policy, Stampbot's root policy, GitHub workflows, and
local actions. Organization policy should add the approving App's other
control files and any transitive decision code. The
[configuration reference](../reference/configuration.md#built-in-non-delegable-paths)
lists the exact patterns and explains the process-wide insecure escape hatch.

These patterns don't assign ownership. Your normal `CODEOWNERS` file must give
them an effective human owner if you want a human approval requirement.

## What changes in repository rules

Native code-owner review and ordinary approval count answer different
questions:

- Did the pull request collect enough approvals overall?
- Did an eligible owner satisfy each owned path?

Keep GitHub's numeric approval rule for the first question. In a disposable
test repository, disable only **Require review from Code Owners** and require
`Extra CODEOWNERS / approval` from the expected Extra CODEOWNERS App for the
second.

```text
ordinary approval count is satisfied
AND Extra CODEOWNERS / approval succeeds from the expected App
AND every other required rule succeeds
```

Extra CODEOWNERS doesn't alter GitHub's numeric count. GitHub's public
documentation also doesn't promise that a third-party App review satisfies
that count.
[Issue #1](https://github.com/stampbot/extra-codeowners/issues/1) tracks a
dated live probe, so test that behavior in your disposable repository and keep
the numeric rule.

The [repository-rules guide](../how-to/prepare-repository-rules.md) gives the
complete test and rollback procedure.

## The unresolved commit boundary

The check's evidence belongs to a pull request: its base, changed paths,
labels, and reviews. GitHub attaches the resulting Check Run to a commit.

If another pull request opens or retargets to the same head, it can briefly
display the earlier success before GitHub delivers the event that lets Extra
CODEOWNERS revoke and recompute the result. Shared-head detection, durable
invalidation, and generation guards reduce that window after the event
arrives. They can't protect the time before delivery.

This is the project's main production blocker. Keep native code-owner
enforcement on production repositories until the
[project status](../reference/project-status.md#production-enforcement-blocker)
says the live contract is closed.

## Keep CODEOWNERS valid

Continue to use GitHub's error API after any ownership change. With Bash and
an authenticated GitHub CLI session, set the three example values and run:

```bash
OWNER=example-org
REPOSITORY=example-repository
BRANCH_OR_COMMIT=main
gh api --method GET "repos/${OWNER}/${REPOSITORY}/codeowners/errors" \
  -f ref="${BRANCH_OR_COMMIT}" \
  --jq '.errors'
```

Replace the values with the repository and exact revision you want GitHub to
inspect. An error-free file returns an empty array. That result proves the file
parses; it does not prove that an undocumented App identity works as a native
code owner.

For GitHub's native behavior, see
[About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
and the
[CODEOWNERS errors API](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors).
