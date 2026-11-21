# Repository access loss and merge-queue checks: November 20, 2026

A repository transfer kept a passing Extra CODEOWNERS check visible after
the App lost access. In a separate fixture, GitHub's merge queue required a
new result from the same App, even though the PR head already had a pass.

## Setup

We used three private fixtures with synthetic changes on GitHub.com. The
service ran `v0.1.0-alpha.95` from commit
`9c373e49c1670d5c557067e22318f4b4bd135ebc`. The check was advisory in the
transfer and deletion fixtures. Only the merge-queue fixture required its
separate test Check Run.

## Transfer without App access at the destination

We moved one private fixture into the playground, selected it for the App,
and waited for its advisory check to pass. The repository already required
GitHub code-owner review and one approving review, with no bypass actors.
Both test PRs were open and blocked on review before the outbound transfer.

At 03:30 UTC, we transferred the fixture back to its original organization,
where the App wasn't installed. GitHub kept the repository private and
preserved its ID, both PR heads and the active review ruleset. Both PRs
remained blocked. The old green Check Run was still visible. GitHub denied a
token for the moved repository through the playground installation with
HTTP 422.

GitHub sent an original `installation_repositories.removed` delivery at
03:30:05 UTC. The receiver returned HTTP 202 without queuing work. We
didn't find a matching `repository.transferred` delivery in the bounded
read. That observation isn't a guarantee about which events GitHub sends.

## Repository deletion

We deleted a different private fixture after its advisory check passed.
GitHub returned HTTP 204, then returned HTTP 404 for reads by both the
repository's name and ID. It sent original `repository.deleted` and
`installation_repositories.removed` deliveries within five seconds. The
receiver returned HTTP 202 for each without scheduling work.

The deleted event's top-level fields were `action`, `enterprise`,
`installation`, `organization`, `repository`, and `sender`. The tests
kept delivery metadata and field names, not private payload values. No
merge was attempted in either lifecycle fixture.

## Merge queue with an expected App source

The third fixture required a merge queue with no bypass actors and one
build and merge slot. Its required check named Extra CODEOWNERS as the
expected source. We published a passing fixture Check Run on the PR head
through a token scoped to that repository. GitHub recognized the check
and allowed the PR to enter the queue.

GitHub created a different candidate commit and waited in
`AWAITING_CHECKS`. The head's pass didn't satisfy the candidate. At
03:33:35 UTC, we published a failure from the same App on the candidate.
At 03:34:05 UTC, GitHub removed the PR with reason `failed_checks`. We
closed the PR without merging it, and the target branch didn't move.
We revoked the probe tokens after use.

This test used manual Check Runs, not the policy evaluator or a live
`merge_group` delivery. It shows that the queue can require a result on
the candidate. It does not show that the App can safely evaluate groups,
that it handles every queue rebuild, or that review withdrawal is atomic
with merge. [Issue #4](https://github.com/stampbot/extra-codeowners/issues/4)
tracks the remaining queue work.
