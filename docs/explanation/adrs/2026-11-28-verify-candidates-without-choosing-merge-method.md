# ADR: Verify candidates without choosing the merge method

| Field | Value |
| --- | --- |
| Date | 2026-11-28 |
| Status | Accepted |
| Owner | Maintainers |
| Scope | Evidence for an individual GitHub merge-queue candidate |
| Revises | The squash requirement in [the one-at-a-time queue decision](2026-11-25-require-a-serial-merge-queue.md). Its other requirements still apply. |

## Why squash was a problem

The first implementation checked that the candidate had one parent and that
its parent was the target tip. That matched the squash fixture. It didn't
work for repositories that keep their commits separate, even though the App
doesn't need to decide which history the repository keeps.

## Decision

The App requires one built candidate and one PR per merge. It ignores the
rule's merge method. The worker verifies the live target and the queue entry,
then proves that the candidate descends from that target.

If the candidate's first parent is the target, the commit itself proves the
relationship. Otherwise the worker asks GitHub for one bounded comparison
that names both commits. The candidate must be ahead of the target, with no
commits behind it. In either case the worker still compares the two complete
trees and checks that the PR's reviewed paths cover the candidate's changes.
The PR test merge used for admission keeps its separate identity check.

## Consequences

Repositories don't have to change their preferred merge method just for the
App. A candidate with more history may need one extra API request. If GitHub
can't establish ancestry for the two commits, the App won't pass the candidate.
Before changing native review on a branch, test that GitHub admits, blocks,
and merges the right PRs using the chosen method and the deployed release.
