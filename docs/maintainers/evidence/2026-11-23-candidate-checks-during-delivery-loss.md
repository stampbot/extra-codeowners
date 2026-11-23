# Candidate checks during webhook loss: November 23, 2026

GitHub showed the same old passing check on two PRs that needed a new review.
Neither PR merged. The queue required a result on a separate candidate commit
in each case. An eligible PR did merge after the App approved its candidate.

## Setup

We used one private GitHub.com fixture with synthetic changes. Extra
CODEOWNERS ran [alpha.103][release] from `f017d13f8abf2535974658af598c2e03a58452cb`.
The experimental worker was enabled for the disposable repository by both
name and repository ID. No production review rule changed.

Each test branch required the merge queue and the Extra CODEOWNERS check
from the installed App. Each queue had one build slot and one merge slot,
required every entry to pass, and had no bypass actors. We checked the
effective rules before submitting the PRs to the queue.

## A delayed delivery and a lost delivery

At 08:15 UTC, while the webhook receiver was stopped for the database
upgrade, we opened one PR and retargeted another to branches that didn't
accept author approval. Both PRs used the same commit that had already
passed on a different base. GitHub still showed that pass on both PRs.
Its delivery log recorded HTTP 503 for the original `opened` and `edited`
events.

Both PRs entered the queue at 08:26 UTC. GitHub created a different
candidate for each one, distinct from the PR head, and waited for its
required check. The original `merge_group.checks_requested` deliveries
returned HTTP 503. After the receiver came back, both candidates were
still waiting and neither had a Check Run from the App.

- **Retargeted PR:** GitHub redelivered the candidate's event at 08:31:34
  UTC and the receiver returned HTTP 202. The App reported failure on that
  candidate; GitHub removed it without merging the PR.
- **Newly opened PR:** We didn't redeliver its candidate event. GitHub
  removed it at 08:37:30 UTC with reason `checks_timed_out`. The candidate
  had no App Check Run, the PR stayed open, and the target branch didn't
  move.

## Positive control

We opened a fresh PR for a path its author owned on a branch that accepted
author approval. It used a new head and had no reviews. GitHub sent the
candidate event at 08:34:46 UTC and the receiver returned HTTP 202. The App
reported success on the candidate at 08:34:54 UTC. GitHub merged that
candidate into the disposable branch at 08:35:26 UTC, without a bypass.

## Hand back enforcement before removing access

On the same branch, we opened another eligible PR and confirmed its App
check passed. In one ruleset update, we replaced the queue and required
App check with GitHub's native code-owner review and one approving review.
There were no bypass actors. GitHub blocked the PR while the old green
check was still visible.

At 08:40 UTC, we briefly suspended the playground installation. Its
reported suspension was active when we tried the normal merge API. GitHub
rejected the request with HTTP 405 because an approving review was missing.
The PR stayed open, its check stayed green, and the branch didn't move.
We resumed the installation and verified that GitHub no longer reported
it suspended.

We then closed the three unmerged test PRs and removed the rules we added
for this run. The fixture's existing default-branch rules were unchanged.

## Limits

This test covers the opt-in worker in one repository, with one PR per
candidate. It shows why a normal required check on the PR head isn't a
substitute for a check on the commit GitHub will merge. It doesn't make
review dismissal atomic with merge, prove how larger groups behave, or
remove the need for native enforcement when retiring the App. See the
[merge-queue design](../../explanation/design/2026-11-21-merge-queue-candidate-checks.md).

[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.103
