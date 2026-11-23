# November 23, 2026: One candidate with a second pull request waiting

GitHub kept the first candidate unchanged when a second pull request joined
the queue. The second PR had no candidate of its own. The distinction matters
because Extra CODEOWNERS currently rejects a queue with more than one entry,
even when only the first entry has a candidate.

## Setup

We watched GitHub.com from 13:31:21 to 13:31:26 UTC. We used a temporary target
branch in the private fixture and opened two PRs. Each added a different
synthetic file from the same base. No App build was under test.

The branch required one build slot and one PR per merge. It required every
candidate to pass (`ALLGREEN`) and had no bypass actors. We posted a
fixture-only status on each PR head so it could enter the queue. That status
wasn't tied to an App source, and we never posted it on a candidate.

## What GitHub returned

With the first PR waiting for a check, we recorded its queue entry and
candidate commit. Then we queued the second PR and read the queue twice.
GitHub returned these two entries in both reads:

| Queue position | State | Candidate |
| --- | --- | --- |
| 1 | `AWAITING_CHECKS` | Same entry, base commit, and candidate commit as before |
| 2 | `QUEUED` | No base or candidate commit yet |

We compared the first candidate with its target commit. The diff contained
only the file from the first PR. Neither PR merged. We closed both and
removed the temporary ruleset and branches. The default branch and its
ruleset were unchanged.

## What the App can read

At 13:35 UTC, we used a pod running [alpha.111][app-release]
(`2bc0e98f60286c30e76b7bcc260faeb39eed31f0`) to mint a read-only App token
for the same repository. We checked the empty default-branch queue after
cleanup. GitHub let the token list entries but returned `FORBIDDEN` for
`mergeQueue.configuration`.

The same token could read the [effective branch rules][branch-rules] through
REST. That response included the `ALLGREEN` strategy, one build slot, and
one PR per merge. We revoked the token after the reads. No App permission
or repository rule changed for this part of the test.

## Limits

The two-entry test used a maintainer credential. The App read tested API
access only; it didn't evaluate or publish a result for a candidate. Neither
test covered multiple build slots, multiple PRs in a candidate, or an
already-passing candidate whose approval changes.
[Issue #4](https://github.com/stampbot/extra-codeowners/issues/4) tracks those
and the work to recognize a waiting entry without weakening candidate checks.

[app-release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.111
[branch-rules]: https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch
