# November 27, 2026: Queue admission and separate candidate decisions

GitHub admitted two pull requests with passing Extra CODEOWNERS checks on
their PR test merges. It merged neither until the App passed its own squash
candidate. A third PR with a Stampbot approval couldn't enter because its
change wasn't eligible for App delegation.

## What we tested

Between 19:04 and 19:16 UTC, locally run App workers used the real App
installation on a disposable GitHub.com repository. The source was based on
`v1.0.0-alpha.2` (`16e1a43ba78ed96158fd1f3799937120ccb79470`) with the
queue changes for [issue #383][issue]. The sorted compact JSON of the tested
runtime file bindings, including its trailing newline, has SHA-256
`c1afef8e2e33c6b0542d4d8099187da10cc0e4b5b0e67ee069cd838f67a37859`.

The temporary branch required one ordinary review and the check from the
expected Extra CODEOWNERS App. Its merge queue used squash, one build slot,
one PR per merge, and `ALLGREEN`. It allowed no bypass actors. Stampbot
approved all three PRs. We passed verified PR and candidate identities to
the local workers and recorded what GitHub did with the resulting checks.

## What we observed

- The App passed two test merges and failed the third. The required check
  wasn't on any raw PR head. GitHub admitted the first two PRs and refused
  the third despite its ordinary approval.
- The first PR waited for checks on its own candidate. The second stayed
  queued without a candidate. GitHub advanced the branch to the first
  candidate only after its App check passed.
- GitHub then built a different candidate for the second PR. It waited
  without a result even though the first candidate and its own test merge
  both passed. The PR record still showed the original base SHA; the live
  branch and queue entry showed the first merge. After the worker used that
  live base and published a pass, GitHub merged the second candidate.
- Both merge commit SHAs matched the respective checked candidate commits.
  The denied PR never merged. We confirmed the queue was empty, closed that
  PR, and removed the temporary branch, rule and source branches.

These observations cover distinct candidate results (XCO-007) under the
tested rules. They don't verify an immutable release or production webhook
delivery. They don't make review withdrawal atomic with GitHub's merge.
Production rules and the advisory deployment weren't changed for the test.

[issue]: https://github.com/stampbot/extra-codeowners/issues/383
