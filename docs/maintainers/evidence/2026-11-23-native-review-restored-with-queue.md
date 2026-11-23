# Restoring native review with a merge queue: November 23, 2026

GitHub refused to queue a pull request after we restored native code-owner review. The same commit still had a passing App check and an ordinary approving review from Stampbot.

We ran the test from 16:41 to 16:44 UTC on a temporary branch in the private repository used for the [earlier merge queue tests](2026-11-23-candidate-checks-during-delivery-loss.md). The deployed App ran [alpha.114][alpha] from `c1afffeb5e59bed16dd8498f8785e6194d1bb9c3`, with its experimental queue worker off. Dependabot opened a pull request that changed a single dependency file. GitHub requested a review from the human owner of that file; the author wasn't a code owner.

## What GitHub enforced

The branch required one approving review, a passing check from the installed Extra CODEOWNERS App, and the merge queue. The queue built one candidate at a time, used squash merges, and required every entry to pass its checks. There were no bypass actors.

Stampbot supplied the only approval. We set an independent required test check on the PR head, but never on a merge candidate. With native code-owner review off, GitHub reported `APPROVED` and admitted the PR to the queue. We removed the entry and confirmed the queue was empty before changing the rule.

We restored **Require review from Code Owners** without changing the review count, other checks, or PR head. The same App Check Run stayed successful, the independent head check stayed green, and Stampbot's approval remained in place. GitHub now reported `REVIEW_REQUIRED`. It refused the next queue request and named the missing code-owner review. The queue stayed empty.

## Cleanup and limits

The PR closed without merging. We removed the temporary rules and branches, restored the original default branch, and verified that its tip and rules were unchanged. No production protections changed.

This isolates the native review rule from the ordinary review count in a serial queue. It doesn't show whether a rule change can stop a merge already in progress. It also doesn't remove the [production enforcement blocker][release-gate].

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.114
[release-gate]: ../../reference/project-status.md#production-enforcement-blocker
