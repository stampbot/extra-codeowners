# November 28, 2026: Rebase, merge commit, and squash in the queue

Three PRs merged through GitHub's queue without bypass. Each needed an App
check on its own candidate. The rebase candidate kept both commits, the merge
candidate had two parents, and the squash candidate had one.

## What we ran

Between 05:36 and 05:40 UTC, local App workers used the real installation in
a disposable GitHub.com repository. The source was based on `v1.0.0-alpha.3`
(`3d32213cca8d54fe2695e16f2761a418f16dce41`). The sorted compact JSON of the
reviewed runtime file bindings, including its final newline, has SHA-256
`6c4b5c6a7207642fca9210f1d551b4316c4e97f43b659878d5173334b1c8151c`.

Each temporary branch required one ordinary review, a one-at-a-time queue,
and the named check from the expected App. We set a different merge method
on each branch, kept `ALLGREEN`, and allowed no bypass. Stampbot approved
three PRs with two commits each and one PR outside its delegation.

## What GitHub did

- GitHub admitted the three eligible PRs after the App passed their test
  merges. The required check was absent from their raw heads.
- Each candidate differed from its PR head and test merge. GitHub waited
  for the App to pass it and then advanced the target to that candidate.
  For rebase, the candidate was two commits ahead of the target and none
  behind it, so the worker used the ancestry comparison (XCO-001 and XCO-007).
- The PR outside the delegation failed admission despite its Stampbot
  approval. We confirmed the queues were empty, closed the denied PR, and
  removed the temporary branch rules and refs.

The test used provider-verified identities to invoke the workers. It didn't
test a published release or live webhook ingress. No production rules or
deployments changed.
