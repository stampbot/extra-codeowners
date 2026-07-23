# DCO evidence contract

Extra CODEOWNERS contains a pure Developer Certificate of Origin (DCO)
evaluator. It is not the DCO check that runs on pull requests today. No service
or workflow calls it, and it cannot publish a Check Run.

The checked-in `.github/workflows/dco.yml` workflow remains active. Because a
pull request can change that workflow, treat its result as review evidence—not
as an independently enforced merge control. [Issue #40][issue-40] tracks the
independent caller, publication guard, live tests, and rollout.

This page defines the evidence that caller must collect. Incomplete,
contradictory, stale, or ambiguous evidence must leave the check blocking.

## Collection sequence

The caller must use a verified GitHub event and current GitHub API responses.
It must not check out or execute code from the pull request.

```text
GitHub                 independent caller                  pure evaluator
  |                            |                                  |
  |-- verified PR event ------>|                                  |
  |<-- fetch PR (before) ------|                                  |
  |<-- list PR commit nodes ---|                                  |
  |<-- fetch each commit ------|                                  |
  |<-- fetch PR (after) -------|                                  |
  |                            |-- event + snapshots + commits --->|
  |                            |<-- repo/PR/base/head decision ----|
  |<-- revalidate + publish ---|                                  |
       not implemented
```

In order, the caller must:

1. Parse the event snapshot from the pull request and top-level repository in
   the verified webhook payload.
2. Fetch the current pull request and parse the `before` snapshot.
3. Page through the pull request's GraphQL commit connection. Require the
   exact repository, pull request, base, and head identity on every page.
4. Fetch each listed `PullRequestCommit` node and project only the fields the
   evaluator consumes.
5. Fetch the pull request again and parse the `after` snapshot.
6. Evaluate only when the event, `before`, and `after` snapshots match exactly.
7. Before publishing success, fetch the pull request once more and require the
   same repository, pull-request number, open state, base SHA, head SHA, and
   commit count. This publication guard does not exist yet.

Snapshot equality includes repository IDs and names, pull-request number and
state, base and head refs, base and head SHAs, author identity, and commit
count. A force-push, retarget, repository change, or concurrent commit makes
the evidence stale.

An eligible REST snapshot is open, so every GraphQL response for it must report
`OPEN`. GitHub's REST pull-request state folds merged pull requests into
`closed`; for an already-ineligible closed snapshot, the adapter accepts either
GraphQL `CLOSED` or `MERGED`. The evaluator cannot pass either one.

A network, permission, rate-limit, parsing, or validation error does not
produce a decision. The future caller must keep the required check blocking
and retry from a fresh snapshot.

## Snapshot-bound commit listing

The client uses GitHub's GraphQL [`PullRequest.commits` connection][pr-commits].
The query selects commit node IDs and OIDs; it does not ask for files, patches,
or change statistics. A large diff therefore cannot make an unrelated DCO read
exceed its response limit.

Every page repeats and validates:

- repository database ID and `nameWithOwner`
- pull-request number and state
- base and head ref names and OIDs
- base and head repository identities
- total commit count and pagination state.

Each node must have a unique GraphQL ID and lowercase 40-character commit OID.
Pages contain at most 100 nodes. The complete list contains at most 250 nodes,
matches the snapshot count exactly, and ends at the snapshot head. A missing,
repeated, malformed, or extra node fails collection.

Keeping the commit connection and base/head identity in the same response lets
the client detect returned identity drift. Evidence from an observably
different target cannot match the snapshot, and the client checks the identity
again with each commit node.

GitHub does not document field-level snapshot isolation within a response or
connection consistency between pages. Exact OIDs, graph checks, and the
before/after snapshots still fail closed when the returned identity changes,
but the provider behavior remains a live-contract assumption. Retarget and
force-push races must pass that contract before rollout.

## Commit details and graph checks

Each detail query addresses the `PullRequestCommit` node ID returned by the
listing. The response must repeat the same pull-request identity, node ID, and
commit OID. This keeps fork commits anchored to the base repository's pull
request without requesting REST commit file data.

The query selects parent OIDs, raw Git author and committer identity, the commit
message, GitHub's author user, and compact signature facts. The parser reduces
the message to ordinary and Dependabot sign-off booleans immediately. It never
retains the full message, raw signature, or signed payload in `CommitEvidence`.
At most two detail requests run concurrently, and the complete pull request has
a 16 MiB decoded-message budget.

The evaluator then requires:

- one detail response for every compared SHA, in the same order
- every parent that is also in the comparison to appear before its child
- every compared commit to be reachable from the exact head through compared
  parents.

Merge commits are valid. Stacked pull requests are also valid: a parent outside
the current comparison does not need to appear.

GitHub's public GraphQL reference does not promise an order for this
connection. The evaluator adds a fail-closed parent-before-child requirement,
so the live contract fixture must prove that behavior before rollout. Cover
merge graphs and deliberately skewed commit timestamps. The fixture must also
prove that the base repository can fetch exact commit details for private-fork
heads. Failure of either contract blocks rollout.

## Ordinary sign-offs

An ordinary commit passes when one complete message line matches its raw Git
author:

```text
Signed-off-by: AUTHOR NAME <AUTHOR EMAIL>
```

The evaluator applies Python `str.casefold()` to both strings and then compares
them for equality. It does not normalize Unicode. This is deterministic across
runner locales and does not send author-controlled text to a shell.

Leading or trailing whitespace, a carriage return, extra text, or a matching
substring on a longer line does not pass. Git identities cannot contain the
`<` or `>` delimiters. Control and formatting characters are rejected before
matching.

The regression corpus records the intended Unicode behavior:

| Raw author | Trailer identity | Result |
| --- | --- | --- |
| `Test Contributor <contributor@example.com>` | `TEST CONTRIBUTOR <CONTRIBUTOR@EXAMPLE.COM>` | Pass |
| `Zoë <zoë@example.com>` | `ZOË <ZOË@EXAMPLE.COM>` | Pass |
| `ΟΣ <sigma@example.com>` | `ος <SIGMA@EXAMPLE.COM>` | Pass; final sigma case-folds to sigma |
| `İpek <ipek@example.com>` | `i̇PEK <IPEK@EXAMPLE.COM>` | Pass; the first `i` is followed by a combining dot |
| `Straße <straße@example.com>` | `STRASSE <STRASSE@EXAMPLE.COM>` | Pass; sharp S case-folds to `ss` |
| `José <jose@example.com>` | `José <JOSE@EXAMPLE.COM>` | Fail; decomposed and precomposed accents are not normalized |

The active workflow delegates case-insensitive matching to GNU `grep` and the
runner locale. Python case folding is a deliberate replacement, not an assumed
equivalent. Before cutover, run this corpus through both implementations in a
disposable repository. Any difference is a migration failure until it is
explained, reviewed, and resolved; unit tests alone do not establish live
parity.

Results contain only fixed outcomes and commit SHAs. They never copy raw commit
messages or identities into check output.

## Dependabot fallback

The ordinary rule is tried first. An official Dependabot commit may instead
use GitHub's canonical `dependabot[bot] <support@github.com>` trailer, but only
when every predicate below matches.

| Evidence | Required value |
| --- | --- |
| Pull-request author | Login `dependabot[bot]`, user ID `49699333`, type `Bot` |
| Repository | Base and head repository IDs equal the evaluated repository ID |
| Branch and history | Head ref starts with `dependabot/`; the pull request has one commit |
| Commit position | Commit SHA is the exact head; its only parent is the exact base |
| GitHub commit author | Login `dependabot[bot]`, user ID `49699333` |
| Raw Git author | `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>` |
| Raw Git committer | `GitHub <noreply@github.com>` |
| Signature | `isValid`; state `VALID`; nonempty verification time; `wasSignedByGitHub`; signer login `web-flow`, user ID `19864447` |
| Trailer | Exact, case-sensitive line `Signed-off-by: dependabot[bot] <support@github.com>` |

The fallback stays case-sensitive and does not use Unicode case folding.
Dependabot can still pass the ordinary route when its trailer matches its raw
Git author.

## Input limits and parsing

Evidence models are immutable and reject unknown fields. Their parsers copy
only fields used by the decision.

| Field | Limit |
| --- | --- |
| Compared commits, detail responses, and results | 250 |
| One GraphQL commit-list page | 256 KiB after HTTP decoding |
| One GraphQL commit-detail response | 8 MiB after HTTP decoding |
| Concurrent commit-detail responses | 2 |
| Pull-request commit node ID | 512 UTF-8 bytes; no whitespace, control, or formatting characters |
| Pagination cursor | 4,096 UTF-8 bytes; nonempty and never repeated while another page is required |
| JSON container nesting | 64 levels |
| Parents per commit | 64 |
| Commit message | 1,000,000 UTF-8 bytes |
| All decoded commit messages in one collection | 16 MiB |
| Git author or committer name and email | 1,024 UTF-8 bytes per field |
| Base or head ref | 1,024 UTF-8 bytes |
| GitHub actor login and type | 256 and 64 UTF-8 bytes, respectively |
| Repository full name | 512 ASCII bytes |
| Signature state and timestamp | 128 UTF-8 bytes per field |

The bounded JSON reader decodes bytes strictly as UTF-8 before parsing. It
rejects a UTF-8 byte-order mark, UTF-16, UTF-32, duplicate object keys,
excessive nesting, and integers beyond Python's parser limit.

A pull request at the 250-commit limit requires at most 253 GraphQL calls per
collection attempt: three commit-list pages and 250 detail queries. Only two
detail queries run at once. Any API, rate-limit, parsing, or validation failure
discards the attempt; the future caller must restart from a fresh snapshot and
budget for the same worst-case call count on retry. Token exchange and the
surrounding REST snapshot and publication reads are additional calls.

GitHub can report [GraphQL primary and secondary rate limits][graphql-rate]
with HTTP 200 and a nonempty `errors` array. The client maps those responses to
the same bounded rate-limit error used for REST. It honors `Retry-After` first,
then `X-RateLimit-Reset`, and defaults to 60 seconds without usable timing
metadata. The raised error uses a fixed message instead of copying provider
error text into logs.

Commit messages may contain newlines, but not NUL. The GraphQL query omits raw
signature and payload fields entirely.
Repository names keep their exact case and must match
`[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`; `.` and `..` are invalid components. Refs,
actor fields, and Git identities reject control and formatting characters.

## Result contract

Every result carries the evaluated repository identity, pull-request number,
base SHA, and head SHA. That binding is required even for a failure, so a future
publisher cannot mistake a decision for another snapshot.

Each commit has one fixed outcome:

- `author-signoff`
- `official-dependabot`
- `missing-signoff`.

A passing result has no failure reason. A failure uses one fixed value and does
not include untrusted evidence:

| Failure | Meaning |
| --- | --- |
| `pull-request-not-open` | The event snapshot was not open. |
| `pull-request-changed` | The event, `before`, and `after` snapshots differed. |
| `comparison-mismatch` | The comparison was bound to a different repository, PR, base, or head. |
| `commit-count-mismatch` | Comparison metadata, compared commits, details, or snapshot count differed. |
| `duplicate-commit` | The comparison repeated a SHA. |
| `head-mismatch` | The comparison did not end at the exact snapshot head. |
| `commit-order-mismatch` | Detail order, parent order, or reachability disagreed. |
| `missing-signoff` | At least one commit passed neither sign-off route. |

## Rollout boundary

`GitHubClient.get_pull_commit_evidence` performs the bounded commit listing and
detail collection. No runtime path calls it for DCO today.

The independent integration still must:

- run code that the evaluated pull request cannot modify
- limit its installation token to **Pull requests: read**, **Contents: read**,
  and **Checks: write**
- perform the publication guard against the exact repository, PR, base, head,
  state, and count
- publish a distinct required context bound to the expected GitHub App source
- leave API, validation, race, and publication failures blocking
- pass same-repository, fork, merge, stacked, retarget, force-push, Unicode,
  and negative source-binding cases in a disposable repository.

Do not replace the current DCO check or change repository rules based on this
dormant layer. Follow [issue #40][issue-40] for the remaining implementation
and live evidence.

[pr-commits]: https://docs.github.com/en/graphql/reference/pulls#object-pullrequestcommitconnection
[graphql-rate]: https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api#exceeding-the-rate-limit
[issue-40]: https://github.com/stampbot/extra-codeowners/issues/40
