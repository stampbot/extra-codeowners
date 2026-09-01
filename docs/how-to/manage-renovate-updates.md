# Review or recover a Renovate update

Renovate keeps dependencies current through ordinary pull requests. Its work
does not bypass DCO, review, or the repository's required checks.

## Before you begin

You need **Write** repository permission or higher. The procedure edits
Renovate's dashboard, closes bot pull requests, opens a fallback pull request,
and can merge an update. Read and Triage access are not enough.

Renovate currently excludes GitHub Action workflows. Dependabot owns those
updates until [issue #160](https://github.com/stampbot/extra-codeowners/issues/160)
records a tested handoff. Don't enable another manager for the same dependency
class in an ad hoc pull request.

## Review an update

1. Open the Renovate pull request and read its release notes. Confirm that its
   files and dependency names match the change you expect.
2. For a container update, review both the readable version and its immutable
   digest. For a GitHub Action, keep the full commit SHA and version comment
   together. The workflow-security check rejects an unpinned Action.
3. Let Renovate own its branch. Don't amend its commit or push a fix to the
   branch: Renovate can overwrite an amendment and stops updating a branch when
   someone pushes a new commit.
4. Wait for the required checks on the current head. Merge only after the
   normal project review says the update is acceptable.

## Retry a failed or stale update

When a Renovate branch is behind its base or has a transient update failure,
select its **rebase/retry** checkbox in the Dependency Dashboard. Renovate
recreates the commit from the current base; it does not run `git rebase` on a
maintainer's changes.

If the update itself is wrong, close its pull request rather than editing the
bot branch. The Dependency Dashboard records closed updates. First fix the
configuration in a signed maintainer pull request, then select that update's
dashboard checkbox to ask Renovate for a fresh branch.

## Respond when Renovate is unavailable

Leave the dashboard and any existing Renovate pull request intact while the
service recovers. For an urgent security fix, open a normal maintainer pull
request with a matching DCO sign-off and run the usual checks. Do not forge the
bot identity or rewrite its commit. Close the superseded Renovate pull request
after the human change merges; the dashboard keeps an audit trail of that
decision.

## Verify the first bot cycle

The first Renovate pull request must show the bot's ordinary DCO sign-off and
pass the full required CI. Record its URL, head SHA, and DCO result in
[issue #160](https://github.com/stampbot/extra-codeowners/issues/160). That
observation comes before moving GitHub Action updates away from Dependabot.

For Renovate's dashboard and retry behavior, see the [Dependency
Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/) and [Updating
and rebasing branches](https://docs.renovatebot.com/updating-rebasing/) guides.
