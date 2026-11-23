# ADR: Start a new major alpha line without publishing stable

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-23 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Start the next major version from a published alpha. Build, signing and publication still run in main CI. |
| Supersedes | The version-selection boundaries of [Release from main CI](2026-08-17-release-from-main-ci.md#decision) for this transition only. |
| Implementation | [PR #340](https://github.com/stampbot/extra-codeowners/pull/340) |
| Revisit when | We need to start a different version line from an existing prerelease. |

## Business driver

A stable trailer promotes the current alpha base. From `v0.1.0-alpha.106`,
that gives us `v0.1.0`, not a candidate for `v1.0.0`. Publishing an extra
stable release would neither test the intended version nor reflect what we
want to support.

## Constraints

- Ordinary alpha merges still increment the suffix, even if they contain a
  breaking-change marker.
- Starting a line and promoting it are separate decisions in Git history.
- Main CI keeps its existing checks for the tested revision, monotonic tags,
  and immutable releases. There is no manually maintained version file.

## Decision

**Y statement:** We will start the next major alpha when a breaking-change
commit also carries `Release-Channel: alpha`, so we can test the intended
release line before deciding whether to promote it.

When the latest release tag is an alpha, both signals must be on the same
commit. The new version resets minor and patch to zero and starts at
`alpha.1`. A second request to start a major line before the first publishes
is ambiguous, so the planner rejects it. Other no-op or malformed channel
requests still fail.

The planner refuses to promote the new line until it has a tag. The release
workflow also checks that the tagged predecessor finished publishing and is
immutable. A later ordinary `alpha` trailer can cancel an early stable request;
it doesn't cancel the pending major line.

## Consequences

The current `0.1.0` alpha line can produce `v1.0.0-alpha.1` without shipping
`v0.1.0`. A later commit can promote the tested line to `v1.0.0`. If GitHub
runs a newer commit first, it can publish the alpha with the same intent; the
older run still verifies the descendant release instead of publishing twice.
The [contributor guide][contributing] covers the commit message and how to
recover from an early promotion request.

## Alternatives considered

### Publish the old line as stable first

That would let the existing stable bump rules start a major alpha. It also
creates a stable release we don't intend to support, so we rejected it.

### Start a new major on every breaking-change commit

That makes it easy for an alpha-only interface change to move the version line
by accident. Requiring the existing trailer keeps that choice explicit with
no new version syntax or release mechanism.

[contributing]: https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md#choose-a-release-channel
