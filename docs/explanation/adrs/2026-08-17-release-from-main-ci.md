# ADR: Release every main commit from its CI run

## Record

| Field | Value |
| --- | --- |
| Date | 2026-08-17 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Danny Sauer |
| Scope | How versions are chosen and how release artifacts are built and published. It doesn't make an alpha a supported production release. |
| Related | [Architecture: CI and release path](../architecture.md#ci-and-release-path), [maintainer guide](../../maintainers/index.md), [Debian slim runtime](2026-08-17-debian-slim-runtime.md) |
| Implementation | [PR #146](https://github.com/stampbot/extra-codeowners/pull/146); release-channel trailers in [PR #168](https://github.com/stampbot/extra-codeowners/pull/168) |

## Business driver

With one maintainer, every manual release step is a step that gets skipped or
done inconsistently. The earlier pipeline was fragile enough that releases
lagged behind `main`, and a release built separately from CI couldn't prove it
contained the bytes CI had tested.

## Constraints

- A release must come from the exact commit that passed the required checks.
- Signatures, attestations, and provenance must bind to that tested commit.
- A partial or repeated run must never publish a second, conflicting release.

## Decision

**Y statement:** We will publish a release from every successful `main` CI run,
inside that run, with the version derived from Git tags and commit messages,
because a release built anywhere else can't prove it matches what CI tested,
so no one maintains a release pull request, version file, or hand-made tag.

The decision has these boundaries:

- Alpha releases increment their numeric suffix. Stable releases use
  conventional commits to choose the bump.
- A terminal `Release-Channel: alpha` or `Release-Channel: stable` Git trailer
  is the only way to change channel. A malformed or repeated trailer fails
  release planning.
- The published, immutable GitHub release is the completion record. A rerun
  reuses matching state and refuses a collision.
- Python archives are GitHub release assets; the project doesn't publish to
  PyPI.

## Consequences

- One release can cover two closely spaced merges, because queued runs may
  start out of order and the older run then steps aside.
- Channel changes happen in commit history, so a squash merge must keep the
  trailer in the final commit message.
- Every merge to `main` ships an artifact, so `main` has to stay releasable.

## Alternatives considered

### Keep the current approach

The previous pipeline crossed a bespoke wheelhouse, a cross-architecture
evidence spine, and raw OCI transport before it could publish anything. Small
changes often failed late, and the maintenance cost outgrew the application.

### Release pull requests

A tool such as Release Please opens a pull request that bumps a version file
and changelog. That adds a second merge per release and a version file to keep
in sync, and the release still has to rebuild artifacts outside the CI run
that tested them.
