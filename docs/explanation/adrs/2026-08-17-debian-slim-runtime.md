# ADR: Build the runtime image on Debian slim

## Record

| Field | Value |
| --- | --- |
| Date | 2026-08-17 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Danny Sauer |
| Scope | The base image for the build and runtime container stages. It doesn't cover vulnerability policy or release signing. |
| Related | [Why the runtime uses Debian slim](../runtime-base.md), [release from main CI](2026-08-17-release-from-main-ci.md) |
| Implementation | [PR #146](https://github.com/stampbot/extra-codeowners/pull/146), [issue #135](https://github.com/stampbot/extra-codeowners/issues/135) |

## Business driver

The container has to build the same way on `amd64` and `arm64`. The previous
Alpine image needed a project-owned native wheelhouse, a cross-architecture
evidence pipeline, and more than 50,000 lines of build tooling. Small changes
routinely failed late in that chain, and keeping it working cost more than the
application itself.

## Constraints

- Runtime dependencies come from `uv.lock` and install without a compiler or
  operating system build packages.
- Both architectures build natively and pass the same smoke test and
  vulnerability gate.
- The base is pinned by digest and updated through ordinary pull requests.

## Decision

**Y statement:** We will build both container stages on the Docker Official
Image for Python on Debian slim, pinned by digest, because its glibc runtime
installs the published Linux wheels for every locked dependency directly, so
the build needs no compiler, native wheelhouse, or second packaging system.

The decision has these boundaries:

- Runtime installation uses `--no-build`. A platform without a compatible wheel
  fails the build rather than compiling from source.
- The Dockerfile is the source of truth for the exact Python patch version and
  digest; documentation doesn't copy them.
- The runtime is presented as a Debian image, not a shell-free or distroless
  one.

## Consequences

- The image carries more operating system surface than Alpine or distroless.
  The Helm defaults compensate with an unprivileged user, a read-only root
  filesystem, and no Linux capabilities.
- A base-image update changes package URLs, so a reviewed VEX statement stops
  matching instead of carrying an old conclusion forward.
- Operators get familiar tools when they inspect a failed pod.

## Alternatives considered

### Keep the current approach

Alpine with musl needed the project to build and sign its own native wheels for
both architectures. That added a release cadence, cache, signing path, and
failure mode, and it bought no compatibility that upstream glibc wheels didn't
already provide.

### Distroless runtime

A distroless image would remove the shell and most of the userland. The build
would still need a glibc base that matches the wheels, and operators would lose
the tools they use to inspect a failed pod. The smaller surface didn't justify
a second base-image line to maintain.
