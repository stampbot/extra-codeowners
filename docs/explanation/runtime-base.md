# Why the runtime uses Debian slim

Extra CODEOWNERS needs the same container build to work on `amd64` and `arm64`
without maintaining a second Python packaging system. Both stages therefore
use the Docker Official Image for Python 3.14 on Debian Trixie slim, pinned
by digest. The Dockerfile is the source of truth for the current patch version
and digest; this page does not copy values that Renovate would have to keep in
sync.

The readable tag tells reviewers which Python and Debian line they are looking
at. The digest fixes the bytes used by the build. Renovate updates both through
an ordinary pull request, so a base-image refresh gets the same tests and
review as an application change.

## Why Debian fits this application

The locked dependency graph has published Linux wheels for both supported
architectures. Debian's glibc runtime can install those wheels directly,
including `psycopg-binary`; the image build doesn't need a compiler, operating
system development packages, or a project-owned wheelhouse.

That matters more than shaving a few megabytes from the final image. A custom
native build adds another release cadence, cache, signing path, and failure
mode. Here it wouldn't buy a compatibility property that upstream wheels do
not already provide.

Debian slim also gives operators a familiar runtime when they need to inspect
a failed pod. It carries more operating system surface than a distroless image,
but the service still runs as an unprivileged user with a read-only root
filesystem and no Linux capabilities in the Helm defaults.

## What the build guarantees

The builder installs the runtime and build graphs from `uv.lock`. Runtime
installation uses `--no-build`, so the build fails when any supported platform
lacks a compatible wheel. The build backend and its transitive dependencies
come from the lockfile as a separate group and never enter the runtime image.

Source code is copied only after the dependency layers. Most application
changes can therefore reuse the expensive layers from the BuildKit cache. A
scheduled cold-build workflow disables that cache on both architectures, which
checks that the cache is an optimization rather than an undeclared input.

The final stage receives only the virtual environment, the project license,
and a small build-identity record. It removes `pip` and `ensurepip`, owns the
application files as root, and starts the service as UID and GID 65532. The
runtime remains a Debian image; it is not presented as shell-free or
distroless.

## How CI tests the choice

Pull-request CI builds each architecture on a native GitHub-hosted runner.
Each job then runs the image with no network, no capabilities, and a read-only
root filesystem. The smoke test checks the native architecture, glibc,
`psycopg-binary`, the installed application version, the source revision, file
ownership, database migration, and health endpoints.

The two native jobs run independently and keep separate BuildKit caches. A
failure on one architecture cannot be hidden by a successful build on the
other. CI also records a vulnerability inventory and rejects fixable High or
Critical findings.

After `Required` succeeds on a `main` push, the release job repeats the native
builds with provenance and software bill of materials generation enabled. It
joins the two resulting digests into one versioned multi-platform image, then
signs and attests that image. The release tag is immutable; the image has no
mutable `latest` contract.

## Updates and rollback

A dependency update changes `uv.lock`. A base update changes the readable
Docker tag and digest in the Dockerfile. Neither update needs a hand-maintained
package inventory or a companion version file.

Before deploying an update, record the platform digest selected from the
multi-platform image and read the matching
[database upgrade notes](../reference/upgrade-notes.md). Roll back only to a
previously verified digest that supports the current database head. If the
database head changed, use the
[backup and restore procedure](../how-to/upgrade.md); rebuilding an old
Dockerfile is not a rollback.

## Risk that remains

Digest pinning prevents the selected base from changing unnoticed. It does
not prove that the base is free of vulnerabilities, that a scanner knows every
issue, or that upstream wheel publishers made no mistake. The final image also
contains Debian userland and the CPython standard library beyond the code this
service normally reaches.

The project manages that risk with locked dependencies, native smoke tests,
complete vulnerability inventories, a fixable High/Critical gate, recurring
cold builds, and release attestations. The JSON inventories retain suppressed
matches, including the reason from `.grype.yaml`.

The policy has one scoped exception. Grype reports CVE-2026-15308 as fixable
for the CPython 3.14 binary because Python 3.15 contains a fix. Moving to an
incompatible Python line isn't a routine patch, so the gate suppresses that
CVE only for the current CPython binary package version. The full inventory
still records it. All other fixable High and Critical findings stop the build.

A Python base update stops matching the exception. CI then requires a
maintainer to read the new report and remove or renew the rule for that exact
patch version. A regression test keeps the version in `.grype.yaml` tied to
the Dockerfile.

The project also has a reviewed OpenVEX statement for current OpenSSL CVEs that
do not affect the service. The [security policy](https://github.com/stampbot/extra-codeowners/blob/main/SECURITY.md)
explains why and links to the exact statement. CI consumes it when it scans the
matching image, while the raw inventory keeps every finding. A base-image
update changes the package URL and makes the VEX stop matching; it cannot
silently carry an old conclusion into a new image. At release time, the
workflow checks the statement against both native inventories before it creates
an immutable tag or versioned image. It then signs the statement as a release
asset and attaches it to the final multi-platform image digest.

Those controls make changes visible and repeatable. They do not turn an alpha
image into a supported production release.
