# Container distribution evidence design

Extra CODEOWNERS distributes more than its Apache-2.0 application code. Its OCI
image also contains CPython, locked Python packages, Alpine packages, and bytes
hidden by later layers. Container evidence makes that aggregate inspectable. It
does not declare the aggregate legally compliant.

## Current status

Pull-request CI builds separate `linux/amd64` and `linux/arm64` candidates and
uploads an evidence archive for each platform. These short-lived, unsigned
artifacts are review inputs. Their subject is the local image configuration
digest because CI has not published a platform manifest.

Public `main` image and tagged publication are deliberately disabled. The main
publication job has been removed. The release workflow may run validation,
proof, and candidate-scan jobs with repository-read authority, but a separate
job fails before any job can publish an image, chart, Python package, or GitHub
release. Setting
`distribution_approval.approved=true` does not remove that structural block.
Security issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
required privilege-separated release implementation.

Pull-request CI now builds the application twice on each native architecture
with the hash-pinned PEP 517 closure, requires byte-identical architecture
proofs, and selects one exact five-file proof. Both container candidates install
that wheel without rebuilding it. Their stable OCI labels bind the source
revision, wheel SHA-256, and selection-record SHA-256; run metadata separately
binds the selected GitHub Actions artifact ID and archive digest. Run-scoped
artifact identity never enters an image label, so a rerun does not change image
bytes for that reason. Issue
[`#32`](https://github.com/stampbot/extra-codeowners/issues/32) remains open for
retaining this proof in release evidence and handing it to the future isolated
publication path. The reusable workflow also supports a read-only manual run,
and the tagged candidate scan consumes only the proof built in its own run. No
CI collector success overrides the publication blocker.

The current archive is intentionally incomplete as distribution evidence.
CPython is now a normalized top-level runtime component with exact identity,
recipe, source, and license evidence. Issue `#18` remains open because native
wheel payloads and embedded SBOMs are not expanded into complete component,
notice, and corresponding-source records. That is the sole remaining reason
the collector sets
`source_completeness.complete` to `false`; it rejects distribution
approval while that status remains false. Issue `#28` independently keeps
every tagged publication path blocked.

## What the CI collector records and validates

The collector saves the inspected image by immutable configuration ID. It
checks the SHA-256 name of the saved configuration and every layer against the
actual member bytes before parsing them. It then:

1. applies OCI whiteout and opaque-directory behavior without letting archive
   order remove files created in the same layer
2. inventories the union of package records in every distributed Alpine
   database and all Python `METADATA`, marking whether each record remains
   effective
3. records every regular-file, directory, non-regular, and whiteout occurrence,
   plus embedded wheel SBOMs, native Python payloads, installed wheel identity
   files, effective Python `RECORD` ownership, and historical RECORD replay
4. rejects duplicate paths, malformed whiteouts, unsafe ancestor topology,
   conflicting authoritative metadata, and an APK architecture that does not
   match the requested platform
5. requires the saved configuration's ordered rootfs diff IDs to match every
   layer and requires the initial diff IDs to match the reviewed
   platform-specific Docker Official Python base
6. compares the normalized top-level component inventory byte-for-byte with the
   reviewed platform policy, including one exact CPython runtime identity
7. reverifies the exact selected proof, requires every application-owned
   runtime file (including the installer-generated `RECORD` and reviewed
   launcher aliases) to match one complete selected-wheel layout, and retains
   all five proof files under `artifacts/application/`
8. retrieves hash-pinned source and license material for those top-level
   components and produces a deterministic, explicitly incomplete review
   archive.

### Historical Python installation replay

For each layer, the collector applies every whiteout before ordinary entries,
then evaluates the completed layer snapshot. Tar member order cannot make an
incomplete installation appear valid. Every newly introduced virtual-environment
`RECORD` must bind regular METADATA, WHEEL, and RECORD occurrences and every
normalized path it claims. The component inventory retains that relationship in
`wheel_installations` with:

- a canonical owner such as `python:demo@1.0`
- the exact METADATA, WHEEL, and RECORD occurrence identities
- normalized wheel tags and `Root-Is-Purelib` state
- each normalized RECORD entry, its declared digest and size, and the exact
  layer occurrence it owned.

The historical list remains after a later whiteout; each retained occurrence
still reports whether it is effective in the final filesystem. The existing
`python_record_ownership` array is the effective-only compatibility view.
Active installations cannot repeat an owner or claim the same path. A later
regular-file occurrence at any historically managed path requires a valid
replacement RECORD introduced in that same layer, even when another layer later
removes the replacement.

RECORD input is limited to 8 MiB and 100,000 rows, and the complete historical
output is limited to 100,000 entries. Paths are canonicalized inside
`/opt/venv`; aliases, escapes, non-regular targets, malformed CSV, and conflicting
occurrence identities fail collection. Every `.pyc` or `.pyo` occurrence under
`/opt/venv` fails even if a later whiteout hides it. Effective bytecode under
`/usr/local/lib/python3.14/` also fails.

This replay establishes file attribution and executable-byte correspondence. It
does not expand embedded native components or supply their corresponding
source. Source completeness therefore remains false.

### CPython runtime identity and source binding

The normalized component inventory contains exactly one effective
`runtime:cpython@3.14.6` record per platform, with package URL
`pkg:generic/python@3.14.6`. The record binds four effective, root-owned
filesystem identities from one reviewed base layer:

- `usr/local/include/python3.14/patchlevel.h`, whose bounded constants identify
  the exact final runtime version
- `usr/local/bin/python3`, a mode-`0777` symbolic link whose target is exactly
  `python3.14`
- `usr/local/bin/python3.14`, whose ELF header must match the selected platform
- `usr/local/lib/libpython3.14.so.1.0`, whose ELF header must match the same
  platform.

The policy binds those per-platform file occurrences to the reviewed initial
base-layer sequence. It also ties the readable base tag to one commit-pinned
Docker Official Python recipe. That recipe's one literal version and source
hash must select the configured CPython archive.

Bundle generation downloads that exact archive and checks its size and
SHA-256. It requires one regular source-carried `LICENSE` member and one regular
`Include/patchlevel.h` member with their reviewed digests. The source
`patchlevel.h` digest must equal the version-header digest in both platform
runtime baselines. The bounded macro parser then confirms the version and final
release state over those source-identical bytes. The bundle retains the archive
and license bytes alongside the recipe. The reviewed license expression remains
a policy judgment, not a legal-compliance determination.

This evidence closes the CPython normalization part of issue `#18`. It does not
close the remaining native-wheel and embedded-SBOM component/source work, and
it does not approve distribution.

### Structured native and SBOM identities

Path and hash baselines show that a payload changed, but they do not say what
the bytes contain. The collector therefore parses every embedded CycloneDX JSON
SBOM under a wheel's `.dist-info/sboms/` directory. It accepts specification
versions 1.4 through 1.6, flattens nested components into canonical
type/name/version/package-URL identities, and rejects conflicting identity or
package-URL mappings within each SBOM. Identities remain scoped to their source
document across wheels: independent builders can describe the same display
identity with different package-URL namespaces. The exact SBOM bytes, path,
digest, and `RECORD` owner preserve both observations without treating either
document as a global identity authority.

The collector also identifies every ELF payload anywhere under `/opt/venv`,
including an executable without a shared-library suffix. It requires a
64-bit, little-endian ELF header whose machine matches the image platform:
x86-64 for `linux/amd64` and AArch64 for `linux/arm64`.

Each structured SBOM or ELF record retains its raw layer occurrence and the
wheel owner established by historical `RECORD` replay. Reviewed policy still
pins the raw path, digest, size, mode, UID, and GID. These identities make the
known native and SBOM surfaces inspectable; they do not yet add their nested
components to notices or retain corresponding source.

CI uploads the artifact even after a collection failure when any partial files
exist. That upload is diagnostic only: the required collection step still
fails the job, and an absent artifact does not become success.
Run metadata is written immediately after inventory collection and before
policy verification, so a policy-drift artifact still identifies its exact
workflow context. A collector failure before inventory completion can remain
partial.

The all-layer inventory preserves raw directory and whiteout headers for
forensic review. Policy comparison uses their filesystem effects instead of
requiring one exporter-specific tar encoding. Re-emitting an inherited
directory with the same type, owner, group, and mode has no security effect and
is omitted from the canonical policy view. Creating a directory, changing its
security metadata, replacing another file type, or recreating a removed path
remains an exact reviewed effect. A whiteout's marker permissions do not enter
the resulting filesystem; its kind, path, target, and removal semantics do.
Missing, extra, malformed, or no-op removals fail.

This distinction does not discard evidence. Raw headers and layer digests stay
in `all-layer-files.json`, and every post-base directory header must still be
root-owned with mode `0755`. The canonical replay only removes differences that
produce the same validated filesystem state across trusted Docker/OCI
exporters.

The two artifact names expose architecture, synthetic merge SHA, and run
attempt before their ZIP bytes are parsed. Maintainer review downloads the raw
ZIPs through the REST API, matches their API-reported size and SHA-256, removes
the GitHub credential, and then uses the previously reviewed bounded helper in
an offline VM. That helper requires the exact pinned upload-action envelope,
validates six files per platform without opening the nested evidence tar, and
requires both platforms to share one workflow context.

## Why all layers are in scope

An OCI whiteout changes the effective filesystem. It does not erase bytes from
an already distributed lower layer. For example, the final runtime removes
system `pip`, but its metadata and implementation remain retrievable from the
base layer. Replacing Alpine's installed-package database likewise does not
remove the earlier database or package bytes. The collector therefore
inventories effective and hidden top-level Python and Alpine package records
and records every non-whiteout regular-file occurrence with its digest.

The two inventories answer different questions:

- the normalized component inventory distinguishes effective records from
  records retained only in lower layers
- the all-layer file inventory supports redistribution review and incident
  forensics.

Neither replaces a per-platform SPDX software bill of materials (SBOM).

## Source selection

The collector obtains source without executing an `APKBUILD`, `setup.py`, or
downloaded build script:

1. Alpine's installed database supplies each package origin and exact
   40-character aports commit. The policy pins the recipe-subtree archive hash.
   By default, one literal `source` block must correspond exactly, in order, to
   one literal `sha512sums` block. Local regular files are verified directly;
   other filenames are downloaded from the pinned Alpine distfiles release and
   verified with SHA-512.
2. Four reviewed Alpine recipes use source construction or a safe link that
   cannot be represented by the default parser. Each exception is bound to the
   exact origin and commit, requires a rationale, and grants only dynamic-source
   handling or an exact link path, type, and target. A link can never replace
   `APKBUILD` or a checksummed source.
3. `uv.lock` supplies immutable URLs, sizes, and SHA-256 values for installed
   top-level Python source distributions. Reviewed policy entries cover
   wheel-only and lower-layer top-level components not represented by a locked
   source distribution. This does not yet provide the nested native components
   named by wheel SBOMs or their corresponding sources.
4. The Docker Official Python recipe is pinned by commit and file hash. Its one
   literal `PYTHON_VERSION` and `PYTHON_SHA256` declaration must select the same
   CPython URL and hash recorded by policy. The source archive's exact size and
   source-carried `LICENSE` and `Include/patchlevel.h` members are pinned
   separately. The source patchlevel digest must equal both platform runtime
   header digests. The Dockerfile must use the exact reviewed base index for
   its builder and final runtime stages.
5. Recursive `git ls-tree -rz HEAD` and `git show` retain every tracked regular
   Git blob and its executable mode at the revision recorded in the image
   label. Mutable working-tree files and untracked files are not evidence.

Every fetched URL and redirect must be credential-free HTTPS. Redirects are
bounded, and `MANIFEST.json` records the complete ordered URL chain as `urls`
while retaining the requested URL as `url`. Downloads, layers, and archive
members have cumulative and per-item limits. Duplicate JSON keys, non-finite
numbers, path controls, traversal, unsafe or unexpected links, digest
mismatches, and ambiguous source metadata fail closed.

## License evidence

Observed package metadata is never overwritten. `THIRD_PARTY_NOTICES.md` shows
both observed and reviewed expressions. A component, version, architecture,
license expression, metadata hash, effective state, origin, or aports commit
change breaks the policy comparison.

A `LicenseRef-*` resolution requires an exact component set, a nonempty
rationale, and one source-carried notice path and SHA-256 for every covered
component. An unrelated file with a plausible name cannot satisfy the pin. The
current public-domain resolutions bind these exact records:

- `alpine:tzdata@2026b-r0` to
  `licenses/from-source/alpine-tzdata/061340856888-LICENSE`, SHA-256
  `0613408568889f5739e5ae252b722a2659c02002839ad970a63dc5e9174b27cf`
- `alpine:xz-libs@5.8.3-r0` to
  `licenses/from-source/alpine-xz/616a3ad264ce-COPYING`, SHA-256
  `616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8`.

The deterministic review archive normalizes member order, ownership, mode, and
timestamps. It includes checksums, canonical manifests, raw inventories, the
reviewed policy, retained top-level source, notices, and license material. Its
manifest preserves the incomplete source-coverage status. Its
`application_artifacts` record binds the source, selected wheel, selection
record, accepted launcher form, and SHA-256 and size of every one of the five
files retained under `artifacts/application/`.

## Required release architecture

The current collector parses hostile images and archives while it can also use
the network. A release job with package-write, OpenID Connect, signing, or
attestation authority must not run that combined operation. Issue `#28`
requires this bounded sequence:

```text
unprivileged pinned fetch
  -> rootless parse with no network
  -> unprivileged fetch of exact checksum-addressed distfiles
  -> rootless final bundle with no network
  -> digest and policy validation
  -> short-lived isolated publication and signing authority
```

Before those phases may publish, the implementation must also parse and retain
the components, notices, and corresponding sources named by embedded wheel
SBOMs, or replace the wheels with builds linked against separately inventoried
packages.

The parsing phases must run rootless with `--network none`, immutable inputs,
read-only mounts where practical, and explicit size limits. The first parse
emits a bounded request for checksum-addressed distfiles. A separate fetch step
retrieves only that request. The final offline parse must reproduce and validate
the complete archive before a privileged job signs or publishes anything.

The future recipient contract also requires a platform digest, archive digest,
signed predicate, and OCI attestation to agree. Identical attestations produced
by a rerun may be deduplicated; two distinct valid predicates for one platform
must fail verification.

## Trust boundary and residual risk

The review archive records what the collector observed and fetched under
reviewed policy. It is not component/source complete today. Even a future
complete archive would not prove upstream metadata is correct, identify every
copyright holder, or decide whether a delivery mechanism satisfies every
jurisdiction. Hashes protect reviewed bytes from silent mutation; they do not
make the original source trustworthy.

A maintainer must review both platforms and separately approve recipient
delivery. Qualified legal review remains necessary before a paid hosted
distribution. Keep those decisions separate from scanner results, SBOMs,
OpenSSF badges, and collector success.

Maintainers use the
[CI evidence review procedure](../how-to/review-container-evidence.md). The
[container evidence release contract](../reference/container-evidence-release-contract.md)
documents the artifacts and trust statements a future supported release must
satisfy. A runnable recipient procedure does not exist until issue #28 ships
the bounded verifier.
