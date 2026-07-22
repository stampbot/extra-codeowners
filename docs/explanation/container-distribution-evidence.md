# How container distribution evidence works

An Extra CODEOWNERS image contains more than the project's Apache-2.0 source.
It also distributes CPython, locked Python packages, Alpine packages, and bytes
that later OCI layers may hide. The evidence system records that whole set so a
maintainer can inspect it. Evidence is not a legal-compliance determination.

## Where the project stands

Pull-request CI produces useful review evidence, but Extra CODEOWNERS does not
publish a supported container image yet.

| Surface | Current state |
| --- | --- |
| Pull-request candidates | CI builds separate `linux/amd64` and `linux/arm64` images and uploads one short-lived, unsigned evidence archive for each. |
| Evidence subject | Each CI archive names its local image configuration digest because CI does not publish a platform manifest. |
| Public `main` image | Disabled; the publication job has been removed. |
| Tagged release | Blocked before any job can publish an image, chart, Python package, or GitHub release. |
| Source closure | CPython, Greenlet, MarkupSafe, and SQLAlchemy are resolved on both platforms; four native-wheel owners remain incomplete. |

The release workflow can still validate source, build proof, and scan a
candidate with repository-read permission. A separate job then fails before
the privileged publication jobs can run. Changing
`distribution_approval.approved` to `true` cannot bypass that structural stop.
Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
privilege-separated release implementation.

The application build has its own reproducibility proof. CI builds the package
twice on each native architecture from the hash-pinned PEP 517 closure and
requires the two architecture proofs to be byte-identical. It then selects one
exact five-file proof. Both container candidates install that selected wheel
without rebuilding it.

Stable OCI labels bind the source revision, wheel SHA-256, and selection-record
SHA-256. Run metadata separately binds the GitHub Actions artifact ID and
archive digest. The run-scoped identity stays out of the image labels, so a
rerun does not change the image bytes for that reason. The reusable proof
workflow also supports read-only manual runs, and the tagged candidate scan
uses only the proof built in its own run. Issue
[#32](https://github.com/stampbot/extra-codeowners/issues/32) tracks retention
of that proof in release evidence and its handoff to the future isolated
publication path.

CPython has a normalized top-level component record with exact runtime
identity, recipe, source, and license evidence. Greenlet, MarkupSafe, and
SQLAlchemy now have closed-world native-owner coverage on both platforms. Four
other owners do not yet have complete records for their observed surfaces.
Issue [#18](https://github.com/stampbot/extra-codeowners/issues/18) tracks that
work. Until it closes, the collector sets `source_completeness.complete` to
`false` and rejects distribution approval. Issue #28 independently blocks
tagged publication. Passing CI does not override either condition.

## How the CI collector builds the evidence

The collector saves the candidate by immutable configuration ID. Before it
interprets the image, it checks the SHA-256 name of the saved configuration and
every layer against the bytes it received. It then:

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
8. selects one hash-locked platform wheel for each native or SBOM owner,
   verifies its complete archive `RECORD` against the historical installation,
   and retains the wheel and raw SBOM bytes under `artifacts/native-wheels/`
9. validates the closed-world native-component policy, writes a per-owner
   coverage ledger, and binds each resolved owner to its exact locked source
10. retrieves the hash-pinned source and license material, including the
    Greenlet/GCC component source and notices, and produces a deterministic,
    explicitly incomplete review archive.

### Historical Python installation replay

For each layer, the collector applies every whiteout before ordinary entries,
then evaluates the completed layer snapshot. Tar member order cannot make an
incomplete installation appear valid. Every newly introduced virtual-environment
`RECORD` must bind regular METADATA, WHEEL, and RECORD occurrences and every
normalized path it claims. The component inventory retains that relationship in
`wheel_installations` with:

- a canonical owner such as `python:demo@1.0`
- the exact METADATA, WHEEL, and RECORD occurrence identities
- the exact wheel build tag, normalized tags, and `Root-Is-Purelib` state
- each normalized RECORD entry, its declared digest and size, and the exact
  layer occurrence it owned.

The historical list remains after a later whiteout; each retained occurrence
still reports whether it is effective in the final filesystem. The existing
`python_record_ownership` array is the effective-only compatibility view.
Active installations cannot repeat an owner or claim the same path. A later
regular-file occurrence at any historically managed path requires a valid
replacement RECORD introduced in that same layer, even when another layer later
removes the replacement.

Native-wheel retention is narrower: an owner must have exactly one historical
installation. The collector rejects a reinstall of the same owner instead of
guessing which installation supplied the redistributed bytes, even when both
versions match. Supporting reinstallations will require an explicit selection
and proof rule.

RECORD input is limited to 8 MiB and 100,000 rows, and the complete historical
output is limited to 100,000 entries. Paths are canonicalized inside
`/opt/venv`; aliases, escapes, non-regular targets, malformed CSV, and conflicting
occurrence identities fail collection. Every `.pyc` or `.pyo` occurrence under
`/opt/venv` fails even if a later whiteout hides it. Effective bytecode under
`/usr/local/lib/python3.14/` also fails.

This replay establishes which wheel owns each file occurrence and whether the
installed executable bytes match the wheel. The native-component ledger uses
that ownership to review one complete wheel at a time. It does not infer which
source or nested SBOM component produced an individual file. Greenlet,
MarkupSafe, and SQLAlchemy are resolved; four other owners still lack
corresponding-source closure, so overall source completeness remains false.

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
approve distribution.

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
pins the raw path, digest, size, mode, UID, and GID. Bundle generation now
selects that owner's exact platform wheel from `uv.lock`, verifies its complete
archive `RECORD`, and matches its installed files to the historical record.
The bundle keeps the wheel and a separately addressed copy of every raw SBOM.

This proves which wheel supplied the bytes. Schema 6 adds closed-world coverage
for individual wheel owners. Every owner record carries explicit
`native_payloads`, `sboms`, and owner-level `components` sets. At least one
native or SBOM surface must exist. The component set must be the canonical
union of the components represented by the SBOM records. Empty sets are valid
evidence; omitted sets are not. Missing, extra, duplicated, cross-platform,
conflicting, or stale records fail.

Those are parallel evidence sets, not a file-provenance map. Greenlet's
auditwheel SBOM lists `libgcc` and `libstdc++` identities and dependencies, but
it contains no relationship from either component to a file path, file hash, or
SONAME. The schema therefore keeps all five native files in one owner-level
`native_payloads` set. It deliberately has no owner-source payload field and no
component payload field. The exact Greenlet sdist proves the reviewed owner's
source selection; it does not explain any individual native file. Likewise,
the nested component source and license records review the SBOM identities
without claiming that a particular file came from either component.

Installed filenames still vary by architecture. Wheel repair can add a
platform-specific hash, and a CPython extension filename includes the target
architecture. The validator derives each role from its exact path: it removes
the reviewed virtual-environment `site-packages` prefix, collapses the CPython
platform ABI suffix, and removes a valid auditwheel filename hash. Every other
part of the relative path remains unchanged. A policy cannot move a role to a
different path, even if its overall role set stays the same. Schema validation
also requires both platforms to contain the same derived role set. This path
projection compares files; it does not attribute them to a source or SBOM
component.

The same validation gives every package URL one global normalized identity,
source, and reviewed license across resolved owners and SBOMs.

Greenlet is the first resolved owner. On each platform, the reviewed wheel
contains three extension modules, two libraries under `greenlet.libs/`, and one
auditwheel SBOM. The policy separately binds the Greenlet 3.5.3 sdist and an
Alpine GCC source record for the SBOM's `libgcc` and `libstdc++` components. The
GCC record pins:

- Alpine aports commit `fbf60319be3bbaf6dd32ef55cc6fb7189e05c266`
- the exact `main/gcc` recipe-subtree archive
- the recipe's literal version, package release, and aggregate license field
- the recipe-selected `gcc-14.2.0.tar.xz` distfile by size and SHA-512
- the SHA-256 and size of `COPYING3` and `COPYING.RUNTIME` in that archive.

The SBOM does not declare license expressions for those nested components. The
policy records `GPL-3.0-or-later WITH GCC-exception-3.1` as the project's
reviewed expression and separately preserves the aggregate license text from
`APKBUILD`. The evidence does not present that review as upstream metadata or
legal advice.

MarkupSafe is the second resolved owner. Each platform wheel has one
`_speedups` extension and no embedded SBOM. The policy binds that one native
role, its exact platform path and digest, the exact locked wheel, and the
80,313-byte MarkupSafe 3.0.3 sdist. Its `sboms` and owner-level `components`
sets are explicitly empty. That closes the observed wheel surface without
inventing a component or build claim. The sdist and its BSD-3-Clause license
files are retained as exact source evidence; they do not prove that every byte
in the extension was reproducibly produced from that archive.

SQLAlchemy is the third resolved owner. Each platform wheel contains five
`cyextension` modules and no embedded SBOM or separately packaged native
library. Every module's dynamic section names only the platform musl runtime.
The policy binds all five paths, roles, and digests to the exact locked wheel
and the 9,912,201-byte SQLAlchemy 2.0.51 sdist. Its `sboms` and `components`
sets are explicitly empty.

The sdist carries the five project-authored `.pyx` files, one supporting
`.pxd`, no generated C source, and no separately attributable bundled
third-party native code. The collector retains that exact sdist and its MIT
license. The owner-level component set remains empty because SQLAlchemy's wheel
has no embedded SBOM; schema 6 derives the set from embedded SBOM components.
Cython and GCC are build tools, not distributed SQLAlchemy components. Musl
remains independently inventoried as part of the platform. This evidence does
not prove that the wheels are reproducible or close the compiler toolchain.

The derived `inventory/native-component-coverage.json` file repeats every
resolved record and lists the raw native and SBOM observations for unresolved
owners. Greenlet, MarkupSafe, and SQLAlchemy are resolved on both platforms.
Four owners remain unresolved, so source completeness remains false.

### Failed jobs can still leave diagnostics

CI uploads the artifact even after a collection failure when any partial files
exist. That upload is diagnostic only: the required collection step still
fails the job, and an absent artifact does not become success.
Run metadata is written immediately after inventory collection and before
policy verification, so a policy-drift artifact still identifies its exact
workflow context. A collector failure before inventory completion can remain
partial.

### Policy compares filesystem effects

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

### Artifact names expose the workflow identity

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
   source distribution. For a resolved native owner, the lock's wheel and sdist
   records must also equal the owner's coverage policy exactly.
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
6. A resolved Alpine-built component uses its own source record rather than the
   final image's Alpine baseline. The record pins the builder's distfiles
   release, a commit-addressed recipe subtree, every nonlocal recipe checksum,
   the exact source archive, and selected source-carried notices. This is how
   the Greenlet wheel's Alpine 3.22 build provenance remains separate from the
   Alpine 3.24 runtime image.

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

A top-level `LicenseRef-*` resolution requires an exact component set, a
nonempty rationale, and one source-carried notice path and SHA-256 for every
covered component. An unrelated file with a plausible name cannot satisfy the
pin. Schema 6 rejects `LicenseRef-*` in native-component expressions
because those components do not use the top-level custom-license evidence
ledger. The current public-domain resolutions bind these exact records:

- `alpine:tzdata@2026b-r0` to
  `licenses/from-source/alpine-tzdata/061340856888-LICENSE`, SHA-256
  `0613408568889f5739e5ae252b722a2659c02002839ad970a63dc5e9174b27cf`
- `alpine:xz-libs@5.8.3-r0` to
  `licenses/from-source/alpine-xz/616a3ad264ce-COPYING`, SHA-256
  `616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8`.

Nested native components keep a reviewed expression without `LicenseRef-*` in
the coverage record and retain their reviewed source notices. Greenlet's
`libgcc` and `libstdc++` entries share the exact GCC source and its retained
`COPYING3` and `COPYING.RUNTIME` bytes. `THIRD_PARTY_NOTICES.md` puts those
components in a separate table so a reader can see that the SBOM declared no
license while the project review selected an expression.

The deterministic review archive normalizes member order, ownership, mode, and
timestamps. It includes checksums, canonical manifests, raw inventories, the
reviewed policy, retained top-level source, notices, and license material. Its
manifest preserves the incomplete source-coverage status and embeds the same
ledger written to `inventory/native-component-coverage.json`. Its
`application_artifacts` record binds the source, selected wheel, selection
record, accepted launcher form, and SHA-256 and size of every one of the five
files retained under `artifacts/application/`.

## Why release collection needs a different boundary

The CI collector parses hostile images and archives in a job that can also use
the network. That job has no publication authority. A release job with
package-write, OpenID Connect, signing, or attestation authority must never run
the combined operation. Issue #28 requires this bounded sequence:

```text
unprivileged pinned fetch
  -> rootless parse with no network
  -> unprivileged fetch of exact checksum-addressed distfiles
  -> rootless final bundle with no network
  -> digest and policy validation
  -> short-lived isolated publication and signing authority
```

Before those phases may publish, the same closed-world coverage now used for
Greenlet, MarkupSafe, and SQLAlchemy must cover the other four native-wheel
owners, or those wheels must be replaced with builds linked against separately
inventoried packages.

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
reviewed policy. Greenlet, MarkupSafe, and SQLAlchemy are closed, but four
native-wheel owners are not, so the archive is not component/source complete
today. Even a future complete archive would not prove upstream metadata is
correct, identify every copyright holder, or decide whether a delivery
mechanism satisfies every jurisdiction. Hashes protect reviewed bytes from
silent mutation; they do not make the original source trustworthy.

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
