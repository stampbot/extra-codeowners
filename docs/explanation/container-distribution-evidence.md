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

CI also exercises a
[raw OCI release-spine transport](../reference/release-spine-format.md). Its
unprivileged producer first downloads and verifies the selected Python proof.
Pinned Buildx and BuildKit versions then export a real two-platform candidate
to a local OCI directory without pushing it. The producer gets the trusted root
digest from the pinned build action and packs the reachable objects into a
canonical record plus an opaque byte-range file. GitHub stores those files as
separate raw artifacts. Their names bind the Python artifact ID, workflow run,
and producer run attempt.

A separate read-only job downloads each artifact by immutable ID. It checks the
provider digests, the out-of-band root digest, the record graph, and every byte
range without calling an archive parser. It does not rebuild the graph from the
opaque OCI bodies. This is still an internal transport test; it does not weaken
the publication blocker.

The spine stops at the OCI object boundary. It does not check tar members, gzip
structure, OCI diff IDs, installed files, notices, source completeness,
signatures, or attestations. The evidence collector and future isolated release
path own those checks. That release path must keep the current trust boundary:
take the root digest from the pinned build action, not from the spine record.
It must also consume only object chunks that the verifier copied from its
retained file descriptor and authenticated before returning them. It must not
reopen a verified path, and it must wait for the verifier's final
unchanged-file check before publishing a manifest, tag, release, or other
reference.

The application build has its own reproducibility proof. CI builds the package
twice on each native architecture from the hash-pinned PEP 517 closure and
requires the two architecture proofs to be byte-identical. It then selects one
exact five-file proof. Both container candidates install that selected wheel
without rebuilding it.

The reusable proof workflow also packs those five selected files into a [raw
Python-distribution
spine](../reference/python-distribution-spine-format.md) and a canonical
record. A separate read-only job downloads both raw artifacts by immutable ID,
then verifies and atomically materializes the five files without opening the
wheel or source-distribution archives.

The tagged workflow defines a privileged consumer that would attest and sign
the materialized distributions and retain the three selection records. The
unconditional publication blocker keeps that job unreachable. Its record
artifact is not an input to the GitHub release job, so the pair remains an
internal transport rather than supported release evidence.

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
SQLAlchemy have closed native-owner reviews on both platforms. Four other
owners have exact observations and explicit omissions, but their reviews remain
open.
Issue [#18](https://github.com/stampbot/extra-codeowners/issues/18) tracks that
work. Until it closes, the derived ledger keeps
`source_completeness.complete` false and the approval-required gate rejects the
candidate. Issue #28 independently blocks tagged publication. Passing CI does
not override either condition.

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
9. validates every schema-7 owner observation, disposition, review, omission,
   and cross-owner relationship; writes the derived coverage ledger; and binds
   each closed owner to its exact locked source
10. retrieves the hash-pinned source and license material, including the
    Greenlet/GCC component source and notices, and produces a deterministic
    review archive whose manifest derives the current incomplete state.

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

Path and hash baselines tell us that a file changed. They don't tell us what
the file contains, and an SBOM doesn't necessarily tell us which component
produced a file. Schema 7 keeps those facts separate.

The collector parses every CycloneDX JSON document below a wheel's
`.dist-info/sboms/` directory. It accepts specification versions 1.4 through
1.6 and retains a bounded observation for each component:

- type, name, version, and package URL (PURL)
- `bom-ref`
- declared hash records
- declared licenses

The collector rejects two hash records that name the same algorithm, even when
their spelling differs only by case. Without this check, one component could
carry the expected source digest and a conflicting digest. Source binding would
find the expected value and ignore the conflict.

The observation also has a digest over its canonical parsed content. Policy
references include that digest and the installed SBOM path, so a reference
can't drift to a similar component in another document.

#### Repeated PURLs are occurrences, not aliases

A PURL describes a package identity. It doesn't always identify one occurrence
inside a document. The Psycopg auditwheel SBOM demonstrates the difference: it
contains four `krb5` occurrences and two `libldap` occurrences. Each group
shares a PURL, but every occurrence has its own `bom-ref`.

Schema 7 uses a nonempty `bom-ref` as the document-local occurrence identity.
It falls back to the PURL only when `bom-ref` is empty. A document may repeat a
PURL only when every repetition has a unique, nonempty `bom-ref`; duplicate
`bom-ref` values and mixed fallback identities fail. This preserves the six
Psycopg observations instead of silently collapsing them into two packages.

PURLs and `bom-ref` values remain scoped to their source document. Independent
builders can use different namespaces or build paths for the same component.
The policy compares normalized review semantics across architectures without
rewriting the literal observations retained for either wheel.

#### Metadata roots need an explicit disposition

An SBOM metadata component can describe the wheel owner, an embedded component,
or a known omission. It can also be absent. Policy records that decision for
each document.

Auditwheel currently emits one narrow anomaly for the Cryptography, Greenlet,
and Psycopg wheels: the document repeats its metadata root as a canonically
identical top-level component with the same `bom-ref`. The parser accepts only
that exact echo. Policy must add a `metadata-root-echo` anomaly review with a
reason, and the coverage ledger reports it in
`observed_sbom_anomalies`. A changed or unreviewed echo fails.

#### Observation, review, and payload claims stay separate

An owner record covers every native payload and embedded SBOM in one wheel.
Each native payload has an exact installed path, digest, size, and a
platform-neutral role derived from its path. Every payload then receives one
disposition:

- `owner` for code treated as part of the Python project
- `sbom-components` for a payload associated with cited SBOM occurrences
- `known-omission` when the needed provenance is still missing

A `known-omission` disposition names one omission, and that exact omission must
list the affected observation or payload role. The validator does not treat
unrelated omissions as a shared pool of exceptions.

A component review cites exact observation occurrences, an immutable source
record, and the project's reviewed license expression. The SBOM's declared
license remains in the observation. These are two different facts.

The schema does not invent a component-to-file relationship. Auditwheel may
list `libgcc` and `libstdc++` without mapping either component to a path, hash,
or SONAME. A payload disposition can say which observations are relevant to
the payload, but the retained SBOM still shows the limits of the upstream
claim.

Schema 7 has one deliberately narrow relationship for evidence shared between
owners. `same-component-by-payload-equivalence` requires the source and target
payloads to be byte-identical. Each named payload disposition must cite its
corresponding observation, and the target observation must have a direct
review in a closed owner. Relationships cannot chain. The current policy uses
this for Cryptography's bundled `libgcc`, whose bytes match Greenlet's reviewed
`libgcc` payload.

#### Sources are verified by kind

Native component sources form a tagged union. The collector supports:

- a commit-pinned Alpine aports recipe plus every checksummed distfile
- a crates.io archive bound to its manifest identity, checksum, raw license,
  normalized license, and reviewed notices
- a canonical, link-free subtree manifest inside the wheel owner's exact
  source distribution
- an upstream release archive bound to a pinned checksum document with one
  exact filename record

Every used source retains its exact reviewed notices. Unused source records
fail policy validation, so adding a source without connecting it to a review
doesn't create evidence.

Rust source closure has one additional check. A crates.io review must include
the exact `Cargo.lock` member from the owner's retained sdist, its hash and
size, the sorted crates.io source IDs represented by SBOM observations, and
the exact registry packages found only in the lockfile. Bundle generation
reparses the retained lockfile. It rejects missing or duplicate packages,
foreign registries, checksum drift, unaccounted registry packages, and local
Cargo packages that do not match reviewed owner-sdist observations.

This proves agreement among the SBOM, lockfile, registry archive, manifest,
license, and notices. It does not prove that those sources built the wheel.

#### Open and closed are policy states

Every observed native-wheel owner must have a record on both platforms. An
owner with complete dispositions and source evidence can be `closed`. An
`open` owner must list known omissions, a reason, and the same omission IDs in
`review.unresolved_items`. Removing an owner from policy fails exact coverage;
it does not turn the owner into an inferred unresolved record.

The current closed owners are Greenlet, MarkupSafe, and SQLAlchemy. MarkupSafe
and SQLAlchemy have no embedded SBOM, so their SBOM and component-review arrays
are empty while their native payload sets remain exact.

Four owners are still open:

- CFFI has no embedded native-component inventory, and its upstream build did
  not record the digest of the libffi 3.4.6 source it downloaded.
- Cryptography still needs complete Rust and OpenSSL source, license, notice,
  and build-material evidence.
- Psycopg still lacks a `libpq` SBOM observation and reviewed source closure
  for its bundled libraries.
- Pydantic Core still lacks a `libgcc` observation and retained source closure
  for the crates represented by its SBOM. Its bundled `libgcc` identifies GCC
  12.4.0, not the reviewed Alpine GCC 14.2 payload used by other owners.

`inventory/native-component-coverage.json` copies closed records into
`resolved_owners` and open records into `unresolved_owners`. It also names the
remaining owners and reports reviewed upstream SBOM anomalies.
`MANIFEST.json` derives `source_completeness` from that ledger. The component
inventory no longer supplies a completeness assertion that policy could
accidentally trust.

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
pin. Schema 7 rejects `LicenseRef-*` in native-component expressions
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

Before those phases may publish, the other four native-wheel owners must move
from `open` to `closed`, or those wheels must be replaced with builds linked
against separately inventoried packages.

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
