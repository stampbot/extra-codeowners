# Container evidence policy reference

`.compliance/container-policy.json` is the exact reviewed allowlist for image
components, licenses, sources, base layers, and post-base filesystem effects.
Use this reference when a container build or policy update changes that file.
It is not configuration for the running GitHub App.

The collector rejects missing and unknown fields at every schema boundary. It
then compares either the raw observed records or the documented canonical
security projection exactly. An invented permissive field cannot weaken the
comparison; the schema rejects it.

!!! warning "Policy approval cannot enable publication"
    Setting `distribution_approval.approved` to `true` does not make the
    current evidence source-complete and does not bypass the release workflow's
    structural publication block.

The enforcement code is in `.github/scripts/container_evidence.py`, especially
`validate_policy_schema`, `verify_inventory`,
`native_component_coverage_ledger`,
`verify_base_layer_binding`, `canonical_post_base_filesystem_changes`,
`verify_post_base_filesystem_policy`, `verify_post_base_provenance`, and
`validate_source_policy_coverage`. Adversarial loader and policy tests are in
`tests/test_container_evidence.py`.

## Common types and limits

The current schema version is integer `6`. JSON must be UTF-8, no larger than
64 MiB, no deeper than 64 containers, and must not contain duplicate object
keys, floating-point values, non-finite numbers, or invalid Unicode. Unless a
field says otherwise, every object has exactly the listed keys.

| Name | Contract |
| --- | --- |
| `platform` | Exactly `linux/amd64` or `linux/arm64`. Both keys are required wherever policies are platform-indexed. |
| `sha256` | 64 lowercase hexadecimal characters, without a prefix. |
| `qualified_sha256` | `sha256:` followed by 64 lowercase hexadecimal characters. |
| `git_sha` | 40 lowercase hexadecimal characters. |
| `path` | Canonical relative POSIX path, at most 4,096 UTF-8 bytes; no empty, `.`, `..`, backslash, absolute, repeated-separator, or control-character component. |
| `role` | Deterministic platform-neutral projection of a native payload's exact `site-packages` path; it has the same canonical-path syntax and limit as `path`. |
| `https_url` | Credential-free HTTPS URL with a valid hostname and port and no control characters; redirects are separately limited to five. |
| `mode` | Integer from `0` through `07777`; booleans are invalid. |
| `uid`, `gid` | Integer from `0` through `2^31 - 1`; booleans are invalid. |
| component list | At most 10,000 exact component records. |
| occurrence list | At most 250,000 exact layer occurrence records. |
| source or payload size | Integer from `0` through 64 MiB unless the field says otherwise; booleans are invalid. Native-component distfiles may be at most 128 MiB. |
| component scalar | UTF-8 text bounded to 512 encoded bytes unless the validator applies a narrower identity grammar. |
| component identity key | UTF-8 text bounded to 1,056 encoded bytes; it combines two component scalars with ecosystem separators. |
| license scalar | UTF-8 text bounded to 16,384 encoded bytes. |

## Top-level object

The policy has exactly these fields:

| Field | Type | Meaning | Consuming gate |
| --- | --- | --- | --- |
| `schema_version` | integer | Policy schema; exactly `6`. | Every command through `validate_policy_schema`. |
| `base_image` | string | Nonempty bounded Dockerfile base reference; the schema rejects whitespace and `@`. The checked-in value is a tagged Docker Official Python reference. | Exact Dockerfile binding during `bundle` and `verify-ci-policy`. |
| `base_image_index_digest` | `qualified_sha256` | Reviewed multi-platform base index. | Schema validation during `verify`; exact Dockerfile/index binding during `bundle` and `verify-ci-policy`. |
| `base_image_platforms` | platform object | Exact ordered base layer diff IDs for both platforms. | Base-prefix and post-base provenance gates. |
| `platforms` | platform object | Exact normalized component list for each platform. | `verify` and `bundle`. |
| `distribution_approval` | object | Separate human decision about recipient distribution. | Required only when `--require-distribution-approval` is set. |
| `license_resolutions` | object | Reviewed expression and rationale for every exact component identity. | Inventory verification, notices, and bundle generation. |
| `license_texts` | array | Hash-pinned standard license texts required by reviewed expressions. | Inventory coverage and bundle fetch. |
| `custom_license_evidence` | object | Exact source-carried notice pins for every top-level `LicenseRef-*`. | Inventory coverage and retained-license verification. |
| `unexpanded_python_payloads` | platform object | Exact raw wheel SBOM, native, and identity-file occurrences. Some owners may also have closed-world coverage. | `verify`; any drift fails. |
| `native_component_sources` | object | Immutable recipe, distfile, and notice records for native components nested inside wheels. | Schema, recipe, source-retention, and notice gates. |
| `native_component_coverage` | platform object | Exact owner-level native payload set plus exact wheel, owner source, and embedded-SBOM component/source/license records. | `verify`, lock binding, coverage ledger, notices, and bundle generation. |
| `filesystem_baselines` | platform object | Exact APK database history plus canonical post-base directory effects and removals. | Deep `bundle` provenance verification and offline CI policy review. |
| `docker_python_recipe` | object | Pinned Docker Official Python recipe and license. | Bundle fetch and CPython binding. |
| `cpython_source` | object | Pinned CPython source archive and source-carried identity evidence. | Bundle fetch, recipe binding, and runtime/source identity binding. |
| `python_sources` | array | Pinned fallback sources for components absent from `uv.lock`. | Exact source-coverage and bundle gates. |
| `alpine_distfiles_release` | string | Alpine distfiles release in `vMAJOR.MINOR` form. | Alpine source fetch. |
| `alpine_recipe_archives` | object | Exact `ORIGIN@APORTS_COMMIT` to recipe-subtree SHA-256 mapping. | Exact source-coverage and bundle gates. |
| `alpine_recipe_exceptions` | object | Narrow parser exceptions for a subset of pinned recipes. | Schema validation and recipe parse. |

There is no policy field for a base manifest digest, base configuration digest,
or paid-hosting legal review. The ordered base diff IDs are the consumed
platform binding. Legal review for a paid hosted service is an external launch
decision and cannot be represented by setting an unused JSON field.

## Base image records

`base_image_platforms` has exactly two platform keys. Each value is:

| Field | Type | Constraint |
| --- | --- | --- |
| `layer_diff_ids` | nonempty array of unique `qualified_sha256` values | Exact initial `rootfs.diff_ids` sequence for the reviewed platform base. |

The collector requires the final image's ordered layers to start with this
sequence. Every later regular file, directory, link, and whiteout is then
subject to the post-base provenance gate.

## Component records

`platforms[PLATFORM]` is an array with unique
`ECOSYSTEM:NAME@VERSION` identities.

A Python record has exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `ecosystem` | string | Exactly `python`. |
| `name` | string | Canonical Python distribution name. |
| `version` | string | Canonical PEP 440 version. |
| `observed_license` | string | Bounded upstream metadata; may be empty. |
| `effective` | boolean | Whether this metadata record survives in the final filesystem. |
| `metadata_sha256` | `sha256` | Digest of the exact installed `METADATA` file. |

An Alpine record has exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `ecosystem` | string | Exactly `alpine`. |
| `name` | string | Valid non-virtual APK package name. |
| `version` | string | Exact installed APK version. |
| `architecture` | string | APK architecture matching the selected image platform. |
| `observed_license` | string | Bounded installed-package license field. |
| `origin` | string | Valid nonempty aports origin. |
| `aports_commit` | `git_sha` | Exact immutable source commit from installed metadata. |
| `effective` | boolean | Whether this package database record remains effective. |

The CPython runtime record has exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `ecosystem` | string | Exactly `runtime`. |
| `name` | string | Exactly `cpython`. |
| `version` | string | Exactly the checked-in runtime version, currently `3.14.6`. |
| `purl` | string | Exactly `pkg:generic/python@3.14.6`. |
| `observed_license` | string | Empty because the image has no authoritative installed-package license field for the runtime. |
| `effective` | boolean | Exactly `true`. |
| `identity_files` | object | Exactly `version_header`, `interpreter_link`, `interpreter`, and `shared_library`. |

The version header, interpreter, and shared library are exact effective
regular-file occurrences with layer, path, SHA-256, size, mode, UID, and GID.
The interpreter link is one exact effective symbolic-link occurrence with
layer, path, target, mode, UID, and GID. All four identities must be root-owned
and come from one reviewed base layer. The version header is mode `0644`; the
link is mode `0777`; and the interpreter and shared library are mode `0755` with
an exact 64-bit, little-endian ELF identity for the selected architecture. The
required identities are:

| Role | Path | Additional constraint |
| --- | --- | --- |
| `version_header` | `usr/local/include/python3.14/patchlevel.h` | Exact regular file. |
| `interpreter_link` | `usr/local/bin/python3` | Symbolic link whose target is exactly `python3.14`. |
| `interpreter` | `usr/local/bin/python3.14` | Exact regular file with platform ELF identity. |
| `shared_library` | `usr/local/lib/libpython3.14.so.1.0` | Exact regular file with platform ELF identity. |

Each platform contains exactly one runtime record. Its name, version, and
package URL must agree across platforms; occurrence hashes and ELF machine
identities remain platform-specific.

The two platform arrays are independently exact. A record retained only in a
lower OCI layer remains in policy with `effective: false`.

## Distribution approval

`distribution_approval` has exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `approved` | boolean | Must remain `false` while source completeness is false. |
| `approved_by` | string | Nonempty when approval is required. |
| `approved_on` | string | Nonempty when approval is required; use an unambiguous date in review. |
| `rationale` | string | Always nonempty. |

Approval is necessary but not sufficient. The collector also requires the
inventory's exact complete-source status. Current code keeps `complete: false`
while four native-wheel owners remain unresolved under issue #18, so the
approval-required gate cannot pass. Issue #28 independently keeps publication
authority out of the collector. Issue #32 still requires the selected
application proof to reach release evidence and the future publication jobs.

## License policy

`license_resolutions` is keyed by every exact component identity. Each value
contains only `expression` and nonempty `rationale`, both strings. Its key set
must equal the selected platform's component identities.

The checked-in `runtime:cpython@3.14.6` resolution is provisionally
`Python-2.0.1`, reflecting the CNRI 1.6.1 terms in the current composite
license. Policy pins the
[exact SPDX `Python-2.0.1` text](https://raw.githubusercontent.com/spdx/license-list-data/421fbabbe80c94c58c12316af1bc6a2dca2362bc/text/Python-2.0.1.txt)
at commit `421fbabbe80c94c58c12316af1bc6a2dca2362bc` with SHA-256
`1d165c0d255094285fe6ce754b431b9efc1e7df547db4aed5c3b3d082e5d5aaa`.
Bundle generation separately retains CPython's exact source-carried `LICENSE`,
which also contains license history and a 0BSD notice. That complete retained
file remains the authoritative evidence. Neither the provisional SPDX
resolution nor collector success is distribution approval or a legal
determination.

`license_texts` contains objects with exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `id` | string | Standard identifier using letters, digits, `.`, `+`, or `-`; unique across the array. |
| `url` | `https_url` | Immutable standard text location. |
| `sha256` | `sha256` | Exact text bytes. |

The ID set must equal every non-operator, non-`LicenseRef-*` token required by
the reviewed top-level and resolved native-component expressions. Schema 6
does not allow `LicenseRef-*` in a nested native-component expression. The
Greenlet closure therefore adds the pinned SPDX `GCC-exception-3.1` text
alongside the existing `GPL-3.0-or-later` text.

`custom_license_evidence` is keyed by every and only `LicenseRef-*` identifier
in the top-level `license_resolutions`. Each value contains exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `components` | array of strings | Unique exact component keys; set must equal components using this identifier. |
| `evidence` | object | Same component-key set; each value has only canonical `path` and `sha256`. |
| `rationale` | string | Nonempty. |
| `require_source_notice` | boolean | Exactly `true`. |

Bundle generation must actually retain the pinned path and digest from the
corresponding component source. A plausible notice from another component does
not satisfy the record.

## Exact payload and filesystem baselines

`unexpanded_python_payloads` has both platform keys. Each platform value has
exactly `embedded_sboms`, `native_payloads`, and `wheel_identity_files`. Every
array uses these regular-file occurrence fields:

| Field | Type |
| --- | --- |
| `effective` | boolean |
| `layer` | nonnegative integer |
| `path` | canonical `path` |
| `sha256` | `sha256` |
| `size` | integer from `0` through 64 MiB |
| `mode` | `mode` |
| `uid`, `gid` | bounded integer |

An occurrence identity is `(layer, path)` and may appear only once per array.
Component-inventory records for `embedded_sboms` and `native_payloads` add a
validated wheel owner plus a `cyclonedx` or `elf` identity. Policy comparison
uses the raw occurrence fields above after the collector validates those added
fields and binds the occurrence to historical RECORD ownership.

The component inventory retains this raw `wheel_identity_files` array as well
as `wheel_installations`. They are not interchangeable: the raw array also
covers base-image identities such as system `pip` WHEEL and RECORD files outside
`/opt/venv`, while installation replay covers wheel ownership inside the runtime
virtual environment. These baselines make known incomplete surfaces visible;
the separate coverage policy says which owners have been resolved.

Each `wheel_installations` record preserves the exact WHEEL build tag as well
as its tags and `Root-Is-Purelib` value. Bundle generation uses those fields to
select one platform wheel from `uv.lock`; a merely compatible wheel is not an
acceptable substitute.

For native-wheel retention, an owner must appear in exactly one historical
installation record. Repeated installation of the same owner fails closed;
there is no last-match or effective-file fallback.

## Native-component closure

`native_component_coverage` has both platform keys. The two sorted arrays must
name the same owner set. An owner record has exactly:

| Field | Contract |
| --- | --- |
| `owner` | Canonical `python:NAME@VERSION`, unique on the platform. |
| `wheel` | Exact credential-free HTTPS URL, SHA-256, and positive size of the platform wheel. The filename must identify that owner and a supported CPython 3.14 musllinux tag for the platform. |
| `owner_source` | Exact URL, SHA-256, and size of the owner's source archive. Bundle generation requires byte-for-byte equality with the `uv.lock` sdist record. |
| `native_payloads` | Sorted, unique `role`, `path`, and `sha256` records for every native file owned by the wheel. The set may be empty and is not attributed to `owner_source` or an SBOM component. |
| `sboms` | Sorted embedded-SBOM records attributed to this owner. The set may be empty but must be present. |
| `components` | Canonical owner-level set of reviewed embedded components. It must equal the union represented by `sboms[].components`, including an explicit empty set when the wheel has none. |

An owner must expose at least one native payload or embedded SBOM. An owner with
all three sets empty is invalid. Each SBOM record pins its installed `path` and
`sha256`. Its `components` list may be empty and must exactly equal the
canonical component projection parsed from those SBOM bytes. A component
contains its CycloneDX `type`, `name`, `version`, and `purl`, plus:

- `source`: one key from `native_component_sources`
- `reviewed_license`: the project's reviewed expression; `LicenseRef-*` is
  prohibited, and the value does not rewrite or imply an upstream SBOM
  declaration

`role` is computed from `path`, not chosen independently. The projection:

1. removes the exact
   `opt/venv/lib/python3.14/site-packages/` prefix
2. changes a matching
   `.cpython-314-{x86_64|aarch64}-linux-musl.so` suffix to
   `.cpython-314.so`, rejecting an architecture that conflicts with the policy
   platform
3. removes a valid auditwheel `-HASH` filename segment before
   `.so[.VERSION...]`, where `HASH` is exactly eight lowercase hexadecimal
   characters
4. otherwise retains the canonical relative path unchanged.

When an auditwheel `.libs` basename contains an all-hexadecimal hash segment,
any other length or uppercase form is invalid. The declared role must equal the
derived value. Roles and paths are unique within `native_payloads`, and both
platform records must contain the same role set. This projection prevents a
role/path swap; it does not attribute the payload to `owner_source` or an SBOM
component.

Matching owner records on the two platforms must also use the same
`owner_source`, owner-level `components` set, and logical SBOM set. The logical
SBOM comparison binds each installed SBOM path and its component set while
allowing the platform-specific SBOM digest to differ. Architecture-specific
wheel pins, payload paths, and payload digests may differ. An empty native,
SBOM, or component set is still part of this comparison; it cannot silently
become nonempty on the other platform.

For a resolved owner, `native_payloads` must equal that owner's complete native
payload inventory by path and digest. Its configured SBOM path/hash set and
each SBOM's component projection must also match the inventory exactly.
Missing, extra, stale, cross-platform, duplicate, or conflicting records fail.
Every configured source must be used; an unreferenced source is an error.
Across all owners, SBOMs, and platforms, one package URL must map to one exact
normalized `type`, `name`, and `version` identity, source ID, and reviewed
license.

The evidence groups are intentionally separate: `native_payloads` proves the
exact files co-contained in the wheel, `owner_source` binds the owner's exact
source archive, `sboms` binds the observed embedded documents, and
`components` binds their reviewed identity set. An auditwheel SBOM need not
provide a component-to-file path, hash, or SONAME relationship. Schema 6
therefore rejects legacy `owner_payloads` and all per-component `payloads`
fields rather than implying an unsupported attribution.

`native_component_sources` is keyed as `alpine:ORIGIN@VERSION`. The current
record shape is deliberately narrow and supports one commit-pinned aports
recipe with one upstream distfile:

| Field | Contract |
| --- | --- |
| `kind` | Exactly `alpine-aports`. |
| `origin`, `version` | Must reproduce the source key. Literal `pkgname`, `pkgver`, and `pkgrel` in `APKBUILD` must agree. |
| `aports_commit` | Exact 40-character commit used in the canonical recipe-subtree URL. |
| `distfiles_release` | Exact Alpine `vMAJOR.MINOR` distfiles namespace used by the recipe. This can differ from the runtime base release. |
| `recipe` | Exact URL, SHA-256, and size of the recipe-subtree archive. |
| `distfiles` | Exactly one canonical filename, URL, SHA-512, and positive size no greater than 128 MiB. It must be the recipe's complete nonlocal checksummed source set. |
| `observed_license` | Exact literal aggregate `license` value from `APKBUILD`. |
| `notices` | Nonempty, sorted regular-file member, SHA-256, and size records selected from the distfile. |

The collector never executes the recipe. It validates the literal recipe
identity and checksum table, scans the full source tar under archive limits,
and retains only the reviewed notice members. The current Greenlet record binds
the auditwheel SBOM's `libgcc` and `libstdc++` identities to the reviewed Alpine
GCC 14.2.0-r6 source record. It makes no claim that either identity explains a
particular native file. The Greenlet sdist is likewise an exact owner source,
not a file-level attribution.

The MarkupSafe records contain one `native_payloads` entry per platform and
explicit empty `sboms` and `components` arrays. They bind the exact locked
wheel and the 80,313-byte MarkupSafe 3.0.3 sdist. The empty arrays mean that
the reviewed wheel exposes no embedded SBOM or component identity; they do not
claim that the sdist explains every byte of the compiled extension.

The SQLAlchemy records contain five `native_payloads` entries per platform and
explicit empty `sboms` and `components` arrays. They bind the exact locked
wheel and the 9,912,201-byte SQLAlchemy 2.0.51 sdist. Each platform record uses
the same five derived roles. The empty arrays describe the wheel's observed
surface; they do not claim reproducibility or close the compiler toolchain.

`inventory/native-component-coverage.json` is derived from policy and observed
inventory. It contains `schema_version`, `platform`, `complete`,
`resolved_owners`, and `unresolved_owners`. Resolved records reproduce the exact
reviewed sets. Unresolved records retain each owner's native path/hash pairs
and embedded-SBOM component projection. The checked-in policy resolves
Greenlet, MarkupSafe, and SQLAlchemy; the ledger still reports four unresolved
owners and `complete: false`.

`filesystem_baselines` also has both platform keys. Each value has exactly:

- `apk_database_occurrences`: regular-file occurrence records using the fields
  above, byte-for-byte equal to every distributed APK database occurrence
- `post_base_directory_effects`: canonical effect records with `layer`, `path`,
  `mode`, `uid`, and `gid`; every post-base directory header must first be
  root-owned with mode `0755`, and an identical re-emission of an inherited
  directory is not an effect
- `post_base_removals`: canonical records with `kind`, `path`, and `target`;
  `kind` is `whiteout` or `opaque`, the marker and target must have the
  corresponding OCI relationship, and the removal must affect lower-layer
  state.

The all-layer inventory still retains every raw directory and marker header.
Both record types include mode, UID, GID, layer, and layer digest; directory
records also include their collector-calculated `effective` state. The policy
projection replays that evidence from the reviewed base boundary. It records a
directory creation, type replacement, security-metadata change, or
remove-and-recreate transition, but omits a repeated header that produces no
change. Whiteout marker permissions are not filesystem state; exact removal
kind, path, target, and effect are. This makes trusted Docker and OCI exporter
encodings comparable without allowing an extra directory transition or
removal.

The post-base gate does not merely compare these arrays. It also permits only
the RECORD-owned virtual environment, its reviewed interpreter links and
`pyvenv.cfg`, and the Git-bound application license. Those regular files and
links must have their exact root ownership and reviewed modes. Any other
post-base occurrence fails.

## Source records

`docker_python_recipe` contains exactly `url`, `sha256`, `license_url`, and
`license_sha256`. URL fields are `https_url`; hashes are bare `sha256` values.

`cpython_source` contains exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `url` | `https_url` | Exact `python.org` source archive for the checked-in runtime version. |
| `sha256` | `sha256` | Exact archive digest; it must match the Docker Official Python recipe. |
| `size` | bounded integer | Exact positive archive size, at most 64 MiB. |
| `license_member` | `path` | Exactly `Python-3.14.6/LICENSE`. |
| `license_sha256` | `sha256` | Digest of that one regular archive member. |
| `patchlevel_member` | `path` | Exactly `Python-3.14.6/Include/patchlevel.h`. |
| `patchlevel_sha256` | `sha256` | Digest of that one regular archive member and both platform image version headers. |

The recipe's one literal Python version and hash must select this source. Both
builder and runtime `FROM` instructions must use the reviewed base index. The
source archive parser permits only bounded regular files, directories, and safe
links. The required license and patchlevel members must each occur once as a
regular file. The patchlevel parser confirms the exact version and final
release state over bytes shared by source and both platform images.

Each `python_sources` item contains exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `name` | string | Component name; normalized for coverage comparison. |
| `version` | string | Exact installed version. |
| `url` | `https_url` | Immutable source archive. |
| `sha256` | `sha256` | Exact archive digest. |
| `size` | bounded integer | Exact byte size, at most 64 MiB. |

Its unique normalized `(name, version)` set must equal Python components absent
from `uv.lock`; extra fallback entries fail.

`alpine_recipe_archives` maps every and only installed
`ORIGIN@APORTS_COMMIT` to a bare SHA-256. `alpine_recipe_exceptions` may name
only those same keys. An exception has nonempty `rationale` and grants at least
one of:

- `allow_dynamic_sources: true`
- `allowed_links`, an array of exact `{path, target, type}` objects, where
  `type` is `symlink` or `hardlink` and the relative target is safe.

Unknown exception fields, duplicate links, unobserved allowed links, observed
unallowed links, and a link replacing `APKBUILD` or a checksummed source fail
during bundle generation.

Resolved nested components use the separate `native_component_sources`
records described above. Their recipe and distfile are retained under
`sources/native-components/ORIGIN/VERSION/`; reviewed notice bytes go under
`licenses/from-source/native-ORIGIN-VERSION/`. This separation matters when a
wheel was built against a different Alpine release than the final runtime
image, as Greenlet was.

## Review and validation

The commands answer different questions. A narrower command passing does not
imply that a wider gate passed.

| Command | Scope |
| --- | --- |
| `verify` | One standalone component inventory, the policy schema, exact components, payload baselines, native-component coverage, APK database history, license coverage, and optional distribution approval. |
| `bundle` | The `verify` scope plus the all-layer inventory, Dockerfile and base binding, post-base provenance, Git source binding, lock-to-wheel and lock-to-sdist binding, recipe and distfile verification, retained notices, network hash checks, and deterministic archive limits. |
| `native-component-coverage-view` | The canonical per-owner coverage ledger after full standalone inventory verification. |
| `filesystem-policy-view` | A human-readable projection of raw layer records into the canonical directory-effect and removal policy. |
| `verify-ci-policy` | The offline policy checks possible from an extracted pull-request artifact, materialized policy blob, and materialized Dockerfile blob. |

Run `verify` for one platform inventory with:

```bash
uv run --frozen python .github/scripts/container_evidence.py verify \
  --inventory PATH_TO_COMPONENT_INVENTORY \
  --policy .compliance/container-policy.json
```

Reviewers must run `bundle` separately for both platforms through the CI
workflow. A standalone `verify` success is not the full release gate.

Generate the native-component coverage ledger with:

```bash
uv run --frozen python .github/scripts/container_evidence.py \
  native-component-coverage-view \
  --inventory PATH_TO_COMPONENT_INVENTORY \
  --policy .compliance/container-policy.json \
  --output PATH_TO_COVERAGE_LEDGER
```

The command runs the full standalone inventory verification before it writes
the canonical ledger. A ledger with `complete: false` is an accurate record of
remaining work, not distribution approval.

Generate the filesystem-policy projection with:

```bash
uv run --frozen python .github/scripts/container_evidence.py \
  filesystem-policy-view \
  --files-inventory PATH_TO_ALL_LAYER_INVENTORY \
  --policy .compliance/container-policy.json \
  --output PATH_TO_POLICY_VIEW
```

The command validates the standalone all-layer fields it consumes, binds the
reviewed base prefix, and emits `platform`, `post_base_directory_effects`, and
`post_base_removals`. It does not replace `verify-ci-policy` or `bundle`.

For extracted pull-request artifacts, a reviewer using a previously trusted
helper runs `verify-ci-policy` with the component inventory, all-layer
inventory, materialized policy blob, and materialized Dockerfile blob. That
command composes deep inventory validation, the complete standalone policy
gate, the reviewed base-layer prefix, canonical post-base directory and removal
policy, and exact Dockerfile base/index binding. It does not run the post-base
regular-file or link provenance gates, application source binding, or exact
source-policy coverage. It also does not fetch sources or open the nested
evidence tar. Those gates remain dependent on the independently reviewed CI
collector, workflow, and exact successful job; the extracted artifact set does
not contain all inputs needed to re-run them.

See [review container evidence](../how-to/review-container-evidence.md) for the
maintainer workflow and
[container evidence release contract](container-evidence-release-contract.md)
for the future recipient-facing artifact contract.
