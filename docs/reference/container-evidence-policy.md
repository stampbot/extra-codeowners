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

The current schema version is integer `9`. JSON must be UTF-8, no larger than
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
| `https_url` | Credential-free HTTPS request URL with a valid hostname and port and no control characters; redirects are separately limited to five and persisted as canonical HTTPS origins. |
| `mode` | Integer from `0` through `07777`; booleans are invalid. |
| `uid`, `gid` | Integer from `0` through `2^31 - 1`; booleans are invalid. |
| component list | At most 10,000 exact component records. |
| occurrence list | At most 250,000 exact layer occurrence records. |
| source or payload size | Integer from `0` through 64 MiB unless the field says otherwise; booleans are invalid. Native-component archives and distfiles may be at most 128 MiB, and an owner-sdist subtree may expand to at most 256 MiB. |
| component scalar | UTF-8 text bounded to 512 encoded bytes unless the validator applies a narrower identity grammar. |
| component identity key | UTF-8 text bounded to 1,056 encoded bytes; it combines two component scalars with ecosystem separators. |
| license scalar | UTF-8 text bounded to 16,384 encoded bytes. |

## Top-level object

The policy has exactly these fields:

| Field | Type | Meaning | Consuming gate |
| --- | --- | --- | --- |
| `schema_version` | integer | Policy schema; exactly `9`. | Every command through `validate_policy_schema`. |
| `base_image` | string | Nonempty bounded Dockerfile base reference; the schema rejects whitespace and `@`. The checked-in value is a tagged Docker Official Python reference. | Exact Dockerfile binding during `bundle` and `verify-ci-policy`. |
| `base_image_index_digest` | `qualified_sha256` | Reviewed multi-platform base index. | Schema validation during `verify`; exact Dockerfile/index binding during `bundle` and `verify-ci-policy`. |
| `base_image_platforms` | platform object | Exact ordered base layer diff IDs for both platforms. | Base-prefix and post-base provenance gates. |
| `platforms` | platform object | Exact normalized component list for each platform. | `verify` and `bundle`. |
| `distribution_approval` | object | Separate human decision about recipient distribution. | Required only when `--require-distribution-approval` is set. |
| `license_resolutions` | object | Reviewed expression and rationale for every exact component identity. | Inventory verification, notices, and bundle generation. |
| `license_texts` | array | Hash-pinned standard license texts required by reviewed expressions. | Inventory coverage, direct-source planning, and verified-store consumption. |
| `custom_license_evidence` | object | Exact source-carried notice pins for every top-level `LicenseRef-*`. | Inventory coverage and retained-license verification. |
| `unexpanded_python_payloads` | platform object | Exact raw wheel SBOM, native, and identity-file occurrences. Some owners may also have closed-world coverage. | `verify`; any drift fails. |
| `native_wheelhouse_contract_sha256` | `sha256` | Digest of the reviewed consumer contract that selects the signed wheelhouse image, source revision, manifests, and workflow identity. | Source planning, image-label verification, wheel selection, and bundle retention. |
| `native_component_sources` | object | Tagged, immutable source records for reviewed components nested inside wheels. | Schema, source-retention, and notice gates. |
| `native_component_coverage` | platform object | Exact wheel observations, review decisions, payload dispositions, omissions, and owner review state. | `verify`, lock binding, coverage ledger, notices, and bundle generation. |
| `filesystem_baselines` | platform object | Exact APK database history, post-base APK world and system-file history, and canonical directory effects and removals. | Deep `bundle` provenance verification and offline CI policy review. |
| `docker_python_recipe` | object | Pinned Docker Official Python recipe and license. | Direct-source planning, verified-store consumption, and CPython binding. |
| `cpython_source` | object | Pinned CPython source archive and source-carried identity evidence. | Direct-source planning, verified-store consumption, recipe binding, and runtime/source identity binding. |
| `python_sources` | array | Pinned fallback sources for components absent from `uv.lock`. | Exact source-coverage and bundle gates. |
| `alpine_distfiles_release` | string | Alpine distfiles release in `vMAJOR.MINOR` form. | Alpine distfile planning and fetch. |
| `alpine_recipe_archives` | object | Exact `ORIGIN@APORTS_COMMIT` to recipe-subtree SHA-256 mapping. | Direct-source planning, Alpine distfile planning, and bundle gates. |
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
| `approved` | boolean | Must be `false` whenever the derived native-component coverage ledger is incomplete. |
| `approved_by` | string | Nonempty when approval is required. |
| `approved_on` | string | Nonempty when approval is required; use an unambiguous date in review. |
| `rationale` | string | Always nonempty. |

Approval is necessary but not sufficient. The collector also requires the
derived ledger's exact complete-source status. Normal verification rejects
`approved: true` while that ledger is incomplete; the
`--require-distribution-approval` gate additionally requires a complete,
attributed approval. The current native-owner ledger is complete, but approval
remains false while issue #18 finishes recipient delivery and release binding,
issue #32 retains the selected application proof in durable release evidence,
and issue #28 separates parsing from publication authority.

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
the reviewed top-level expressions and every direct native-component review,
including reviews in open owner records. Extra, missing, and duplicate text
IDs fail both standalone verification and bundle source-policy verification
with the same exact reviewed-identifier check. Schema 9
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

`filesystem_baselines` also has both platform keys. Each platform record has
exactly six arrays:

| Field | Contract |
| --- | --- |
| `apk_database_occurrences` | Every layered `lib/apk/db/installed` occurrence, including a lower-layer record that is not effective in the final image. Records use the regular-file occurrence fields above. |
| `post_base_apk_world_occurrences` | Every `etc/apk/world` occurrence after the reviewed base-layer prefix. Records use the same occurrence fields, must have that exact path, and must be root-owned with mode `0644`. |
| `post_base_system_regular_occurrences` | Exact effective package-manager state and runtime-library files introduced above the base. Records use the regular-file occurrence fields above and are restricted to the reviewed system paths. |
| `post_base_system_links` | Exact post-base runtime-library symbolic links. Each record pins `kind`, `layer`, `path`, `target`, `mode`, `uid`, and `gid`; only the reviewed system-link paths are accepted. |
| `post_base_directory_effects` | Root-owned directory creations or security-metadata changes that affect the post-base filesystem. Each record pins `layer`, `path`, `mode`, `uid`, and `gid`. |
| `post_base_removals` | Effective post-base whiteout or opaque-directory effects. Each record pins its kind, marker path, and target. |

The APK database describes installed package metadata; APK world describes the
selected top-level package set. The policy binds both because a runtime
`apk add` can replace them independently. Directory and removal baselines are
semantic projections, while both APK files retain exact layer, digest, size,
mode, owner, group, and final-effect status. Post-base occurrences of both
files must also be root-owned with mode `0644`. The system-file and link arrays
classify the exact package-manager state and runtime library bytes accepted by
the provenance gate.

Schema 9 adds `apk_shared_libraries` to the component inventory. The collector
derives this sorted array from the effective APK database's `F`, `R`, and `Z`
records. The all-layer validator binds every projected occurrence back to
`inventory/all-layer-files.json`. Each item has exactly:

| Field | Contract |
| --- | --- |
| `package` | Exact effective APK `name` and `version` that owns the path. |
| `path` | Canonical shared-library path directly under `lib` or `usr/lib`; unique across the array. |
| `apk_sha1` | Lowercase SHA-1 decoded from the APK database's `Q1` checksum. |
| `occurrence` | Exact effective regular-file or symbolic-link occurrence at `path`. |

A regular occurrence carries `kind: regular` plus the regular-file occurrence
fields above. A symbolic-link occurrence carries `kind: symlink`, effective
state, layer, path, target, mode, UID, and GID. The collector recomputes the APK
SHA-1 over regular-file bytes or the symbolic-link target. A missing, replaced,
hard-linked, multiply owned, malformed, or checksum-mismatched library fails
collection. The all-layer validator then binds each library back to the exact
occurrence and effective filesystem topology. This proves package ownership of
the runtime bytes; it does not prove that those bytes built a native wheel.

## Native-component closure

`native_component_coverage` is a closed-world review ledger, not a list of
components inferred from package names. Both platforms must contain the same
sorted owner set, and that set must exactly match every wheel owner with a
native payload or embedded SBOM in the inventory. Schema 9 is the only accepted
version. Older owner-level `components` records are rejected.

Each owner record has exactly these fields:

| Field | Contract |
| --- | --- |
| `owner` | Canonical `python:NAME@VERSION`, unique on the platform. |
| `wheel` | Either an exact HTTPS lock-file artifact or an exact `native-wheelhouse` provider record. A lock wheel must match the supported CPython 3.14 musllinux platform. A wheelhouse wheel must match the contract's native CPython 3.14 platform and bind its filename, source name, SHA-256, and positive size. |
| `wheelhouse_build` | `null` for a lock wheel. A wheelhouse wheel must record the matching source name, sorted crates.io source IDs, local Cargo package identities, and at least one linked library with its SONAME, exact Alpine package identity, runtime path, and resolved path. |
| `owner_source` | Exact HTTPS URL, SHA-256, and size for the owner source. Lock wheels bind this to the lock or reviewed fallback. Wheelhouse wheels bind it to the signed build manifest. |
| `cargo_lock` | `null` unless the owner directly reviews a crates.io source; otherwise, the exact retained owner-sdist lockfile context described below. |
| `native_payloads` | Sorted records with derived `role`, installed `path`, SHA-256, and positive `size`. |
| `sboms` | Sorted, hash-pinned CycloneDX observations and a disposition for each metadata root. |
| `component_reviews` | Direct source and reviewed-license decisions over exact SBOM occurrences. |
| `payload_dispositions` | One decision for every native payload role: owner, SBOM observations, or a named omission. |
| `known_omissions` | Structured, reviewable evidence gaps. |
| `canonical_relationships` | Narrow, byte-proven equivalence to a directly reviewed observation in another closed owner. |
| `review` | The owner-level `open` or `closed` decision. |

An owner must expose at least one native payload or SBOM. `role` is derived from
`path`: the validator strips the reviewed `site-packages` prefix, normalizes the
platform CPython ABI suffix, and removes only a valid eight-lowercase-hex
auditwheel filename segment. Paths and roles are unique. Both platforms must
have the same role set, although paths, wheel bytes, and payload digests may
differ.

Each `wheelhouse_build.linked_libraries` item has exactly `name`, `package`,
`runtime_path`, and `resolved_path`. `name` is the ELF SONAME and must equal the
basename of `runtime_path`. Both paths are canonical and directly under `lib` or
`usr/lib`; both must use the same directory. `resolved_path` must name a shared
library. Both inventory entries must belong to the exact named APK package and
version. The resolved occurrence must be a regular file. The runtime occurrence
must either be that same regular file or one direct, same-directory symbolic
link to its basename. Absolute links, link chains, cross-directory targets, and
cross-package bindings fail. Native wheelhouse inspection also rejects ELF
`RPATH` and `RUNPATH`, so a wheel cannot redirect these reviewed SONAMEs to an
unreviewed directory.

### SBOM observations and occurrence identity

An SBOM record pins `path`, `sha256`, its exact `observation`, and a
`metadata_root` disposition. The observation retains:

- `bom_format`, exactly `CycloneDX`, and a supported `spec_version`
- a canonical `observation_sha256` over the security projection
- the optional `metadata_component` and optional `metadata_root_echo`
- `upstream_invalid_duplicate_bom_ref`, which is true only for that accepted
  metadata-root echo
- the sorted component occurrences, including `type`, `name`, `version`,
  `purl`, `bom_ref`, hashes, and raw license observations.

Each occurrence may contain at most one digest for a hash algorithm. Duplicate
algorithm names, including case-only aliases, fail validation because they make
source binding ambiguous.

One CycloneDX document may contain at most 10,000 component occurrences across
its metadata root and its top-level and nested component arrays. A component
may contain at most 16 hash records and 16 license observations. Each component
JSON object, and every object nested inside it, may contain at most 16 fields.
Arrays inside the object may contain at most 16 values, except a direct child
`components` array, which uses the 10,000-component document limit.

Occurrence references contain `sbom_path`, `observation_sha256`,
`identity_kind`, and `purl`; a `bom-ref` identity also contains `bom_ref`.
A nonempty `bom-ref` is the document-local identity. The PURL is the fallback
only when `bom-ref` is empty. Repeated PURLs are valid only when every
occurrence has its own unique, nonempty `bom-ref`.

Some auditwheel documents repeat the metadata component once as the first
top-level component and reuse its `bom-ref`. The collector accepts only that
canonically identical metadata-root echo, sets
`upstream_invalid_duplicate_bom_ref: true`, and requires an explicit
`metadata-root-echo` anomaly review with a reason. Any other duplicate
metadata PURL or `bom-ref` fails.

`metadata_root.kind` is `missing`, `owner`, `embedded-component`, or
`known-omission`. An owner root must match the wheel owner name and version.
A known-omission root names the corresponding omission. `anomaly_review` is
`null` unless the exact metadata-root echo described above is present.

### Reviews, dispositions, and omissions

Each `component_reviews` item has exactly `observations`, `source`, and
`reviewed_license`. Observation references are sorted and unique; an
occurrence can be directly reviewed only once. The source must name one tagged
`native_component_sources` record, and `LicenseRef-*` is not allowed in a
nested reviewed expression.

Every payload role has exactly one disposition:

- `owner` says only that the payload belongs to the wheel owner
- `sbom-components` cites the exact observations used to explain the payload
- `known-omission` cites one structured omission.

These are review decisions, not claims inferred from co-membership. An
auditwheel SBOM does not normally prove a component-to-file path, hash, or
SONAME relationship.

A known omission has an ID, a component identity, zero or more observation
references, zero or more payload roles, a nonempty sorted `missing_evidence`
set, and a reason. Supported missing-evidence values are
`build-material-attestation`, `component-inventory`, `exact-source`,
`license-evidence`, `notice-evidence`, `payload-provenance`,
`sbom-observation`, and `source-payload-relationship`.

A `known-omission` metadata root or payload disposition must name the exact
omission that contains its observation reference or payload role. Listing the
same reference under another omission does not satisfy the disposition.

`review.state` is `closed` only when the owner has no omissions or unresolved
items. An open review requires omissions, a reason, and an `unresolved_items`
list whose values exactly equal its omission IDs. The derived ledger retains
the full open owner records; it does not reconstruct a lossy gap summary.

`canonical_relationships` supports only
`same-component-by-payload-equivalence`. The source and target observations
must have the same type, name, and version. Their selected payloads must have
the same size and SHA-256, and each named payload's `sbom-components`
disposition must cite its corresponding observation. The target owner must be
closed, the target observation must be directly reviewed there, and targets
cannot be reused or form chains.

### Cargo lock context

A direct review of any `crates-io` source requires a non-null `cargo_lock`
record. A non-null record without a crate review is invalid. The record has
exactly these fields:

| Field | Contract |
| --- | --- |
| `member` | Canonical owner-sdist member path whose basename is `Cargo.lock`. |
| `sha256` | Lowercase SHA-256 of the exact lockfile bytes. |
| `size` | Positive byte size, no greater than 8 MiB. |
| `source_ids` | Sorted, unique source IDs that exactly match the crates.io sources used by this owner's component reviews. |
| `non_sbom_packages` | Sorted, unique crates.io package records present in the lockfile but absent from those reviewed SBOM sources. Each record has exact `name`, `version`, registry URL, and checksum. |

Bundle generation reads this member from the already retained owner sdist and
accepts Cargo lockfile versions 3 and 4. Every registry package must use the
canonical crates.io registry and must appear exactly once in either
`source_ids` or `non_sbom_packages`. The lockfile checksum for a reviewed crate
must equal the checksum of its retained official archive. Local lockfile
packages must match Cargo PURLs assigned to the owner root or to reviewed
owner-sdist subpaths.

The verified lockfile is retained under
`sources/cargo-locks/OWNER_DIGEST_PREFIX/Cargo.lock`. It is checksum-bound by
the archive, while its member identity and digest remain in the reviewed
policy. This closes a source-set accounting gap; it is not build provenance.

### Source tagged union

`native_component_sources` accepts four source kinds. Every record has a
nonempty, sorted `notices` array of exact archive member, SHA-256, and size
records.

| Kind | Required identity and verification |
| --- | --- |
| `alpine-aports` | `alpine:ORIGIN@VERSION`; a commit-pinned aports recipe, exact release distfiles, literal recipe identity and license, bounded sibling symlink exceptions, and retained notices. Every upstream recipe source must appear once with its exact checksum. Each allowed symlink must resolve directly to a retained regular sibling. |
| `crates-io` | `crates-io:NAME@VERSION`; the canonical crates.io archive, exact `NAME-VERSION/Cargo.toml`, raw and normalized license, and retained notices. Archive root, manifest name/version/license, PURL, archive hash, and reviewed expression are bound together. Every regular archive member whose name denotes a license or notice must appear in the policy's exact notice set. |
| `owner-sdist-subpath` | `owner-sdist:OWNER#PATH`; a canonical subtree of that same owner's locked sdist. `#.` selects the archive root. The record pins the tree SHA-256, member count, expanded size, root or workspace manifest, every selected or reachable package manifest, reviewed license, and notices. Tar and ZIP parsers reject unsafe paths, duplicate members, devices, sparse files, and links. |
| `checksummed-upstream-release` | `upstream-release:NAME@VERSION`; an exact archive, exact checksum document, selected filename, reviewed license, and notices. The observation name, version, download PURL, and SHA-256 must identify that archive. The strict GNU-style checksum parser requires exactly one matching record. |

For crates.io records, `raw_license` must match the exact Cargo manifest.
`normalized_license` normally preserves the same value. The one supported
legacy rewrite is `MIT/Apache-2.0` to `MIT OR Apache-2.0`; any other difference
fails. A directly reviewed crate observation must carry exactly one supported
CycloneDX license expression or SPDX ID, and it must equal
`normalized_license`.

Owner-subtree package records pin each Cargo package's path, name, version, and
exact `Cargo.toml` bytes. Each local observation must name one of those
packages. A reachable local dependency may lack its own SBOM observation, but
it must still have a reviewed package record and a matching local entry in
`Cargo.lock`.

For an observed package, the PURL path and file `bom-ref` must agree, and a
PURL fragment must name a regular file in the verified subtree. The absolute
checkout prefix in a build-generated `bom-ref` is treated as opaque; the
reviewed package identity comes from the Cargo PURL and pinned manifest. A
fragmented observation may keep the normalized package name or use the
compiled-library target name. In both cases, the fragment must match the
pinned manifest's library target path. An explicit `[lib]` target is honored;
the verifier does not invent a default `src/lib.rs` target when
`autolib = false` is set in `[package]`.

Bundle generation parses the pinned root or workspace and package manifests,
including a package that is also its workspace root. It resolves inherited
version, license, and local path-dependency fields. The reviewed package list
must match the selected root plus declared or implicit workspace members and
their reachable local path dependencies. An unused package or workspace
dependency cannot justify its own inclusion.

Owner-subtree and checksummed-release reviews carry the same
`reviewed_license` expression as their source record. Bundle generation
rechecks that equality before it associates retained notice bytes with the
reviewed component occurrences.

All configured sources must be used. The two platforms must agree on sources,
review decisions, omissions, relationships, and logical observations.
Build-specific `bom-ref` values are normalized only for that semantic
cross-platform comparison; the literal values remain in each platform record.
Canonicalized reference lists are sorted again, and relationship targets use
the referenced owner's canonical occurrence map. These rules prevent
platform-specific identifiers from creating false review drift.

### Derived coverage ledger

`inventory/native-component-coverage.json` contains `schema_version`,
`platform`, `complete`, `resolved_owners`, `unresolved_owners`,
`observed_sbom_anomalies`, `remaining_owner_count`, and
`remaining_owner_names`. Closed owners are copied to `resolved_owners`; open
owners are copied in full to `unresolved_owners`. The count and names are
derived from that open list.

The current ledger closes all seven observed native owners: CFFI 2.1.0,
Cryptography 48.0.1, Greenlet 3.5.3, MarkupSafe 3.0.3, Psycopg C 3.3.4,
Pydantic Core 2.46.4, and SQLAlchemy 2.0.51. CFFI's `libffi.so.8`, Psycopg C's
`libpq.so.5`, and Pydantic Core's `libgcc_s.so.1` are bound to the exact
APK-owned runtime and resolved paths through the schema-9 rules above.

Each platform also reports two reviewed metadata-root-echo anomalies: the
Cryptography and Greenlet auditwheel documents. The ledger reports
`complete: true`, an empty `unresolved_owners` array,
`remaining_owner_count: 0`, and an empty `remaining_owner_names` array.
`MANIFEST.json.source_completeness` is derived from this ledger; the raw
component inventory has no caller-controlled completeness field. This source
accounting result is not distribution approval.

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
  `type` is `symlink` or `hardlink`. Both paths are canonical and relative to
  the archive root. `target` names the resolved sibling in the archive, not the
  symlink's literal target text. For example, a link at
  `aports/main/demo/post-upgrade` whose literal target is `post-install` uses
  `aports/main/demo/post-install` as its policy target.

Unknown exception fields, duplicate links, unobserved allowed links, observed
unallowed links, and a link replacing `APKBUILD` or a checksummed source fail
during bundle generation. The resolved target must be a distinct regular file
in the same directory as the link. Absolute paths, traversal, and link chains
fail.

Directly reviewed nested components use the `native_component_sources` tagged
union described above. Each source ID is SHA-256 hashed and shortened to its
first 20 hexadecimal characters. Kind-specific artifacts or subtree manifests
are retained under `sources/native-components/SOURCE_DIGEST_PREFIX/`; reviewed
notice bytes go under
`licenses/from-source/native-SOURCE_DIGEST_PREFIX/`. For an
`owner-sdist-subpath` source, the locked owner archive remains under
`sources/python/` and the hash-addressed directory contains its verified
subtree manifest. This separation matters when a wheel was built against a
different Alpine release than the final runtime image, as Greenlet was.

## Verified source plans and stores

Source acquisition uses two canonical plans. The direct plan binds the source
revision, policy digest, lock-file digest, exact request URLs, allowed hosts,
expected digests, byte limits, and consumers. A rootless parser reads the
verified recipe objects from that store and produces the Alpine distfile plan.
The Alpine plan binds its parent plan and parent store manifest, so it cannot be
combined with recipes from another fetch.

Each fetch writes a versioned `SOURCE-STORE.json` and content-addressed objects.
The store retains canonical HTTPS origins for the request and redirect trail.
It does not persist redirected paths or queries, because those can contain
signed parameters or credentials. The exact initial request URL remains in the
trusted `SOURCE-PLAN.json`.

CI fetches both stores once and uploads them together. Both architecture jobs
download that artifact by immutable artifact ID. The `bundle` command requires
each plan's trusted SHA-256 and byte size, rechecks every object as it reads it,
and verifies the retained store again before it commits its three outputs. It
has no network fallback.

## Review and validation

The commands answer different questions. A narrower command passing does not
imply that a wider gate passed.

| Command | Scope |
| --- | --- |
| `inventory-image-archive` | Inside the rootless offline parser, verify one Docker-only export record and its exact archive hash, size, configuration digest, subject, and platform; then inventory every layer through one stable no-follow descriptor. |
| `verify` | One standalone component inventory, the policy schema, exact components, payload baselines, native-component coverage, APK database history, license coverage, and optional distribution approval. |
| `bundle` | The `verify` scope plus the all-layer inventory, Dockerfile and base binding, exact post-base APK world history, post-base provenance, Git source binding, lock-to-wheel and lock-to-sdist binding, verified direct and Alpine source stores, recipe and distfile verification, retained notices, and deterministic archive limits. It requires trusted plan digests and sizes and has no network fallback. |
| `native-component-coverage-view` | The canonical per-owner coverage ledger after full standalone inventory verification. |
| `filesystem-policy-view` | A human-readable projection of raw layer records into exact post-base APK world and system-file history plus canonical directory-effect and removal policy. |
| `verify-ci-policy` | The offline policy checks possible from an extracted pull-request artifact, materialized policy blob, and materialized Dockerfile blob. |

`export_container_image.py` is deliberately not an archive parser or a
collector command. It is the Docker-owning producer for
`inventory-image-archive`: it inspects bounded Docker JSON, streams the saved
image under a fixed byte limit, and writes the binding record. It never opens
the archive it creates.

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
reviewed base prefix, and emits `platform`,
`post_base_apk_world_occurrences`, `post_base_directory_effects`, and
`post_base_removals`, plus `post_base_system_regular_occurrences` and
`post_base_system_links`. It does not replace `verify-ci-policy` or `bundle`.

For extracted pull-request artifacts, a reviewer using a previously trusted
helper runs `verify-ci-policy` with the component inventory, all-layer
inventory, materialized policy blob, and materialized Dockerfile blob. That
command composes deep inventory validation, the complete standalone policy
gate, the reviewed base-layer prefix, exact post-base APK world history,
canonical directory and removal policy, and exact Dockerfile base/index
binding. It does not run the broader post-base regular-file or link provenance
gates, application source binding, or exact source-policy coverage. It also
does not fetch sources or open the nested evidence tar. Those gates remain
dependent on the independently reviewed CI collector, workflow, and exact
successful job; the extracted artifact set does not contain all inputs needed
to re-run them.

See [review container evidence](../how-to/review-container-evidence.md) for the
maintainer workflow and
[container evidence release contract](container-evidence-release-contract.md)
for the future recipient-facing artifact contract.
