# Container evidence policy reference

`.compliance/container-policy.json` is the reviewed allowlist for container
component, license, source, base-image, and layer provenance. It is not a
configuration file for the running GitHub App. The evidence collector rejects
unknown or missing fields at every schema boundary and compares observed
raw records or their documented canonical security projection exactly; adding
a permissive field has no effect.

The executable source of truth is
`.github/scripts/container_evidence.py`, principally
`validate_policy_schema`, `verify_inventory`,
`verify_base_layer_binding`, `canonical_post_base_filesystem_changes`,
`verify_post_base_filesystem_policy`, `verify_post_base_provenance`, and
`validate_source_policy_coverage`. Adversarial loader and policy tests live
in `tests/test_container_evidence.py`.

## Common types and limits

The current schema version is integer `2`. JSON must be UTF-8, no larger than
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
| `https_url` | Credential-free HTTPS URL with a valid hostname and port and no control characters; redirects are separately limited to five. |
| `mode` | Integer from `0` through `07777`; booleans are invalid. |
| `uid`, `gid` | Integer from `0` through `2^31 - 1`; booleans are invalid. |
| component list | At most 10,000 exact component records. |
| occurrence list | At most 250,000 exact layer occurrence records. |
| source or payload size | Integer from `0` through 64 MiB; booleans are invalid. |
| component scalar | UTF-8 text bounded to 512 encoded bytes unless the validator applies a narrower identity grammar. |
| component identity key | UTF-8 text bounded to 1,056 encoded bytes; it combines two component scalars with ecosystem separators. |
| license scalar | UTF-8 text bounded to 16,384 encoded bytes. |

## Top-level object

The policy has exactly these fields:

| Field | Type | Meaning | Consuming gate |
| --- | --- | --- | --- |
| `schema_version` | integer | Policy schema; exactly `2`. | Every command through `validate_policy_schema`. |
| `base_image` | string | Nonempty bounded Dockerfile base reference; the schema rejects whitespace and `@`. The checked-in value is a tagged Docker Official Python reference. | Exact Dockerfile binding during `bundle` and `verify-ci-policy`. |
| `base_image_index_digest` | `qualified_sha256` | Reviewed multi-platform base index. | Schema validation during `verify`; exact Dockerfile/index binding during `bundle` and `verify-ci-policy`. |
| `base_image_platforms` | platform object | Exact ordered base layer diff IDs for both platforms. | Base-prefix and post-base provenance gates. |
| `platforms` | platform object | Exact normalized component list for each platform. | `verify` and `bundle`. |
| `distribution_approval` | object | Separate human decision about recipient distribution. | Required only when `--require-distribution-approval` is set. |
| `license_resolutions` | object | Reviewed expression and rationale for every exact component identity. | Inventory verification, notices, and bundle generation. |
| `license_texts` | array | Hash-pinned standard license texts required by reviewed expressions. | Inventory coverage and bundle fetch. |
| `custom_license_evidence` | object | Exact source-carried notice pins for every `LicenseRef-*`. | Inventory coverage and retained-license verification. |
| `unexpanded_python_payloads` | platform object | Exact known-incomplete wheel SBOM, native, and identity-file occurrences. | `verify`; any drift fails. |
| `filesystem_baselines` | platform object | Exact APK database history plus canonical post-base directory effects and removals. | Deep `bundle` provenance verification and offline CI policy review. |
| `docker_python_recipe` | object | Pinned Docker Official Python recipe and license. | Bundle fetch and CPython binding. |
| `cpython_source` | object | Pinned CPython source archive. | Bundle fetch and recipe binding. |
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
inventory's exact complete-source status. Current code intentionally requires
`complete: false` with the issue #18 reason, so the distribution gate cannot
pass. Issue #28 independently prevents publication authority from entering
the current collection path. Issue #32 separately requires release and ad-hoc
builds to consume CI's hash-pinned selected proof and exact application wheel.

## License policy

`license_resolutions` is keyed by every exact component identity. Each value
contains only `expression` and nonempty `rationale`, both strings. Its key set
must equal the selected platform's component identities.

`license_texts` contains objects with exactly:

| Field | Type | Constraint |
| --- | --- | --- |
| `id` | string | Standard identifier using letters, digits, `.`, `+`, or `-`; unique across the array. |
| `url` | `https_url` | Immutable standard text location. |
| `sha256` | `sha256` | Exact text bytes. |

The ID set must equal every non-operator, non-`LicenseRef-*` token required by
the reviewed expressions.

`custom_license_evidence` is keyed by every and only `LicenseRef-*` identifier
in those expressions. Each value contains exactly:

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
array uses this regular-file occurrence shape:

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
they do not claim that the nested components and corresponding sources are
complete.

`filesystem_baselines` also has both platform keys. Each value has exactly:

- `apk_database_occurrences`: regular-file occurrence records using the shape
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
`cpython_source` contains exactly `url` and `sha256`. The recipe's one literal
Python version and hash must select the configured CPython source, and both
builder and runtime `FROM` instructions must use the reviewed base index.

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

## Review and validation

For one platform inventory, this command validates the complete standalone
inventory, the policy schema, component equality, payload baselines, APK
database history, license coverage, and optional distribution approval:

```bash
uv run --frozen python .github/scripts/container_evidence.py verify \
  --inventory PATH_TO_COMPONENT_INVENTORY \
  --policy .compliance/container-policy.json
```

The `bundle` command adds all-layer schema validation, Dockerfile/base binding,
exact post-base provenance, Git source binding, exact source-policy coverage,
network hash verification, retained notice verification, and deterministic
archive limits. Reviewers must run it separately for both platforms through
the CI workflow; a standalone `verify` success is not the full release gate.

For a human-readable projection of raw layer records into the exact semantic
filesystem-policy shape, use:

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
