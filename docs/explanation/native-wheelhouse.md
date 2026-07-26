# Why native dependencies have their own build

Compiling C and Rust during every application build is slow. Pulling an
upstream wheel is faster, but a checksum only tells us that we downloaded the
same wheel again. It doesn't connect that wheel to reviewed source.

Extra CODEOWNERS handles those jobs separately. A dedicated workflow builds
the native dependency wheels when their sources or toolchain change. A later
application change can consume that wheelhouse by immutable image digest.
Routine application builds won't need Cargo, a C compiler, or network access
to a Python package index.

The wheelhouse is build infrastructure. It is not an Extra CODEOWNERS
application image.

## What the build does

The reviewed inputs live in
[`containers/native-wheelhouse/inputs.json`][inputs]. They pin the Python
version, Alpine base digest, complete Alpine package closure for each
architecture, source archives, expected wheel identities, and Cargo package
count.

The build then follows this sequence:

1. The toolchain stage asks `apk` for every common package and version in the
   reviewed closure. The pinned base supplies its architecture-specific
   virtual package. The assembler later requires the installed package
   database to match the combined platform closure exactly.
2. BuildKit downloads four source archives and verifies each archive against
   the SHA-256 written next to its URL.
3. A fetch-only stage reads Pydantic Core's `Cargo.lock`, downloads that exact
   crates.io closure, and rejects extra, missing, or checksum-mismatched crate
   archives.
4. Two separate nonroot stages build the wheels. Both stages have networking
   disabled and receive fresh copies of the same Cargo input directory.
5. A third offline stage compares the two wheel sets byte for byte.
6. The same stage checks each wheel's filename, `WHEEL` compatibility fields,
   package metadata, `RECORD` hashes, native architecture, and shared-library
   requirements. `Root-Is-Purelib` and `Tag` must agree with the filename and
   the observed native payloads. Every file is checked for ELF content, so a
   versioned library or executable cannot bypass inspection by avoiding a
   `.so` suffix.
7. The final scratch image contains the verified wheelhouse. The compiler
   toolchain and source trees don't cross that boundary.

Running the two builds in separate stages matters. The second build can't
reuse an unpacked crate, compiler target directory, or generated file from the
first one.

The toolchain installation also precedes copies of the build script, source
contract, and source archives. A dependency-source update can therefore reuse
the completed compiler layer. Only a base, Alpine closure, or toolchain
instruction change invalidates that layer.

## What gets published

The `Native wheelhouse` workflow runs only when its builder, inputs, tests, or
workflow change. It uses native GitHub-hosted amd64 and arm64 runners; it
doesn't emulate one architecture on the other.

Each runner uploads a short-lived platform artifact. A trusted `main` branch
job downloads both artifacts and verifies them again before publication. That
job wraps the already-built files in a multi-platform scratch image, generates
software bills of materials (SBOMs), attaches provenance, and signs the image
digest with GitHub Actions' keyless identity. It moves the commit tag and
`latest` only after those steps pass.

The commit tag is immutable. If a run creates that tag and then fails while
updating `latest`, a retry doesn't replace it with a newly generated
provenance-bearing digest. The retry verifies the existing signature,
two-platform index, source-revision labels, and both platform payloads against
its fresh wheelhouse artifacts. Only an exact match can repair `latest`.

The package name is:

```text
ghcr.io/stampbot/extra-codeowners-native-wheelhouse
```

`latest` is useful for discovery, but it moves. Application builds must use
the digest shown in the successful workflow summary.

Every platform directory contains:

| File | Purpose |
| --- | --- |
| `inputs.json` | The complete reviewed input contract used for this build. |
| `cargo-inputs.json` | The exact Cargo registry closure from `Cargo.lock`. |
| `manifest.json` | Builder inventory, source review records, wheel hashes, native linkage, and the hashes of the two input files. |
| `cffi-*.whl` | CFFI built from its reviewed commit archive. |
| `psycopg_c-*.whl` | Psycopg C built from its reviewed tag archive and linked to Alpine `libpq`. |
| `pydantic_core-*.whl` | Pydantic Core built from its PyPI source distribution and locked crates. |
| `setuptools-*.whl` | The bootstrap backend reproduced from the reviewed Setuptools source. |

The verifier rejects extra files. Consumers can therefore treat the directory
inventory as a closed set, not a bag of wheels that happens to contain the
expected names.

## How the Setuptools bootstrap matches the release

Setuptools builds itself. Its signed repository archive includes a small
`bootstrap.egg-info` directory and a development release suffix in
`setup.cfg`; the published wheel does not.

The input contract names both bootstrap files and binds their hashes. The
builder refuses to remove the directory if it contains anything else. It also
binds the original and replacement `setup.cfg` hashes. With those release
transformations applied, the build reproduces the published Setuptools 80.3.1
wheel exactly:

```text
sha256:3d6b173312bc2f71193fc44b33d22d377fedb074bfdd5bf8e5b333f7d4140671
```

That match is useful evidence: the signed source and published bootstrap wheel
lead to the same bytes in the pinned environment.

## What the evidence does not prove

The `signature_review` fields record a maintainer's upstream review. The
container build doesn't import a maintainer keyring or repeat that review.
Pydantic Core's selected tag is unsigned, so the wheelhouse deliberately uses
the checksum-bound PyPI source distribution and says so.

Two identical builds in one pinned toolchain show deterministic output under
those conditions. They are not independent, diverse rebuilds. The base image,
Alpine package repository, GitHub Actions runner, and BuildKit remain part of
the trust path. The full Alpine closure is version-pinned and checked against
the installed database, so repository drift fails the build instead of
silently changing it. The workflow also records that closure and publishes
signed provenance.

The application image doesn't consume this wheelhouse yet. Until a follow-up
change replaces its locked upstream wheels with a verified wheelhouse digest,
the open native-wheel findings in
[issue #18](https://github.com/stampbot/extra-codeowners/issues/18) still apply.

See [Update the native wheelhouse](../how-to/update-native-wheelhouse.md) for
the maintainer procedure.

[inputs]: https://github.com/stampbot/extra-codeowners/blob/main/containers/native-wheelhouse/inputs.json
