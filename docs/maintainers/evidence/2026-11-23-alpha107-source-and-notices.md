# Alpha.107 source and notice verification: November 23, 2026

The [main CI run][run] published [alpha.107][release] from
`9f87a4955bdf41c951bbbeeb6fbb3dfbe1436a7c` at 10:03:45 UTC. GitHub reports
release ID `455244258` as an immutable prerelease. No release operator had
to create a tag or upload an artifact.

## Check what was published

We started with empty download and checkout directories on Linux x86-64.
The tools were GitHub CLI 2.96.0, Cosign 3.1.2, Helm 4.2.3, and Python
3.12.13. We didn't start either container or change any deployment.

1. Verify GitHub's signed release record. Compare the downloaded names,
   sizes, and SHA-256 hashes with the attested list. All 42 assets matched,
   totaling 806,378,738 bytes.
2. Check out the release tag and verify its commit. Run the release
   provenance verifier from that checkout against the downloaded files. It
   checks the signature and GitHub Actions identity, the source revision,
   and the bindings between inventories, source archives, and image digests.
3. Read the registry's image index and compare both Linux child digests.
   Pull the chart from the registry and compare its bytes with the release
   asset. Use the [source archive reference][sources] to repeat the checks.

## Check what the archives cover

The source manifests matched the installed Python distribution list on both
images, including the project's own distribution, whose source ships as a
separate asset. Neither notice manifest reported unresolved declared files.
The two releases' Debian inventory, native wheel file hashes, and embedded
wheel SBOMs matched the previously verified alpha.106 baseline.

| Published evidence | amd64 | arm64 |
| --- | ---: | ---: |
| Python distributions accounted for | 51 | 51 |
| Files in the recipient notice bundle | 226 | 226 |
| CPython notice references | 14 | 12 |
| Entries in the wheel-native catalog | 13 | 14 |
| Bundled Psycopg libraries matched by path, size, and hash | 15 | 16 |
| Rust component references from the wheel SBOMs | 146 | 146 |

The shared Debian archive contained 61 source packages and 193 files. Each
CPython archive indexed its incorporated-software notices and retained pip
26.2.2, which is still shipped in an earlier image layer. The Rust archives
provided 134 crate archives, 242 indexed notice files, and three separately
retained upstream notice files per platform.

Every bundled Psycopg library matched a catalog entry and source archive.
The catalog also matched Cryptography's statically linked OpenSSL evidence
to the installed extension. The Python bundles supplied the additional CFFI,
Protobuf, and charset-normalizer sources or notices. Earlier
[replacement tests][replacement] established that both image architectures
could load compatible replacements for two Psycopg libraries. They did not
test a database connection with those replacements.

## Limits

The bundles supply version-matched source and recipes. They don't prove a
byte-for-byte reconstruction of upstream wheels. The charset-normalizer
wheel does not identify its mypyc build version. The bundle retains all
three candidates supported by the review, with their identical notice text.

This closes the technical source-delivery work in [issue #18][source-issue]
for the reviewed runtime. An empty list of unresolved declared files isn't
a legal determination. Nothing in this run changes the existing VEX
assessments or establishes that the App is ready for production enforcement.
The [Psycopg wheel refresh][psycopg] and [merge-queue work][queue] are separate.

[run]: https://github.com/stampbot/extra-codeowners/actions/runs/45147892388
[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.107
[sources]: ../../reference/source-archives.md
[replacement]: https://github.com/stampbot/extra-codeowners/issues/18#issuecomment-7094543063
[source-issue]: https://github.com/stampbot/extra-codeowners/issues/18
[psycopg]: https://github.com/stampbot/extra-codeowners/issues/341
[queue]: https://github.com/stampbot/extra-codeowners/issues/4
