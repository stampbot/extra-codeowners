# Debian source outage and reuse: November 5, 2026

A source-collection outage blocked publication even though the archive cache
was warm. A read-only prototype authenticated the previous immutable release's
source evidence and rebound all 61 source packages to the new inventories
without consulting Debian Snapshot. This is a collector preflight, not a
completed release or deployment.

## Failure evidence

Main CI [41972594159](https://github.com/stampbot/extra-codeowners/actions/runs/41972594159),
source `4aa5f4d6069bab4ef711e2b4b80d7c0365a2a953`, passed the source tests,
native container builds and scans. Its Debian source job restored a
313,149,167-byte cache, then failed to fetch metadata for `acl` `2.3.2-2`.
A failed-jobs retry failed at that lookup too. A separate read-only HTTP probe
of the metadata endpoint returned 504. The job's own error reported a failed
download, not an HTTP status.

No complete immutable release was published by those attempts. The cache held
archives, but `collect_bundle` still resolved every package through Snapshot
before checking cached archive bytes.

## Snapshot-independent preflight

The test used both native image inventories and child digests from that failed
main run. They are staging evidence, not a newly signed immutable release.
The retained sources came from completed immutable alpha.68, tag revision
`5acc54460ab4485710aa56b05f3a9ac280d75d74`.

The prototype fetched both old inventories and the Debian bundle, verified
their official release-workflow attestations against that revision and main
ref, and rejected self-hosted signers. It then verified the old bundle's
binding and contents, copied unchanged source bytes into a new bundle with
the current inventories' image binding, and verified that output. A separate
`verify` invocation against both new inventories also exited zero.

The resulting local bundle measured:

| Field | Result |
| --- | --- |
| Source packages | 61 |
| Bytes | 313,559,040 |
| SHA-256 | `8e6545813d44457d9ce2f656c6de64fbe9dff082aa096d2be63d565c9e59a6d0` |

This path contacted GitHub and Sigstore; it was independent of Snapshot, not
fully offline. Sigstore trust-root initialization first failed under the
restricted default cache location. Both trust repositories updated and
verified after the test used an owned workspace cache. No trust check was
disabled. An initial large-download deadline was also too short for the local
link; the final implementation allows 600 seconds per download while retaining
the CI job's overall 20-minute limit.

Focused tests cover old/new bindings, exact source-set matching, rejected
attestations, corrupt or linked inventories and bundles, immutable-release
selection, tag resolution, CLI result codes and overwrite prevention. They
use fictional fixtures and do not contact GitHub. Existing source and
workflow tests also pass. CI and immutable publication remain separate checks.

## Cleanup and limits

No application, cluster, installation selection, queue or registry artifact
was changed by this test. Downloaded native source archives not needed by the
preflight were removed. The disposable rebound tar is removed after its hash
and result are recorded; compact inventories, digests and private observations
remain in the maintainer's evidence directory.

This verifies the collector's reuse path, not distribution approval or the
upstream binaries' exact build inputs. The new bundle was not published or
signed as a release during the test. A changed source identity still requires
fresh collection. [Issue #264](https://github.com/stampbot/extra-codeowners/issues/264)
tracks publication recovery; [issue #18](https://github.com/stampbot/extra-codeowners/issues/18)
retains its independent source-delivery and approval gates.
