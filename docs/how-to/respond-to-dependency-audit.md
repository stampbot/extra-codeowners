# Respond to a dependency audit

The `Dependency audit` workflow checks the locked application, development, and documentation dependencies against uv's advisory service every Monday for Python 3.12, 3.13, and 3.14. Maintainers can also run it on demand. A successful run is point-in-time evidence, not a guarantee that a new advisory will not appear later.

## Understand the control

The workflow runs this command independently for every supported Python line:

```bash
uv --no-cache \
  --no-python-downloads \
  --preview-features audit-command audit \
  --locked \
  --python-version "PYTHON_VERSION"
```

The explicit preview-feature switch records that the repository intentionally uses uv's pinned audit interface. `--locked` makes a lockfile change an error; the audit cannot silently resolve a different environment. Each job selects its matrix Python version and forbids uv from downloading a substitute interpreter. The job has read-only repository permission, uses no persistent uv cache, has no publishing or OIDC permission, uploads no artifact, and stops after ten minutes.

The network-dependent audit is not a pull-request trigger. An advisory-service outage therefore cannot freeze unrelated pull requests. Pull requests still run the deterministic toolchain consistency test and GitHub's dependency review. A pull request that changes dependencies may fail dependency review independently of this scheduled control.

## Triage a failed run

Open the failed matrix job and identify which of these conditions uv reported:

| Condition | Meaning | Response |
| --- | --- | --- |
| Known vulnerability | At least one dependency selected for that Python version has an active advisory. | Confirm the affected package and version against the linked advisory. Update the requirement and lockfile, run the complete test matrix, and rerun the audit. Follow the private [security policy](https://github.com/stampbot/extra-codeowners/security/policy) when exploitability or an undisclosed weakness needs discussion. |
| Withdrawn or otherwise adverse package release | The locked package version is no longer an acceptable upstream release, for example because the package index quarantined or deprecated it. | Treat unexpected withdrawal as a supply-chain event. Verify the upstream project and index record, choose a reviewed replacement, regenerate the lockfile, and rerun tests and the audit. Do not restore an untrusted file from a local cache. |
| Advisory-service or network failure | The audit could not obtain a complete answer. This is an unknown result, not a clean result. | Check the service status and runner network, then rerun the same commit. If the outage persists, use an independent advisory source as temporary evidence and keep the failed run visible. Do not add an ignore solely to hide an outage. |
| Lockfile drift or unsupported resolution | `uv.lock` does not describe the checked-out project for that Python line. | Reproduce with the pinned uv version, correct the project metadata and lockfile together, and run all supported Python tests. |

An audit failure does not retroactively add a failing check to an already-open pull request. Maintainers must assess affected releases and open changes, pause publication when necessary, and carry the remediation through normal review. The release workflow still installs only the reviewed lockfile; a scheduled failure must not be dismissed because release automation is technically able to run.

## Reproduce and verify

From a clean checkout, install the reviewed toolchain and run each supported resolution:

```bash
mise install
for python_version in 3.12 3.13 3.14; do
  mise exec -- uv --no-cache \
    --no-python-downloads \
    --preview-features audit-command audit \
    --locked \
    --python-version "$python_version"
done
```

To run the hosted control against the default branch:

```bash
gh workflow run dependency-audit.yml --ref main
gh run list --workflow dependency-audit.yml --limit 1
```

Inspect the selected run in GitHub Actions or pass its numeric ID to `gh run watch`. Record the commit, affected Python version, advisory identifier or outage evidence, and the clean rerun in the remediation issue or pull request. Do not paste credentials, private index URLs, or environment dumps into the record.

## Update uv without creating drift

`mise.toml` is the reviewed version source. The Dockerfile's digest-pinned uv image and every `astral-sh/setup-uv` invocation must use the same version. Renovate owns the uv image, runtime strings, image digest, and setup action as one `uv toolchain` update; Dependabot intentionally ignores only `astral-sh/setup-uv`.

Review the proposed release notes and image digest before merging an update. The `test_toolchain_configuration.py` regression test fails if local development, containers, or hosted workflows diverge. Do not bypass that test or manually update only one location.
