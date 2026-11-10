# Respond to a dependency-audit failure

The weekly `Dependency audit` workflow checks the locked application,
development, and documentation dependencies against the public Open Source
Vulnerabilities service. It audits the locked package variants in one job and
can also be dispatched by a maintainer. Python compatibility testing still
runs separately for 3.12, 3.13, and 3.14 in ordinary CI.

A green run describes that commit at that time. A new advisory can appear
later.

## Before you begin

For a local reproduction, use a clean checkout with Git and
[mise](https://mise.jdx.dev/getting-started.html). The audit needs outbound
HTTPS access to `api.osv.dev` and any configured package index. Package names
and versions are sent to the public OSV service; GitHub credentials are not
needed.

To inspect or dispatch the hosted workflow, authenticate GitHub CLI with an
account that may run Actions and read results:

```bash
gh auth status
```

Confirm the account and GitHub host before continuing.

## What the workflow proves

The job installs the interpreter named by `.python-version`, then runs:

```bash
uv --no-cache \
  --no-python-downloads \
  --preview-features audit-command audit \
  --locked
```

`--locked` turns lockfile drift into an error instead of resolving a different
environment. Pinned uv uses the project's interpreter to validate the lock,
then audits its package variants rather than running those packages on each
Python line. Its `--python-version` option does not override interpreter
discovery; installing only a matrix interpreter could leave the project's
pinned interpreter unavailable. The job forbids uv from downloading
a substitute. It has read-only repository permission, no OIDC or
publication authority, no persistent uv cache, and a ten-minute timeout.

This network-dependent control does not run on pull requests. An OSV outage
therefore cannot freeze unrelated changes. Pull requests still run GitHub's
dependency review and deterministic toolchain checks.

## Classify the failure

Open the failed audit job and match the result to one of these cases:

| Failure | What it means | Response |
| --- | --- | --- |
| Active advisory | A locked package variant has a known vulnerability. | Confirm the package, version, and advisory. Update the requirement and lockfile, run the full test matrix, then rerun the audit. Use the private [security policy](https://github.com/stampbot/extra-codeowners/security/policy) when exploitability or an undisclosed weakness needs discussion. |
| Withdrawn or adverse release | A locked version is no longer acceptable upstream—for example, an index quarantined or withdrew it. | Treat the event as a supply-chain incident. Verify the upstream project and index record, select a reviewed replacement, regenerate the lockfile, and rerun tests and audit. Do not restore an unknown file from local cache. |
| OSV or network failure | The job did not obtain a complete answer. | Check service status and runner networking, then rerun the same commit. If the outage continues, record evidence from an independent advisory source and leave the failed run visible. Do not add an ignore to hide an outage. |
| Lockfile or resolution mismatch | `uv.lock` does not describe the checked-out project. | Reproduce with the pinned uv version, change project metadata and lockfile together, and run all supported Python tests. |
| Missing interpreter | uv cannot find the Python named by `.python-version`. | Install that interpreter. An audit target flag does not replace the project's interpreter requirement. Don't enable implicit downloads to hide a runner setup error. |

A scheduled failure does not add a new check to an already-open pull request.
Maintainers must identify affected open changes and any published artifacts,
pause publication when needed, and carry remediation through normal review.

## Reproduce locally

Review the checked-out revision and `mise.toml` before trusting it. `mise
trust` permits repository configuration and tasks to execute locally. Then
install the pinned tools and audit the lock:

```bash
mise trust
mise install
mise exec -- uv --no-cache \
  --no-python-downloads \
  --preview-features audit-command audit \
  --locked
```

The same locked package variant should fail locally. A network
failure remains an unknown result, not a clean audit.

## Dispatch and verify a hosted rerun

Run the control against the default branch:

```bash
gh workflow run dependency-audit.yml --ref main
gh run list \
  --workflow dependency-audit.yml \
  --branch main \
  --event workflow_dispatch \
  --limit 1 \
  --json databaseId,headSha,status,conclusion,url
```

Before using the listed run as evidence, confirm that `headSha` is the intended
`main` commit. Open its URL or pass `databaseId` to `gh run watch`.

Record the commit, pinned interpreter, advisory or outage evidence, remediation,
and successful rerun in the issue or pull request. Leave out credentials,
private index URLs, and environment dumps.

## When the uv audit interface changes

The `tooling` dependency group pins uv, and `uv.lock` records its exact version
and package hashes. CI's setup action and Read the Docs read that lockfile.
`mise.toml` installs the same local version, and the Dockerfile pins the matching
uv image by digest. The tooling group isn't installed in the application image.

`[tool.uv].required-version` is a compatibility minimum, not a build-version
selector. Dependabot runs its own uv version to update the lockfile. An exact
compatibility requirement would reject that updater before it could propose a
security fix. A newer updater still has to produce a lockfile that passes CI
with our pinned toolchain; CI doesn't silently adopt the updater's version.

Renovate groups the tooling dependency, local tool, and container image as one
`uv toolchain` update. Dependabot still owns GitHub Action updates while
[#160](https://github.com/stampbot/extra-codeowners/issues/160) verifies the
Renovate handoff. Review the upstream release notes and image digest before
merging, and don't bypass
`test_toolchain_configuration.py` when it reports drift.
