# Extra CODEOWNERS

[![CI](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml)
[![Property testing](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml)
[![Coverage report](https://github.com/stampbot/extra-codeowners/actions/workflows/coverage-pages.yml/badge.svg)](https://stampbot.github.io/extra-codeowners/)
[![CodeQL](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/stampbot/extra-codeowners/badge)](https://scorecard.dev/viewer/?uri=github.com/stampbot/extra-codeowners)
[![Documentation](https://readthedocs.org/projects/extra-codeowners/badge/?version=latest)](https://extra-codeowners.readthedocs.io/)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12%E2%80%933.14-blue.svg)](https://www.python.org/) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Extra CODEOWNERS is a self-hosted GitHub App that uses an existing trusted
GitHub App's pull-request approval to satisfy `CODEOWNERS` for a small,
explicit set of paths. People and teams stay in the standard `CODEOWNERS`
file. App identity, paths, owners, and label restrictions live in separate
policy.

[Stampbot](https://github.com/dannysauer/stampbot) is the first planned
integration: let it approve `uv.lock`, while people keep the approval policy.

> [!CAUTION]
> Extra CODEOWNERS is alpha software. Don't replace GitHub's native **Require
> review from Code Owners** rule in production yet. The live contract still has
> open work in
> [issue #1](https://github.com/stampbot/extra-codeowners/issues/1).
> There is no supported release or image, hosted service, or Marketplace
> Action. An older public image may still be discoverable; do not deploy it.

## What the check does

GitHub documents `CODEOWNERS` for users and teams with write access. It does
not document GitHub App bot accounts as a supported owner type. Extra
CODEOWNERS keeps App authority out of that file instead of depending on
undocumented behavior.

```text
CODEOWNERS + human approval -----------------+
                                              +--> Extra CODEOWNERS / approval
App enrollment + delegation + App approval --+
```

The checker reads the current paths, labels, and reviews. Every effective
`CODEOWNERS` owner set needs an eligible human approval or an enrolled App
approval whose delegation covers the path, owner, and labels.

It does not submit reviews, grant an App repository access, or replace the
repository's ordinary approval count. It publishes one check:
`Extra CODEOWNERS / approval`.

## What policy looks like

The organization enrolls an App by numeric App ID, bot user ID, and slug. A
member repository opts in separately and grants a smaller scope:

```toml
schema_version = 1
enabled = true

[[delegations]]
app = "example-automation"
paths = ["/uv.lock"]
for_owners = ["@example-org/platform"]
required_labels = ["dependencies"]
```

This rule is useful only when organization policy also enrolls
`example-automation`. The complete, validated pair lives under
[`examples/policy/`](examples/policy/).

Approval policy, workflows, and local actions reject App substitution by
default. The
[threat model](docs/explanation/threat-model.md#what-the-insecure-changes-escape-hatch-changes)
explains additional guardrails and the process-wide insecure override.

## Run locally

From the repository root, with Bash, `curl`, and `mise` installed, review
`mise.toml` before allowing it to execute with `mise trust`. This smoke test
uses a temporary SQLite database and stops the server on exit. It still records
the `mise` trust decision, installs the pinned tools, and creates or updates
`.venv/`.

```bash
(
  set -euo pipefail

  if [[ -e .env ]]; then
    echo 'Move .env out of the repository before running this smoke test.' >&2
    exit 1
  fi
  if env | grep '^EXTRA_CODEOWNERS_' >/dev/null; then
    echo 'Unset existing EXTRA_CODEOWNERS_* variables first.' >&2
    exit 1
  fi

  smoke_root="$(mktemp -d)"
  server_pid=""
  # shellcheck disable=SC2329  # Invoked by the EXIT trap.
  cleanup() {
    exit_status=$?
    trap - EXIT INT TERM
    set +e
    if [[ -n "$server_pid" ]]; then
      kill "$server_pid" 2>/dev/null
      wait "$server_pid" 2>/dev/null
    fi
    find "$smoke_root" -mindepth 1 -delete
    rmdir "$smoke_root"
    exit "$exit_status"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  export EXTRA_CODEOWNERS_DATABASE_URL="sqlite:///${smoke_root}/smoke.db"
  export EXTRA_CODEOWNERS_WORKER_ENABLED=false
  export EXTRA_CODEOWNERS_RECONCILE_ENABLED=false
  mise trust
  mise install
  mise run bootstrap
  mise exec -- uv run python -m extra_codeowners database migrate
  mise exec -- uv run python -m extra_codeowners serve &
  server_pid=$!
  response="$(
    curl --silent --show-error --fail-with-body \
      --connect-timeout 2 --max-time 5 --retry-max-time 20 \
      --retry 10 --retry-connrefused --retry-delay 1 \
      http://127.0.0.1:8000/health/live
  )"
  if ! kill -0 "$server_pid" 2>/dev/null ||
    ! jobs -pr | grep -Fx "$server_pid" >/dev/null; then
    wait "$server_pid" || true
    echo 'Extra CODEOWNERS exited before the liveness check completed.' >&2
    exit 1
  fi
  expected='{"status":"alive","worker":true,"reconciler":true}'
  if [[ "$response" != "$expected" ]]; then
    printf 'Unexpected liveness response: %s\n' "$response" >&2
    exit 1
  fi
  printf '%s\n' "$response"
)
```

In that response, `true` means healthy. A disabled component counts as
healthy, and this smoke test disables both the worker and reconciler. The
response proves process liveness, not GitHub readiness or production safety.

## Try it safely

The [first-check tutorial](docs/tutorials/development-installation.md) ends
with a real check on a disposable pull request. Keep native enforcement on in
production; the
[project status](docs/reference/project-status.md) explains why.

## Documentation

| Task | Start here |
| --- | --- |
| Decide whether the trust model fits | [Native CODEOWNERS comparison](docs/explanation/native-codeowners.md) and [threat model](docs/explanation/threat-model.md) |
| Run the first check | [Development installation tutorial](docs/tutorials/development-installation.md) |
| Register the App through its setup URL | [App registration guide](docs/how-to/register-app.md) |
| Delegate paths to an App | [Configuration guide](docs/how-to/configure.md) |
| Understand a failed or pending check | [Check troubleshooting guide](docs/how-to/troubleshoot-check.md) |
| Understand the service design | [Architecture](docs/explanation/architecture.md) |
| Plan a deployment | [Deployment guide](docs/how-to/deploy.md) |
| Operate an installation | [Operations guide](docs/how-to/operate.md) |
| Look up exact behavior | [Configuration](docs/reference/configuration.md), [checks](docs/reference/checks.md), [CLI](docs/reference/cli.md), and [HTTP API](docs/reference/http-api.md) |

The full documentation is published on
[Read the Docs](https://extra-codeowners.readthedocs.io/).

## Community

- Ask for help under the [support policy](SUPPORT.md).
- Report vulnerabilities privately under the [security policy](SECURITY.md).
- Read the [contributor guide](CONTRIBUTING.md), [changelog](CHANGELOG.md),
  [governance](GOVERNANCE.md), and [maintainer documentation](docs/maintainers/index.md).
