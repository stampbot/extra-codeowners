# Command-line reference

Run the command line through the locked development environment:

```bash
uv run python -m extra_codeowners --help
```

An installed package also exposes the equivalent `extra-codeowners` executable.

## Global options

| Option | Meaning |
| --- | --- |
| `--help` | Show the command list and exit. |
| `--show-completion` | Print shell-completion setup for the current shell. Review the output before applying it. |
| `--install-completion` | Install completion for the current shell; this changes that user's shell configuration. |

## `serve`

Run the FastAPI webhook service, in-process durable worker, and scheduled reconciler:

```bash
uv run python -m extra_codeowners serve [OPTIONS]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | string | Runtime `EXTRA_CODEOWNERS_HOST` value | Bind address. The command-line value overrides the environment. |
| `--port` | integer | Runtime `EXTRA_CODEOWNERS_PORT` value | Bind port from `1` through `65535`. The command-line value overrides the environment. |
| `--help` | flag | off | Show command help and exit. |

All other service configuration comes from the typed [runtime settings](configuration.md#runtime-settings). Uvicorn access logs are disabled because the App Manifest callback carries a one-use code in its query string; structured application logs provide operational context without recording request URLs.

The command exits nonzero when startup configuration is invalid or the server cannot bind. Production mode rejects missing GitHub App credentials, a webhook secret shorter than 32 bytes, a non-HTTPS GitHub API URL, a non-PostgreSQL database, or a non-local database URL without `sslmode=verify-full`. The weaker `require` and `verify-ca` modes are rejected because they do not verify the database hostname. An effective `localhost`, `127.0.0.1`, `::1`, or Unix-socket/proxy `host` may omit TLS; query-string `host` takes precedence over the URL authority, and any `hostaddr` or `service` override requires `verify-full`. Setup mode rejects a non-HTTPS or missing public URL and a setup-state secret shorter than 32 bytes.

## `validate-policy`

Parse and validate repository policy and, optionally, organization policy without contacting GitHub:

```text
uv run python -m extra_codeowners validate-policy \
  --repository REPOSITORY_POLICY_FILE \
  [--organization ORGANIZATION_POLICY_FILE]
```

| Option | Type | Required | Meaning |
| --- | --- | --- | --- |
| `--repository` | readable file path | yes | Repository policy file to parse; its runtime default location is `.github/extra-codeowners.toml`. |
| `--organization` | readable file path | no | Organization policy file to parse; it uses the same runtime policy path. |
| `--help` | flag | no | Show command help and exit. |

Success output:

```text
Policy files are valid.
```

The command exits nonzero for missing files, invalid TOML, unknown fields, unsupported schema versions, invalid App aliases or IDs, invalid owners, invalid delegation patterns, conflicting labels, and other model constraints. When `--organization` is supplied, it also compiles organization guardrails and rejects repository references to unenrolled application aliases.

Validation is intentionally offline. It does not prove that:

- an enrolled App ID, bot user ID, or slug exists on GitHub;
- the App installation can read both repositories;
- a repository delegation alias exists in organization policy when `--organization` was omitted;
- CODEOWNERS patterns and owners are valid on GitHub; or
- a pull request currently has sufficient review evidence.

The GitHub check fails closed on unresolved live conditions.

## `queue-status`

Report aggregate pending and legacy terminal pull-request evaluation and authority fan-out job counts in the configured durable database:

```bash
uv run python -m extra_codeowners queue-status
```

Sample output:

```text
pending=3 dead=0
```

The command uses `EXTRA_CODEOWNERS_DATABASE_URL`. It does not display repository names, pull-request numbers, errors, or delivery IDs. It initializes missing database tables, so pointing it at a new database is a schema-creating side effect; verify the database URL before running it. Initialization also reactivates any terminal `dead` rows created by an incompatible pre-release build, because current runtime failures retry indefinitely.

Exit status `0` means the database was reachable and counts were returned. Nonzero means settings, connection, or schema initialization failed.

## `requeue-dead`

Requeue a bounded batch of legacy or manually created terminal rows. Current workers do not create this state: evaluation and authority failures remain pending and retry indefinitely, and database initialization automatically reactivates rows left by the earlier pre-release retry contract. This command remains only as a compatibility recovery hook. If such rows are introduced after initialization, it prioritizes oldest authority fan-out rows before oldest pull-request evaluation rows so broad revocation work resumes first:

```bash
uv run python -m extra_codeowners requeue-dead --limit 100
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--limit` | integer | `100` | Maximum legacy terminal rows to requeue, inclusive range `1` through `10000`. Oldest authority rows are selected first, followed by oldest evaluation rows when capacity remains. |
| `--help` | flag | off | Show command help and exit. |

Sample output:

```text
requeued=1
```

This command changes durable state. It resets a selected legacy terminal row's attempt count, last error, lease, and availability, then makes it immediately pending. Workers re-fetch current GitHub and policy evidence; stored scheduling hints are never treated as approval evidence.

Do not use this command as routine retry control or manually manufacture terminal rows. Current pending work retries automatically. Fix its dependency, permission, rate-limit, or evidence failure, then verify recovery with `queue-status`, sanitized worker logs, and a current-head check.
