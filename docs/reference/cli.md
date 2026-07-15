# Command-line reference

The locked development environment exposes the command line through `uv`:

```bash
uv run python -m extra_codeowners --help
```

An installed package exposes the equivalent `extra-codeowners` executable.

## Global options

| Option | Meaning |
| --- | --- |
| `--help` | Show the command list and exit. |
| `--show-completion` | Print shell-completion setup for the current shell. Review the output before applying it. |
| `--install-completion` | Install completion for the current shell; this changes that user's shell configuration. |

## `serve`

`serve` runs the FastAPI webhook service, in-process durable worker, and scheduled reconciler:

```bash
uv run python -m extra_codeowners serve [OPTIONS]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | string | Runtime `EXTRA_CODEOWNERS_HOST` value | Bind address. The command-line value overrides the environment. |
| `--port` | integer | Runtime `EXTRA_CODEOWNERS_PORT` value | Bind port from `1` through `65535`. The command-line value overrides the environment. |
| `--help` | flag | off | Show command help and exit. |

All other service configuration comes from the typed [runtime settings](configuration.md#runtime-settings). Uvicorn access logs are disabled because the App Manifest callback carries a one-use code in its query string. Structured application logs provide operational context without recording request URLs.

The command exits nonzero when startup configuration is invalid or the server cannot bind.

Production mode rejects:

- missing GitHub App credentials
- a webhook secret shorter than 32 bytes
- a non-HTTPS GitHub API URL
- a non-PostgreSQL database
- a non-local database URL without `sslmode=verify-full`.

The weaker `require` and `verify-ca` modes are rejected because they do not verify the database hostname. An effective `localhost`, `127.0.0.1`, `::1`, or Unix-socket/proxy `host` may omit TLS. A query-string `host` takes precedence over the URL authority. Any `hostaddr` or `service` override requires `verify-full`.

Setup mode rejects a non-HTTPS or missing public URL and a setup-state secret shorter than 32 bytes.

## `database migrate`

Upgrade the configured database to the single Alembic head bundled with the
installed application:

```bash
uv run python -m extra_codeowners database migrate \
  --lock-timeout-seconds 60
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--lock-timeout-seconds` | number | `60` | Wait longer than `0` and at most `300` seconds for the migration lock. |
| `--adopt-pre-alembic-schema` | flag | off | After a verified backup, adopt only the exact schema produced by documented pre-release builds. |
| `--help` | flag | off | Show command help and exit. |

Production mode applies the same PostgreSQL and transport validation as the
service. PostgreSQL migration calls obtain a session advisory lock and limit
each statement to 60 seconds. Another migrator can wait only for the selected
lock timeout. A failed or interrupted process releases the lock when its
connection closes.

Normal application startup never runs this command. Read the [upgrade and
restore procedure](../how-to/upgrade.md) before using the adoption flag.

## `database check`

Verify the configured database without changing it:

```bash
uv run python -m extra_codeowners database check
```

Success prints the compatible Alembic revision. Missing or mismatched
revisions, tables, columns, primary keys, named unique constraints, indexes, or
the application compatibility marker exit nonzero. The database URL and stored
repository metadata are not printed.

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

Validation is offline. It does not prove that:

- an enrolled App ID, bot user ID, or slug exists on GitHub
- the App installation can read both repositories
- a repository delegation alias exists in organization policy when `--organization` was omitted
- CODEOWNERS patterns and owners are valid on GitHub
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

The command uses `EXTRA_CODEOWNERS_DATABASE_URL`. It does not display repository names, pull-request numbers, errors, or delivery IDs.

The command is read-only. It fails when the database has not been migrated to
the exact revision required by this application.

| Exit status | Meaning |
| --- | --- |
| `0` | The database was reachable and counts were returned. |
| Nonzero | Settings validation, connection, or schema compatibility failed. |

## `requeue-dead`

`requeue-dead` requeues a bounded batch of legacy or manually created terminal rows. Current workers do not create this state. Evaluation and authority failures remain pending and retry indefinitely. Migration `0002_retry_dead_jobs` reactivates rows left by the earlier pre-release retry contract.

The command remains as a compatibility recovery hook. If terminal rows appear
after migration, it selects the oldest authority fan-out rows first. It then
selects the oldest pull-request evaluation rows until the batch is full. This
order resumes broad revocation work first.

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

This command changes durable state. It resets each selected row's attempt count, last error, lease, and availability. The row becomes pending immediately. Workers re-fetch current GitHub and policy evidence. Stored scheduling hints never count as approval evidence.

This command is not routine retry control. Current pending work retries automatically. Terminal rows must not be created manually. After correcting the dependency, permission, rate-limit, or evidence failure, recovery is visible in `queue-status`, sanitized worker logs, and the current-head check.
