# Command-line reference

In the locked development environment, run the command line through `uv`:

```bash
uv run python -m extra_codeowners --help
```

An installed package provides the equivalent `extra-codeowners` executable.

## Global options

These options apply to the top-level command:

| Option | Meaning |
| --- | --- |
| `--help` | Print the command list and exit. |
| `--show-completion` | Print completion setup for the current shell. Review the output before applying it. |
| `--install-completion` | Install completion for the current shell. This changes the current user's shell configuration. |

## `serve`

`serve` starts the FastAPI webhook service, the in-process durable worker, and the scheduled reconciler.

```text
uv run python -m extra_codeowners serve [OPTIONS]
```

`serve` accepts these options:

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | string | Current `EXTRA_CODEOWNERS_HOST` value | Bind address. A command-line value overrides the environment. |
| `--port` | integer | Current `EXTRA_CODEOWNERS_PORT` value | Bind port from `1` through `65535`. A command-line value overrides the environment. |
| `--help` | flag | off | Print command help and exit. |

All other service configuration comes from the typed [runtime settings](configuration.md#runtime-settings). Uvicorn access logs are disabled because the App Manifest callback puts a one-use code in its query string. Structured application logs provide operational context without recording request URLs.

The command exits nonzero if startup configuration is invalid or the server cannot bind.

In production mode, startup rejects:

- missing GitHub App credentials
- a webhook secret shorter than 32 bytes
- a GitHub API URL that does not use HTTPS
- a database URL that does not use the exact `postgresql+psycopg` driver
- a PostgreSQL URL without one explicit host, database, username, and nonempty
  password
- a remote PostgreSQL URL that does not use `sslmode=verify-full`
- any ambient libpq connection variable.

The weaker `require` and `verify-ca` modes are rejected because they do not
verify the database hostname. Every production URL must name exactly one
nonempty host or Unix-socket path; hostless and comma-separated multi-host URLs
are rejected. TLS may be omitted only for `localhost`, `127.0.0.1`, `::1`, a
Unix-socket path, or a local-proxy path. A query-string `host` overrides the
URL authority only when the authority omits its host. A `hostaddr` is allowed
only with that explicit host and `sslmode=verify-full`.

Connection-service URLs, `PGSERVICE`, `PGSERVICEFILE`, `.pgpass`, and
`PGPASSFILE` are unsupported. The URL accepts only `host`, `hostaddr`,
`sslmode`, and `sslrootcert` query parameters. `sslrootcert` must be a nonempty
absolute path. Percent-encode reserved characters in the required username and
password. The process pins `search_path=public`; caller-supplied `options` are
rejected.

See the [runtime settings reference](configuration.md#service-settings) for
the complete ambient-variable denylist. The same production database rules
apply to `database migrate`, `database check`, `queue-status`, and
`requeue-dead`.

Setup mode also requires a setup-state secret containing at least 32 bytes and an HTTPS public URL that contains only an origin—no credentials, path, query, or fragment.

## `database migrate`

`database migrate` upgrades the configured database to the one Alembic head
bundled with the installed application. It then validates the required release
contract, even when the database was already at that head.

```bash
uv run python -m extra_codeowners database migrate \
  --lock-timeout-seconds 60
```

The migration options are:

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--lock-timeout-seconds` | number | `60` | Wait from `0.1` through `300` seconds for the migration lock. |
| `--adopt-pre-alembic-schema` / `--no-adopt-pre-alembic-schema` | flag | off | In the `0.1.0` artifact only, adopt an unversioned schema that exactly matches immutable revision `0001_initial_schema` and whose provenance and backup the operator has verified. |
| `--help` | flag | off | Print command help and exit. |

On success, the final line names the bundled revision:

```text
Database is at migration 0003_shared_head_epochs.
```

Production mode applies the same PostgreSQL and transport checks as `serve`. A
PostgreSQL migration takes a session advisory lock, waits no longer than the
selected lock timeout, limits each SQL statement to 60 seconds, and pins
`search_path=public`. PostgreSQL releases the lock if the migrator's connection
closes after a failure or interruption.

The success line appears only after Alembic reaches the expected head and the
required release contract passes. A database already at the expected head
still receives that validation. A mismatch exits nonzero; the migrator does
not repair an unexpected schema that happens to carry the right revision.

Normal application startup never runs migrations. Read the [upgrade and restore procedure](../how-to/upgrade.md) before using the adoption flag. Every change to the Alembic head requires a database restore before an older artifact can start again; additive SQL is not an exception.

## `database check`

`database check` inspects the configured database without changing it.

```bash
uv run python -m extra_codeowners database check
```

On success, the final line names the compatible revision:

```text
Database migration 0003_shared_head_epochs is compatible.
```

The command exits nonzero when it cannot connect or when the required release
contract is missing or wrong. It checks:

- the single Alembic revision and application compatibility marker
- every required table and its exact column set
- column types, lengths, nullability, PostgreSQL time-zone mode, defaults,
  identities, computed values, autoincrement behavior, and canonical owned
  integer-sequence type, start, increment, bounds, cache, and cycle settings
- ordered, exact-named primary keys and exact named unique constraints
- exact named index columns, uniqueness, predicates, and supported options
- exact named check-constraint expressions
- the absence of foreign keys on required application tables
- safe PostgreSQL constraint and index catalog states.

For PostgreSQL, expected primary-key, unique, and check constraints must be
validated and nondeferrable. The primary-key and unique backing indexes, along
with the other expected indexes, must have their canonical immediate, valid,
ready, live `btree` state, uniqueness, and predicate.

This is the application's `required-release-contract`, not a universal proof
of every object or policy in the database. It does not print the database URL
or stored repository metadata.

## `validate-policy`

`validate-policy` parses repository policy and, optionally, organization policy without contacting GitHub.

```text
uv run python -m extra_codeowners validate-policy \
  --repository REPOSITORY_POLICY_FILE \
  [--organization ORGANIZATION_POLICY_FILE]
```

The validation options are:

| Option | Type | Required | Meaning |
| --- | --- | --- | --- |
| `--repository` | readable file path | yes | Repository policy to parse. Its default runtime location is `.github/extra-codeowners.toml`. |
| `--organization` | readable file path | no | Organization policy to parse. At runtime, both policy types use the configured policy path. |
| `--help` | flag | no | Print command help and exit. |

On success, the final line is:

```text
Policy files are valid.
```

The command exits nonzero for an unreadable or missing file, invalid TOML, unknown fields, an unsupported schema version, invalid application identities or aliases, invalid owners or delegation patterns, conflicting labels, and other policy-model constraints. When `--organization` is present, the command also compiles the two files together and rejects a repository delegation that names an unenrolled application alias.

Offline validation cannot prove that:

- an enrolled App ID, bot user ID, or slug exists on GitHub
- the App installation can read the target and organization-policy repositories
- a repository delegation alias exists in organization policy when `--organization` was omitted
- the repository's actual `CODEOWNERS` file and owners are valid on GitHub
- a pull request currently has enough review evidence.

The GitHub check fails closed when live evidence is missing or invalid.

## `queue-status`

`queue-status` reports aggregate counts from the configured durable database.

```bash
uv run python -m extra_codeowners queue-status
```

Sample output:

```text
pending=3 dead=0
```

`pending` includes pending and currently leased exact-head invalidation,
pull-request evaluation, and authority fan-out rows. `dead` counts legacy or
manually introduced terminal evaluation and authority rows. The command reads
`EXTRA_CODEOWNERS_DATABASE_URL` and does not show repository names,
pull-request numbers, errors, or delivery IDs.

The command is read-only and requires the exact database revision used by the installed application.

Exit status has the following meaning:

| Exit status | Meaning |
| --- | --- |
| `0` | The database was reachable and both counts were returned. |
| Nonzero | Settings validation, connection, or schema compatibility failed. |

## `requeue-dead`

`requeue-dead` returns a bounded batch of terminal rows to the pending queue. Current workers never create terminal rows: evaluation and authority failures stay pending and retry indefinitely. Migration `0002_retry_dead_jobs` also reactivates rows left by the earlier pre-release retry contract.

This command remains available as a compatibility recovery hook. It selects the oldest authority fan-out rows first, then fills any remaining batch capacity with the oldest pull-request evaluation rows.

```bash
uv run python -m extra_codeowners requeue-dead --limit 100
```

The recovery options are:

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--limit` | integer | `100` | Requeue from `1` through `10000` rows. Authority rows are selected before evaluation rows. |
| `--help` | flag | off | Print command help and exit. |

Sample output:

```text
requeued=1
```

This command changes durable state. For each selected row, it clears the lease and last error, resets the attempt count, and makes the row immediately available as `pending`. A worker then fetches current GitHub and policy evidence; stored scheduling hints never count as approval evidence.

`requeue-dead` is not routine retry control. Current pending work retries on its own, and operators must not create terminal rows manually. After the underlying dependency, permission, rate-limit, or evidence problem is corrected, recovery appears in `queue-status`, worker logs, and the check on the current head.
