# AGENTS.md

Guidance for AI coding agents working in this repository. People should start
with [CONTRIBUTING.md](CONTRIBUTING.md); this file points agents at the same
rules and adds the reading order for design documents.

## What this project is

Extra CODEOWNERS is a self-hosted GitHub App. It publishes a required Check Run
that accepts either a human CODEOWNER approval or an enrolled App's approval
for delegated paths. It takes part in pull-request authorization, so a bug can
let a change merge without the review it needed. Fail closed when in doubt.

The service is Python with FastAPI, SQLAlchemy, and Alembic, backed by
PostgreSQL in production and SQLite for local development. It ships as a
container image and a Helm chart.

## Commands

Tools come from `mise.toml` and Python dependencies from `uv.lock`. Review
`mise.toml` before running `mise trust`.

```shell
mise install
mise run bootstrap   # uv sync --all-groups --frozen
mise run format      # ruff format
mise run check       # lint, tests, strict docs build, workflow and Helm checks
```

Run a single test with `uv run pytest tests/test_evaluator.py -k <name>`.
PostgreSQL tests run only when `TEST_POSTGRES_URL` points at a disposable
database whose name ends in `_test`; the suite drops and recreates tables.

## Rules for changes

- Every commit needs a DCO `Signed-off-by` trailer, and CI enforces it. Add one
  with `git commit --signoff` only when the person you're working for
  certifies the DCO for the change. Never add a sign-off for someone else.
- Use conventional commit subjects. The release planner reads them, and a
  `Release-Channel:` trailer changes the release channel; read
  [CONTRIBUTING.md](CONTRIBUTING.md#choose-a-release-channel) before using one.
- Use clearly fictional fixtures. Never put real GitHub payloads, credentials,
  organization identifiers, or private repository content in tests or docs.
- Schema changes need an Alembic revision, fresh-install and upgrade tests, and
  an entry in `docs/reference/upgrade-notes.md`. Startup never migrates.
- Don't run the live GitHub contract fixture; it's destructive and needs a
  disposable organization.

## Design documents

Read these before changing the system's behavior:

1. `docs/explanation/architecture.md` for how the service works
2. `docs/explanation/threat-model.md` for the invariants a change must keep
3. Accepted ADRs in `docs/explanation/adrs/` for decisions a change must
   respect
4. `docs/reference/project-status.md` for what's supported and what's still
   open

When documents disagree, an Accepted ADR wins over a living page, and a living
page wins over a proposal or an open issue. Issues define the scope of current
work but never override an Accepted ADR. Nothing overrides a threat-model
invariant: if a document or change conflicts with one, keep the fail-closed
behavior and report the conflict. Report any other conflict instead of
silently resolving it.

The pages under `docs/explanation/` and `docs/reference/` describe the current
state. When a change alters behavior, update the affected pages in the same
pull request, and put the history in an ADR, the changelog, or the commit
message. Dated test results belong in `docs/maintainers/live-validation.md`.

Requirements have stable IDs of the form `XCO-NNN`: the threat model's
invariants and the architecture page's design rules. A test that verifies one
names its ID in a comment, such as `# Verifies XCO-002.`, so the requirement
can be traced to its proof. Never reuse a retired ID.

`.trellis.yaml` records these conventions for the trellis documentation
skills. This repository keeps every decision record here; it has no shared ADR
home.

## Documentation

The manual uses Diátaxis: `tutorials/`, `how-to/`, `reference/`, and
`explanation/`. `mkdocs.yml` lists every page explicitly and builds with
`--strict`, so a new page needs a nav entry. ADRs go in the nav in date order
and in `docs/explanation/adrs/index.md`.
