# Run a development installation

This tutorial starts Extra CODEOWNERS locally, connects a development GitHub App, and verifies its health endpoints. Use a disposable organization or test repository. Extra CODEOWNERS is pre-release software and is not ready to protect production merges.

## Prerequisites

You need:

- a POSIX-compatible shell;
- Git;
- [mise](https://mise.jdx.dev/) installed;
- permission to create a GitHub App and install it on a test repository;
- an HTTPS forwarding service that can send public traffic to local port `8000`; and
- a standard `CODEOWNERS` file in the test repository.

Choose an HTTPS forwarding service that preserves the raw request body and GitHub signature headers. Do not expose `/metrics` through the public forwarding URL.

## 1. Install the pinned tools and dependencies

From the repository root, run:

```bash
mise install
uv sync --all-groups
```

Expected result: mise installs the versions in `mise.toml`, and uv creates `.venv` without dependency-resolution errors.

## 2. Start HTTPS forwarding

Configure your forwarding service to send a public HTTPS origin to `http://127.0.0.1:8000`. Record the origin without a trailing path. This tutorial uses the reserved example value:

```text
https://extra-codeowners-tutorial.example.com
```

Replace that value with the origin supplied by your forwarding service. Keep the forwarding process running in a separate terminal.

## 3. Register a development GitHub App

In GitHub's **Developer settings**, create a GitHub App with a unique, development-specific name and:

- **Webhook URL:** `https://YOUR_FORWARDING_ORIGIN/webhooks/github`
- **Webhook secret:** a new random secret for this development App
- **Repository permissions:** Checks read and write; Contents read; Pull requests read; Statuses read and write
- **Organization permissions:** Members read
- **Subscribe to events:** Check run, Installation target, Label, Member, Membership, Organization, Pull request, Pull request review, Push, Repository, Team, and Team add

GitHub automatically delivers Installation and Installation repositories events to every App; they are not selectable subscriptions. Extra CODEOWNERS handles both automatic events.

GitHub grants Metadata read implicitly. Statuses write makes the App selectable as an expected source in organization-level rulesets; runtime tokens are downscoped so they cannot write commit statuses. Do not grant Issues, Actions, Workflows, Administration, or Pull requests write access.

Generate a private key for the App and save it outside the repository. Install the App on only the test repository and the configured organization-policy repository (the organization's `.github` repository by default). See the [permission reference](../reference/github-permissions.md) for why each permission and event is used.

## 4. Configure the local process

Copy the checked-in safe defaults, then edit `.env` in the repository root:

```bash
cp .env.example .env
```

The copied file is ignored by Git. Uncomment the credential settings and make the relevant entries equivalent to:

```dotenv
EXTRA_CODEOWNERS_ENVIRONMENT=development
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/absolute/path/to/development-app.private-key.pem
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET=replace-with-the-development-webhook-secret
EXTRA_CODEOWNERS_DATABASE_URL=sqlite:///./extra-codeowners.db
```

Replace the App ID, absolute private-key path, and webhook secret. Do not use the example App ID as real configuration. The public forwarding URL was already registered directly in the development App; `EXTRA_CODEOWNERS_PUBLIC_URL` is needed only by the optional App Manifest setup flow. The [configuration reference](../reference/configuration.md#runtime-settings) describes every setting copied from `.env.example`.

File-mounted secrets are preferred. The inline webhook-secret variable is used here only for a local tutorial; deployments can instead set `EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE`.

## 5. Start Extra CODEOWNERS

From the repository root, run:

```bash
uv run python -m extra_codeowners serve
```

The process listens on `127.0.0.1:8000` by default. Leave it running and open a new terminal in the repository root.

Verify liveness:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/live
```

Verify readiness:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/ready
```

Both commands should exit with status `0` and report `worker` and `reconciler` as `true`. Liveness and readiness fail when either configured local background task stops; readiness also fails when required GitHub credentials or the database are unavailable. Inspect the local service log without copying secret values into an issue.

## 6. Configure policy and exercise the check

Follow [Configure organization and repository policy](../how-to/configure.md), then [Prepare repository rules](../how-to/prepare-repository-rules.md) in the test repository.

Open a pull request that changes a delegated file. After GitHub sends an event, the service should accept a durable job and publish `Extra CODEOWNERS / approval` for the current head. The check remains non-successful until an appropriate human or enrolled application supplies the required approval.

Success means:

- GitHub shows a verified delivery to `/webhooks/github`;
- the local readiness probe remains successful;
- a Check Run from the development Extra CODEOWNERS App appears on the pull request; and
- the negative tests in the configuration guide behave as documented.

## 7. Run the project checks

Stop the server with `Ctrl-C`, then run:

```bash
mise run check
```

Expected result: source, workflow, Markdown, test, documentation, and Helm checks complete successfully.

This is the fast local path: it does not enforce the coverage threshold, and PostgreSQL-only tests skip when `TEST_POSTGRES_URL` is absent. To exercise the complete database suite and enforce the project's coverage threshold, provision a disposable PostgreSQL test database and run the dedicated coverage task with its SQLAlchemy URL:

```bash
read -rsp 'Disposable PostgreSQL test URL: ' TEST_POSTGRES_URL
printf '\n'
export TEST_POSTGRES_URL
mise run test:coverage
unset TEST_POSTGRES_URL
```

At the hidden prompt, enter a percent-encoded URL such as `postgresql+psycopg://TEST_USER:TEST_PASSWORD@127.0.0.1:5432/extra_codeowners_test` with the placeholders replaced. The prompt keeps the value out of normal shell history; keep it out of support logs as well. The database name must end in `_test`; the suite refuses any other name, then drops and recreates Extra CODEOWNERS tables in that database. Never point this variable at a production or shared database. CI exercises this path against an ephemeral, digest-pinned PostgreSQL service.

## Clean up

After the tutorial:

1. Uninstall or suspend the development GitHub App.
2. Delete its private key in GitHub.
3. Stop the HTTPS forwarding process.
4. Delete `.env` and the local `extra-codeowners.db` file.
5. Remove test policy and repository-rule changes that are no longer needed.
