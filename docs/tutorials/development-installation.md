# Run a development installation

In this tutorial, we'll run Extra CODEOWNERS locally, connect it to a development GitHub App, and check that it is healthy. We'll use a disposable organization or test repository. The shared-commit behavior described in [Prepare repository rules](../how-to/prepare-repository-rules.md#3-verify-the-conjunction) means this installation must not protect production merges.

## Prerequisites

Before we begin, we'll need:

- Bash
- Git
- [mise](https://mise.jdx.dev/) installed
- permission to create a GitHub App and install it on a test repository
- an HTTPS forwarding service that can send public traffic to local port `8000`
- a standard `CODEOWNERS` file in the test repository.

Our forwarding service must preserve the raw request body and GitHub signature headers. We'll keep `/metrics` off its public URL.

## 1. Install the pinned tools and dependencies

From the repository root, we'll run:

```bash
mise install
uv sync --all-groups
```

Mise should install the versions in `mise.toml`. Uv should then create `.venv` without a dependency-resolution error.

## 2. Start HTTPS forwarding

We'll configure the forwarding service to send a public HTTPS origin to `http://127.0.0.1:8000`. We need to record the origin without a trailing path. This tutorial uses a reserved example value:

```text
https://extra-codeowners-tutorial.example.com
```

We'll replace that value with the origin from our forwarding service and leave the forwarding process running in a separate terminal.

## 3. Register a development GitHub App

In GitHub's **Developer settings**, we'll create a GitHub App with a unique name that marks it as a development App. We'll give it these settings:

- **Webhook URL:** `https://YOUR_FORWARDING_ORIGIN/webhooks/github`
- **Webhook secret:** a new random secret for this development App
- **Repository permissions:** Checks read and write; Contents read; Pull requests read; Statuses read and write
- **Organization permissions:** Members read
- **Subscribe to events:** Check run, Installation target, Label, Member, Membership, Organization, Pull request, Pull request review, Push, Repository, Team, and Team add

GitHub automatically delivers Installation and Installation repositories events to every App, so we can't select them as subscriptions. Extra CODEOWNERS handles both events.

GitHub grants Metadata read implicitly. Statuses write makes the App available as an expected source in organization-level rulesets, but Extra CODEOWNERS downscopes runtime tokens so they can't write commit statuses. We won't grant Issues, Actions, Workflows, Administration, or Pull requests write access.

Next, we'll generate a private key for the App and save it outside the repository. We'll install the App only on our test repository and the organization-policy repository, which is the organization's `.github` repository by default. The [permission reference](../reference/github-permissions.md) explains each permission and event.

## 4. Configure the local process

We'll copy the checked-in safe defaults and then edit `.env` in the repository root:

```bash
cp .env.example .env
```

Git ignores this file. We'll uncomment the credential settings and make the relevant entries equivalent to these:

```dotenv
EXTRA_CODEOWNERS_ENVIRONMENT=development
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/absolute/path/to/development-app.private-key.pem
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET=replace-with-the-development-webhook-secret
EXTRA_CODEOWNERS_DATABASE_URL=sqlite:///./extra-codeowners.db
```

We'll replace the App ID, absolute private-key path, and webhook secret. The example App ID is not valid configuration. We registered the public forwarding URL directly in the development App, so we need `EXTRA_CODEOWNERS_PUBLIC_URL` only if we use the optional App Manifest setup flow. The [configuration reference](../reference/configuration.md#runtime-settings) describes every setting copied from `.env.example`.

File-mounted secrets are the preferred deployment method. We use the inline webhook-secret variable only for this local tutorial; a deployment can set `EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE` instead.

## 5. Migrate and start Extra CODEOWNERS

From the repository root, we'll create or upgrade the local development schema
explicitly, then start the service:

```bash
uv run python -m extra_codeowners database migrate
uv run python -m extra_codeowners serve
```

Normal service startup never creates or upgrades tables. If the migration
fails, we'll fix that error before starting the service.

It listens on `127.0.0.1:8000` by default. We'll leave it running and open another terminal in the repository root.

First, we'll check liveness:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/live
```

Then we'll check readiness:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/ready
```

Both commands should exit with status `0` and report `worker` and `reconciler` as `true`. Liveness and readiness fail if either configured local background task stops. Readiness also fails if the database or required GitHub credentials are unavailable. If a probe fails, we'll inspect the local service log without copying secret values into an issue.

## 6. Configure policy and exercise the check

We'll follow [Configure organization and repository policy](../how-to/configure.md), then [Prepare repository rules](../how-to/prepare-repository-rules.md) in the test repository.

Now we'll open a pull request that changes a delegated file. After GitHub sends an event, the service should accept a durable job and publish `Extra CODEOWNERS / approval` for the current head. The check stays non-successful until an appropriate human or enrolled application supplies the required approval.

We'll know the installation works when:

- GitHub shows a verified delivery to `/webhooks/github`
- the local readiness probe remains successful
- a Check Run from the development Extra CODEOWNERS App appears on the pull request
- the negative tests in the configuration guide behave as documented.

## 7. Run the project checks

We'll stop the server with `Ctrl-C`, then run:

```bash
mise run check
```

The source, workflow, Markdown, test, documentation, and Helm checks should all pass.

This fast local task does not enforce the coverage threshold. It also skips PostgreSQL-only tests when `TEST_POSTGRES_URL` is absent. To exercise the complete database suite and enforce the project's coverage threshold, we'll provision a disposable PostgreSQL test database and run:

```bash
read -rsp 'Disposable PostgreSQL test URL: ' TEST_POSTGRES_URL
printf '\n'
export TEST_POSTGRES_URL
mise run test:coverage
unset TEST_POSTGRES_URL
```

At the hidden prompt, we'll enter a percent-encoded URL such as `postgresql+psycopg://TEST_USER:TEST_PASSWORD@127.0.0.1:5432/extra_codeowners_test`, with the placeholders replaced. The prompt keeps the value out of normal shell history; we'll keep it out of support logs too.

The database name must end in `_test`. The suite refuses any other name, then drops and recreates Extra CODEOWNERS tables in that database. We'll never point this variable at a production or shared database. CI runs this path against an ephemeral, digest-pinned PostgreSQL service.

## Clean up

We built a working local Extra CODEOWNERS installation and watched it evaluate a delegated pull request. Now we'll remove its credentials and test state:

1. We'll uninstall or suspend the development GitHub App.
2. We'll delete its private key in GitHub.
3. We'll stop the HTTPS forwarding process.
4. We'll delete `.env` and the local `extra-codeowners.db` file.
5. We'll remove test policy and repository-rule changes that we no longer need.
