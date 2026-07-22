# Run a development installation

This tutorial takes you from a clean checkout to a working Extra CODEOWNERS
check on a disposable pull request. You will run the service locally, connect a
development GitHub App, delegate one low-risk path, and verify both the success
and failure cases.

Do not use the result to protect production merges. The
[commit-scoped check limitation](../reference/project-status.md#production-enforcement-blocker)
still blocks production enforcement.

## What you need

- Bash and Git on a POSIX-compatible system
- [mise](https://mise.jdx.dev/)
- permission to create and install a GitHub App
- a disposable organization or repository
- an HTTPS forwarding service that can send public traffic to local port
  `8000`
- a standard `CODEOWNERS` file in the test repository.

The forwarding service must preserve the request body and GitHub signature
headers. Expose only the webhook and setup routes you need; keep `/metrics`
private.

## 1. Prepare the checkout

Review `mise.toml` before allowing it to install or run tools. From the
repository root:

```bash
mise trust
mise install
mise run bootstrap
```

Mise installs the pinned toolchain, and the bootstrap task creates `.venv` from
the committed lockfile. Stop here if dependency installation changes
`uv.lock` or cannot complete with the locked versions.

## 2. Give GitHub a temporary HTTPS endpoint

Start your forwarding service and point its public HTTPS origin at
`http://127.0.0.1:8000`. Keep the forwarding process open in another terminal.

Record only the origin, with no trailing path. This tutorial uses a reserved
example:

```text
https://extra-codeowners-tutorial.example.com
```

The webhook URL will be that origin plus `/webhooks/github`.

## 3. Create the development App

Create a private GitHub App with a name that clearly marks it as disposable.
You can use the [App setup URL](../how-to/register-app.md), which fills in the
permissions and webhook subscriptions, or enter the same settings manually in
GitHub's **Developer settings**.

For a manual registration, use:

- **Webhook URL:** `https://YOUR_ORIGIN/webhooks/github`
- **Webhook secret:** a new random value used only by this App
- **Repository permissions:** Checks read and write; Contents read; Pull
  requests read; Statuses read and write
- **Organization permissions:** Members read
- **Events:** Check run, Installation target, Label, Member, Membership,
  Organization, Pull request, Pull request review, Push, Repository, Team, and
  Team add.

GitHub supplies Metadata read automatically. It also delivers Installation and
Installation repositories events to every App, so those events do not appear
in the subscription picker.

Do not grant Issues, Actions, Workflows, Administration, or Pull requests write
access. Statuses write is present so an organization ruleset can identify this
App as an expected check source; Extra CODEOWNERS deliberately omits that
permission from the installation tokens it requests at runtime.

Generate a private key, save it outside the checkout, and install the App only
on:

1. the disposable target repository, and
2. the organization's policy repository, which is `.github` by default.

The [permissions reference](../reference/github-permissions.md) explains why
each permission and event is needed.

## 4. Configure the local service

Copy the development defaults:

```bash
cp .env.example .env
```

Git ignores `.env`. Edit it so these settings point to the development App:

```dotenv
EXTRA_CODEOWNERS_ENVIRONMENT=development
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/absolute/path/to/development-app.private-key.pem
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET=replace-with-the-development-webhook-secret
EXTRA_CODEOWNERS_DATABASE_URL=sqlite:///./extra-codeowners.db
```

Replace the App ID, key path, and webhook secret. The example values are not
usable credentials. An inline webhook secret is reasonable for this local
exercise; deployed installations should use the file-backed setting or a
secret manager.

`EXTRA_CODEOWNERS_PUBLIC_URL` is required only while the optional App setup
flow is enabled. Normal webhook handling uses the URL stored in GitHub's App
settings.

## 5. Start the service

Database migration is an explicit operator step. Run it before starting the
server:

```bash
mise exec -- uv run python -m extra_codeowners database migrate
mise exec -- uv run python -m extra_codeowners serve
```

Startup never creates or upgrades tables. Fix any migration error before
continuing.

The server listens on `127.0.0.1:8000`. Leave it running, then open another
terminal and check both probes:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/live
curl --fail-with-body http://127.0.0.1:8000/health/ready
```

Both commands should exit with status `0`. The liveness response reports an
alive worker and reconciler:

```json
{"status":"alive","worker":true,"reconciler":true}
```

The readiness probe also checks the database and required GitHub credentials. If
it fails, inspect the local log, but do not copy keys, secrets, or complete
database URLs into an issue.

## 6. Delegate one path

Use the [configuration guide](../how-to/configure.md) to enroll the App that
will submit approvals. That may be Stampbot or another development App; it is
not normally the Extra CODEOWNERS checker itself.

Start with one harmless file and one human owner group. Keep native code-owner
enforcement enabled while you test the policy. The repository-rules guide comes
later, after the negative cases pass.

Open a pull request that changes the delegated file. Add any required label and
have the enrolled App approve the current head. A working installation has all
of these signals:

- GitHub records a successful delivery to `/webhooks/github`.
- `/health/ready` continues to return HTTP 200.
- `Extra CODEOWNERS / approval` appears on the current pull-request head.
- The check succeeds only after the configured owner obligation is satisfied.

Now remove a required label or push another commit. The existing approval must
stop satisfying the check. Finish the remaining negative tests in the
[configuration guide](../how-to/configure.md#5-test-the-boundary).

## 7. Run the local quality gate

Stop the development server with `Ctrl-C`, then run:

```bash
mise run check
```

This task runs the pull-request test, lint, documentation, workflow, and Helm
checks available on the workstation. It does not enforce coverage and skips
PostgreSQL-only tests when `TEST_POSTGRES_URL` is absent.

To exercise the complete database suite, create a disposable PostgreSQL
database whose name ends in `_test`, then enter its URL at a hidden prompt:

```bash
read -rsp 'Disposable PostgreSQL test URL: ' TEST_POSTGRES_URL
printf '\n'
export TEST_POSTGRES_URL
mise run test:coverage
unset TEST_POSTGRES_URL
```

Use a URL such as:

```text
postgresql+psycopg://TEST_USER:TEST_PASSWORD@127.0.0.1:5432/extra_codeowners_test
```

Percent-encode reserved characters in the credentials. The test suite refuses
database names without the `_test` suffix, then drops and recreates Extra
CODEOWNERS tables. Never point it at a shared or production database.

## Clean up

You now have a local service that evaluated a real pull request. Remove the
temporary authority before moving on:

1. If you changed repository rules, restore GitHub's native code-owner rule and
   wait for it to apply. Only then remove the Extra CODEOWNERS required check.
2. Disable or remove the test repository policy.
3. Uninstall or suspend the development GitHub App, then delete its private key
   in GitHub.
4. Stop the HTTPS forwarding process.
5. Delete `.env` and `extra-codeowners.db` from the checkout.
