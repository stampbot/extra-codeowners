# Run your first check

In this tutorial, we will run Extra CODEOWNERS locally and watch it evaluate a
real pull request. A human CODEOWNER will approve the change. We won't delegate
anything to an App yet.

The result is for learning, not production. Extra CODEOWNERS still has a
[commit-scoped check limitation](../reference/project-status.md#production-enforcement-blocker).

## What you need

Use a POSIX-compatible shell and a disposable GitHub organization. You also
need:

- Git with an author name and email, `curl`, and
  [mise](https://mise.jdx.dev/) 2026.7.12 or newer
- GitHub CLI authenticated as an organization administrator
- permission to create and install a private GitHub App
- two human GitHub accounts: one pull-request author and one CODEOWNER
- write access for the CODEOWNER on the test repository
- an operator-controlled browser and terminal.

This tutorial uses a
[Cloudflare Quick Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)
to send webhooks to your local service. Cloudflare is a third party and can see
the proxied payload. Use public, disposable repositories with no private code
or real secrets. Don't reuse the App, webhook secret, or tunnel after the
tutorial. Quick Tunnels are a development service with no availability
guarantee.

## 1. Prepare a clean checkout

Clone the repository. Before trusting the checkout, review the revision you
received and read `mise.toml` and `mise.tutorial.toml`. `mise trust` permits
repository configuration and tasks to execute on your workstation.

```bash
git clone https://github.com/stampbot/extra-codeowners.git
cd extra-codeowners
git status --short
git log -1 --oneline --show-signature
less mise.toml mise.tutorial.toml
```

When the checkout and tool configuration match the revision you intended to
run, install the pinned toolchain:

```bash
export EXTRA_CODEOWNERS_ROOT="$PWD"
mise trust mise.toml
mise trust mise.tutorial.toml
mise install
mise run bootstrap
```

`mise run bootstrap` should exit with status `0` and create `.venv/` without
changing `uv.lock`.

## 2. Create the disposable repositories

Set your organization name, then create its policy repository and one target
repository:

```bash
export TUTORIAL_ORG='REPLACE_WITH_DISPOSABLE_ORGANIZATION'
export CODEOWNER_LOGIN='REPLACE_WITH_SECOND_HUMAN_LOGIN'
gh repo create "${TUTORIAL_ORG}/.github" --public --add-readme
gh repo create "${TUTORIAL_ORG}/extra-codeowners-tutorial" --public --add-readme
```

Replace both placeholders before running the commands. Set
`CODEOWNER_LOGIN` to a login without the leading `@`. Give that person write
access to the target repository:

```bash
gh api --method PUT \
  "repos/${TUTORIAL_ORG}/extra-codeowners-tutorial/collaborators/${CODEOWNER_LOGIN}" \
  -f permission=push
```

If GitHub creates an invitation, ask that person to accept it now.

Clone both repositories into a temporary directory:

```bash
export TUTORIAL_ROOT
TUTORIAL_ROOT="$(mktemp -d)"
: >"${TUTORIAL_ROOT}/.extra-codeowners-tutorial"
gh repo clone "${TUTORIAL_ORG}/.github" \
  "${TUTORIAL_ROOT}/organization-policy"
gh repo clone "${TUTORIAL_ORG}/extra-codeowners-tutorial" \
  "${TUTORIAL_ROOT}/target"
```

Create organization policy:

```bash
install -d "${TUTORIAL_ROOT}/organization-policy/.github"
cat >"${TUTORIAL_ROOT}/organization-policy/.github/extra-codeowners.toml" <<'EOF'
schema_version = 1
EOF
git -C "${TUTORIAL_ROOT}/organization-policy" add \
  .github/extra-codeowners.toml
git -C "${TUTORIAL_ROOT}/organization-policy" commit --signoff \
  -m 'Add tutorial organization policy'
git -C "${TUTORIAL_ROOT}/organization-policy" push
```

Create repository policy and the human ownership rule:

```bash
install -d "${TUTORIAL_ROOT}/target/.github"
cat >"${TUTORIAL_ROOT}/target/.github/extra-codeowners.toml" <<'EOF'
schema_version = 1
enabled = true
EOF
printf '/docs/tutorial-check.txt @%s\n' "$CODEOWNER_LOGIN" \
  >"${TUTORIAL_ROOT}/target/.github/CODEOWNERS"
git -C "${TUTORIAL_ROOT}/target" add .github
git -C "${TUTORIAL_ROOT}/target" commit --signoff \
  -m 'Add tutorial approval policy'
git -C "${TUTORIAL_ROOT}/target" push
```

The repository policy opts in but delegates no ownership to an App.

Check the file before you continue:

```bash
gh api \
  "repos/${TUTORIAL_ORG}/extra-codeowners-tutorial/codeowners/errors" \
  --jq '.errors'
```

The command should print `[]`.

## 3. Start the HTTPS tunnel

Keep the first terminal for the remaining commands. In a second terminal,
change to the same Extra CODEOWNERS checkout and start a temporary tunnel with
the checksum-pinned `cloudflared` release:

```bash
cd /absolute/path/to/extra-codeowners
install -d -m 700 "$HOME/.config/extra-codeowners"
printf '{}\n' \
  >"$HOME/.config/extra-codeowners/tutorial-cloudflared.yml"
mise exec -E tutorial -- \
  cloudflared tunnel \
  --config "$HOME/.config/extra-codeowners/tutorial-cloudflared.yml" \
  --no-autoupdate \
  --url http://127.0.0.1:8000
```

The isolated empty config prevents an existing `cloudflared` configuration
from changing Quick Tunnel behavior.

`mise.tutorial.toml` pins release `2026.7.2` and the exact asset digest for
x86-64 and arm64 Linux and macOS. The
[relay update procedure](../maintainers/update-tutorial-relay.md) keeps the
version, four checksums, and signed-delivery evidence together.

The command prints a random HTTPS URL ending in `trycloudflare.com`. Leave that
terminal running. Back in the first terminal, record the URL as `TUNNEL_URL`
and treat it as temporary sensitive data:

```bash
export TUNNEL_URL='REPLACE_WITH_PRINTED_TRYCLOUDFLARE_URL'
```

Leave the tunnel running. Requests will fail until the service starts. That is
expected. A restarted Quick Tunnel gets a new URL; update the App's webhook URL
before redelivering an event.

Extra CODEOWNERS verifies GitHub's signature over the exact request bytes, as
required by
[GitHub's signature-validation contract](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).
Do not substitute a webhook relay that parses and reserializes JSON.
The pin covers the open-source local client, not Cloudflare's proprietary edge.
If signature verification changes, stop the tutorial instead of weakening the
webhook check.

## 4. Register the checker App

First, create a random webhook secret of at least 32 bytes in a file outside
the checkout:

```bash
install -d -m 700 "$HOME/.config/extra-codeowners"
(
  umask 077
  mise exec -- python -c \
    'import secrets; print(secrets.token_urlsafe(32))' \
    >"$HOME/.config/extra-codeowners/tutorial-webhook-secret"
)
```

In the disposable organization's GitHub settings, open **Developer settings**,
then **GitHub Apps**, then **New GitHub App**. Complete the form in this order:

1. Enter a globally unique **GitHub App name** no longer than 34 characters.
   A name such as `eco-tutorial-UNIQUE_SUFFIX` makes its purpose clear.
2. Set **Homepage URL** to
   `https://github.com/stampbot/extra-codeowners`.
3. Leave **Callback URL** and **Setup URL** empty. Do not request user
   authorization during installation.
4. Enable **Active** under **Webhook**.
5. Set **Webhook URL** to the exact `TUNNEL_URL` followed by
   `/webhooks/github`.
6. Paste the single line from
   `~/.config/extra-codeowners/tutorial-webhook-secret` into **Webhook
   secret**.
7. Set repository permissions to Checks read and write; Contents read; Pull
   requests read; and Commit statuses read and write.
8. Set the Members organization permission to read. Leave every other
   repository, organization, and account permission at **No access**.
9. Subscribe to Check run, Installation target, Label, Member, Membership,
   Organization, Pull request, Pull request review, Push, Repository, Team, and
   Team add.
10. Under **Where can this GitHub App be installed?**, select **Only on this
    account**.
11. Review the form, then select **Create GitHub App**.

GitHub supplies Metadata read automatically. It also sends Installation and
Installation repositories events to every App, so they do not appear in the
event picker.

Do not grant Actions, Administration, Issues, Workflows, or Pull requests write.
Extra CODEOWNERS reads reviews; it never submits one. Commit statuses
(`statuses`) write is a registration permission for organization ruleset
source selection. Runtime tokens omit it, and the service publishes Check Runs
instead.

On the new App's settings page, record the numeric App ID. Select **Generate a
private key**, then move the downloaded PEM and restrict its permissions:

```bash
mv /absolute/path/to/downloaded-private-key.pem \
  "$HOME/.config/extra-codeowners/tutorial-app.private-key.pem"
chmod 0600 \
  "$HOME/.config/extra-codeowners/tutorial-app.private-key.pem"
```

Replace the source path before running the command.

The [App setup guide](../how-to/register-app.md) describes the automatic
manifest flow. It is a separate bootstrap path because its callback routes must
already be reachable over HTTPS.

## 5. Configure and start Extra CODEOWNERS

Return to the Extra CODEOWNERS checkout. Copy the local defaults:

```bash
cd "$EXTRA_CODEOWNERS_ROOT"
cp .env.example .env
```

Edit `.env` and uncomment these settings:

```dotenv
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/absolute/path/to/tutorial-app.private-key.pem
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/absolute/path/to/tutorial-webhook-secret
```

Replace the App ID and both absolute paths. Keep the SQLite development
database and leave `EXTRA_CODEOWNERS_SETUP_ENABLED=false`.

Migrate the database, then start the service in the background. Its process ID
stays in the first terminal for cleanup:

```bash
mise exec -- uv run python -m extra_codeowners database migrate
mise exec -- uv run python -m extra_codeowners serve \
  >"${TUTORIAL_ROOT}/service.log" 2>&1 &
export SERVICE_PID=$!
```

Check both probes from the same terminal:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/live
curl --fail-with-body http://127.0.0.1:8000/health/ready
```

Both commands should exit with status `0`. The liveness response looks like:

```json
{"status":"alive","worker":true,"reconciler":true}
```

If either probe fails, read `"${TUTORIAL_ROOT}/service.log"` before continuing.

## 6. Install the App

From the App's settings page:

1. Select **Install App**.
2. Select **Install** beside the disposable organization.
3. Choose **Only select repositories**.
4. Select `.github` and `extra-codeowners-tutorial`.
5. Review the requested access, then select **Install**.

Return to the App's **Advanced** settings and open **Recent deliveries**. Find
the `installation.created` delivery. GitHub should report HTTP `202`. If the
service was not ready when GitHub sent it, select **Redeliver** and check again.

## 7. Open and approve the pull request

Continue with the GitHub CLI account that created the repositories. It must not
be `CODEOWNER_LOGIN`. Create the owned file and open a pull request:

```bash
cd "${TUTORIAL_ROOT}/target"
git switch -c tutorial-human-approval
install -d docs
printf 'first revision\n' >docs/tutorial-check.txt
git add docs/tutorial-check.txt
git commit --signoff -m 'Add the tutorial check file'
git push --set-upstream origin HEAD
gh pr create \
  --title 'Exercise human CODEOWNER approval' \
  --body 'Disposable Extra CODEOWNERS tutorial.'
```

The `Extra CODEOWNERS / approval` check should appear and fail because the
owned path has no approval. Open its details and confirm that it names
`docs/tutorial-check.txt` and the configured owner without exposing a secret.

Now sign in as the CODEOWNER and approve the current pull-request head. The
same check should run again and finish successfully.

Push one more commit as the author:

```bash
printf 'second revision\n' >>docs/tutorial-check.txt
git add docs/tutorial-check.txt
git commit --signoff -m 'Update the tutorial check file'
git push
```

The earlier approval must stop satisfying the check because it belongs to the
old head. After the CODEOWNER approves the new head, the check should return
to success.

You now have a checker App that evaluated `CODEOWNERS` and a current human
review. App delegation is the next layer, not a prerequisite for proving that
the checker works.

## Clean up

Stop the tunnel with `Ctrl-C` in the second terminal. Stop the service and
remove the temporary local files from the first terminal:

```bash
if test -n "${SERVICE_PID:-}" && kill -0 "$SERVICE_PID" 2>/dev/null; then
  kill "$SERVICE_PID"
  wait "$SERVICE_PID" || true
fi
rm -f "$EXTRA_CODEOWNERS_ROOT/.env"
rm -f "$EXTRA_CODEOWNERS_ROOT/extra-codeowners.db"
rm -f "$HOME/.config/extra-codeowners/tutorial-cloudflared.yml"
rm -f "$HOME/.config/extra-codeowners/tutorial-app.private-key.pem"
rm -f "$HOME/.config/extra-codeowners/tutorial-webhook-secret"
test -n "${TUTORIAL_ROOT:-}" &&
  test -f "${TUTORIAL_ROOT}/.extra-codeowners-tutorial" &&
  rm -rf -- "$TUTORIAL_ROOT"
unset CODEOWNER_LOGIN EXTRA_CODEOWNERS_ROOT SERVICE_PID TUNNEL_URL TUTORIAL_ORG
unset TUTORIAL_ROOT
```

Uninstall and delete the disposable GitHub App. Delete the tutorial
repositories and organization when nothing else uses them. The Quick Tunnel
stops accepting requests when `cloudflared` exits.
