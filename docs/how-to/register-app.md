# Register a GitHub App with the setup URL

Use the optional App Manifest flow to create a private Extra CODEOWNERS GitHub App with the required permissions, webhook URL, secret, and event subscriptions. The flow displays sensitive credentials once. Run it from an operator-controlled browser and disable setup immediately afterward.

## Prerequisites

You need:

- permission to create a GitHub App for the intended user or organization;
- an Extra CODEOWNERS process reachable at a public HTTPS origin;
- control of reverse-proxy access logging for that origin;
- a secret manager ready to receive the generated credentials; and
- a new high-entropy setup-state secret of at least 32 bytes, distinct from every GitHub credential.

Do not perform setup over plain HTTP, from a shared browser profile, while screen sharing, or through a proxy that records query strings.

## 1. Start a bootstrap process

Configure a short-lived development-mode process with:

```text
EXTRA_CODEOWNERS_ENVIRONMENT=development
EXTRA_CODEOWNERS_PUBLIC_URL=https://extra-codeowners-setup.example.com
EXTRA_CODEOWNERS_SETUP_ENABLED=true
EXTRA_CODEOWNERS_SETUP_STATE_SECRET=replace-with-a-high-entropy-setup-only-secret
```

Replace the public origin and secret. The origin must use HTTPS, and the state secret must contain at least 32 UTF-8 bytes. Supply the state secret through the deployment's secret manager, not a command-line argument or committed file. Configure the proxy to omit query strings from access logs, especially for `/setup/callback`.

Start the service:

```bash
uv run python -m extra_codeowners serve
```

The bootstrap process can serve setup without existing GitHub App credentials. Its readiness endpoint remains non-successful until those credentials are configured, so do not route normal webhook traffic to it.

## 2. Open the setup URL

For an organization-owned App, open this URL in the operator-controlled browser, replacing `ORGANIZATION` and the example origin:

```text
https://extra-codeowners-setup.example.com/setup?organization=ORGANIZATION
```

For a user-owned App, omit the query string:

```text
https://extra-codeowners-setup.example.com/setup
```

Select **Continue to GitHub**. GitHub displays the App Manifest before creation. Verify:

- the App name is unique across GitHub and no longer than 34 characters; edit the proposed name to a short deployment-specific value such as `eco-ORG-dev` when needed;
- the App is private;
- the webhook URL is the expected HTTPS origin plus `/webhooks/github`;
- Checks and Statuses are read and write;
- Contents, Metadata, Members, and Pull requests are read-only;
- the explicit subscriptions are Check run, Installation target, Label, Member, Membership, Organization, Pull request, Pull request review, Push, Repository, Team, and Team add;
- GitHub automatically delivers Installation and Installation repositories events to every App, so the manifest does not list them as manual subscriptions even though Extra CODEOWNERS handles them; and
- user authorization is not requested.

Stop if the owner, URL, permission, or event list differs.

GitHub documents that the manifest registration page lets the operator edit the proposed name, and [GitHub App names must be unique](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app#registering-a-github-app). The final name identifies this checker deployment; it is not the application enrolled to submit delegated reviews.

Statuses write is present only because GitHub requires it to offer an App as the expected source in organization-level rulesets. Extra CODEOWNERS requests downscoped runtime tokens without Statuses, so the running service cannot write commit statuses.

## 3. Store the one-time credentials

After App creation, GitHub redirects to `/setup/callback`. Extra CODEOWNERS validates the short-lived state, exchanges GitHub's one-use code, and displays the complete conversion response once.

Store the App ID, PEM private key, webhook secret, slug, and any client secret GitHub returned directly in the secret manager. Do not save the page, use browser synchronization, copy it into a ticket or chat, or include it in shell history.

Close the page after verifying the secret-manager entries. The service does not retain the conversion response.

## 4. Disable setup and configure the service

Stop the bootstrap process. Remove the setup-state secret from its runtime and set:

```text
EXTRA_CODEOWNERS_SETUP_ENABLED=false
```

Configure the normal service with the new App ID, private key, and webhook secret. GitHub retains the webhook URL registered by the manifest, so `EXTRA_CODEOWNERS_PUBLIC_URL` may be unset after setup is disabled; webhook processing does not use it. Prefer the file-based private-key and webhook-secret settings described in the [configuration reference](../reference/configuration.md#github-settings).

Start the normal service and confirm `/health/ready` succeeds. Verify `/setup`, `/setup/callback`, and `/setup/complete` return `404` while setup is disabled.

## 5. Install and verify the App

Install the private App on the configured organization-policy repository (by default, the organization's `.github` repository) and one disposable target repository. GitHub may visit `/setup/complete` after installation; if setup is already disabled, a `404` is expected and does not undo the installation.

Send a test webhook from the App's GitHub settings. Confirm:

1. GitHub receives `202` from `/webhooks/github`.
2. The webhook delivery metric increments.
3. No credential or callback query string appears in application, proxy, or load-balancer logs.
4. On the disposable repository's default branch, commit a minimal disabled policy at the effective policy path (by default `.github/extra-codeowners.toml`) containing `schema_version = 1` and `enabled = false`.
5. Opening a pull request in that repository produces a failing `Extra CODEOWNERS / approval` check stating that repository policy is disabled. This confirms read and Checks access without authorizing delegation or accidentally satisfying a required check.

Without any repository policy, the App intentionally publishes no check; organization policy alone does not opt the repository in.

Continue with [Configure organization and repository policy](configure.md).

## Recover from an interrupted setup

If the callback fails or expires, do not reuse a conversion code. Return to `/setup` to issue new state and create a new App Manifest conversion. Delete any incomplete or duplicate App in GitHub after confirming it is not installed and none of its keys are in use.

If credentials were displayed but their storage is uncertain, delete the generated private key and rotate the webhook secret before installing the App.
