# Register a GitHub App with the setup URL

Use the optional App Manifest flow to create a private Extra CODEOWNERS GitHub App. The manifest supplies the required permissions, webhook URL, secret, and event subscriptions.

The flow displays sensitive credentials once. Use an operator-controlled browser, then disable setup as soon as you've stored them.

## Prerequisites

You need:

- permission to create a GitHub App for the intended user or organization
- an Extra CODEOWNERS process reachable at a public HTTPS origin
- control of reverse-proxy access logging for that origin
- a secret manager ready to receive the generated credentials
- a new high-entropy setup-state secret of at least 32 bytes, distinct from every GitHub credential.

Don't run setup over plain HTTP, from a shared browser profile, while sharing your screen, or through a proxy that records query strings.

## 1. Start a bootstrap process

Configure a short-lived process in development mode:

```text
EXTRA_CODEOWNERS_ENVIRONMENT=development
EXTRA_CODEOWNERS_PUBLIC_URL=https://extra-codeowners-setup.example.com
EXTRA_CODEOWNERS_SETUP_ENABLED=true
EXTRA_CODEOWNERS_SETUP_STATE_SECRET=replace-with-a-high-entropy-setup-only-secret
```

Replace the public origin and secret. Use HTTPS for the origin and at least 32 UTF-8 bytes for the state secret. Supply that secret through the deployment's secret manager, never through a command-line argument or committed file. Configure the proxy to omit query strings from access logs, especially for `/setup/callback`.

Migrate the setup database explicitly, then start the service:

```bash
uv run python -m extra_codeowners database migrate
uv run python -m extra_codeowners serve
```

The bootstrap process can serve setup without GitHub App credentials. Its readiness endpoint stays non-successful until those credentials are configured. Don't route normal webhook traffic to it.

## 2. Open the setup URL

If an organization will own the App, open this URL in the operator-controlled browser. Replace `ORGANIZATION` and the example origin:

```text
https://extra-codeowners-setup.example.com/setup?organization=ORGANIZATION
```

If a user will own the App, omit the query string:

```text
https://extra-codeowners-setup.example.com/setup
```

Select **Continue to GitHub**. Before creating the App, verify the manifest GitHub displays:

- Give the App a unique name no longer than 34 characters. If needed, edit the proposal to a short deployment-specific name such as `eco-ORG-dev`.
- Confirm that the App is private.
- Confirm that the webhook URL is the expected HTTPS origin plus `/webhooks/github`.
- Confirm that Checks and Statuses are read and write.
- Confirm that Contents, Metadata, Members, and Pull requests are read-only.
- Confirm the explicit subscriptions: Check run, Installation target, Label, Member, Membership, Organization, Pull request, Pull request review, Push, Repository, Team, and Team add.
- Confirm that the manifest omits Installation and Installation repositories. GitHub delivers them automatically to every App, and Extra CODEOWNERS handles them.
- Confirm that user authorization isn't requested.

Stop if the owner, URL, permission, or event list differs.

GitHub lets the operator edit the proposed manifest name, and [GitHub App names must be unique](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app#registering-a-github-app). The final name identifies this checker deployment, not the application that submits delegated reviews.

GitHub requires Statuses write before it offers the App as an expected source in organization-level rulesets. Extra CODEOWNERS requests runtime tokens without Statuses, so the running service can't write commit statuses.

## 3. Store the one-time credentials

!!! warning
    Don't save the callback page, synchronize it through the browser, copy it into a ticket or chat, or put any value in shell history. If you can't confirm secure storage, rotate the credentials before installing the App.

After App creation, GitHub redirects to `/setup/callback`. Extra CODEOWNERS validates the short-lived state, exchanges GitHub's one-use code, and displays the complete conversion response once.

Store the App ID, PEM private key, webhook secret, slug, and any client secret GitHub returned directly in the secret manager. Verify the entries, then close the page. Extra CODEOWNERS doesn't retain the conversion response.

## 4. Disable setup and configure the service

Stop the bootstrap process. Remove the setup-state secret from its runtime and set:

```text
EXTRA_CODEOWNERS_SETUP_ENABLED=false
```

Configure the normal service with the new App ID, private key, and webhook secret. GitHub retains the webhook URL from the manifest, so you may leave `EXTRA_CODEOWNERS_PUBLIC_URL` unset after disabling setup; webhook processing doesn't use it. Prefer the file-based private-key and webhook-secret settings in the [configuration reference](../reference/configuration.md#github-settings).

Start the normal service and confirm `/health/ready` succeeds. Verify that `/setup`, `/setup/callback`, and `/setup/complete` each return `404` while setup is disabled.

## 5. Install and verify the App

Install the private App on the configured organization-policy repository, which defaults to the organization's `.github` repository, and on one disposable target repository. GitHub may visit `/setup/complete` after installation. If setup is already disabled, the expected `404` doesn't undo the installation.

In the App's GitHub settings, open **Advanced**, then **Recent deliveries**. Select the `installation` delivery created when you installed the App and choose **Redeliver**. Confirm each result:

1. GitHub receives `202` from `/webhooks/github`.
2. The webhook delivery metric increments.
3. No application, proxy, or load-balancer log contains a credential or callback query string.
4. On the disposable repository's default branch, commit a minimal disabled policy at the effective policy path, `.github/extra-codeowners.toml` by default. Set `schema_version = 1` and `enabled = false`.
5. Open a pull request and confirm that Extra CODEOWNERS publishes a failing `Extra CODEOWNERS / approval` check stating that repository policy is disabled. This proves read and Checks access without authorizing delegation or accidentally satisfying a required check.

Without repository policy, the App intentionally publishes no check. Organization policy alone doesn't opt a repository in.

Continue with [Configure organization and repository policy](configure.md).

## Recover from an interrupted setup

If the callback fails or expires, don't reuse its conversion code. Return to `/setup` to issue new state and create another App Manifest conversion. After confirming that an incomplete or duplicate App isn't installed and none of its keys are in use, delete it from GitHub.

If GitHub displayed the credentials but you can't confirm their storage, delete the generated private key and rotate the webhook secret before installing the App.
