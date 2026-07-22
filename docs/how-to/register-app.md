# Register a GitHub App with the setup URL

Use the optional App Manifest flow to create a private Extra CODEOWNERS GitHub
App. The manifest proposes the webhook URL, permissions, and event
subscriptions. GitHub creates the webhook secret and private key during the
conversion.

The callback displays credentials once. Run it from an operator-controlled
browser, store the values immediately, and disable setup when registration is
complete.

## Prerequisites

You need:

- permission to create a GitHub App for the intended user or organization
- a reviewed Extra CODEOWNERS checkout with dependencies installed
- a short-lived service process reachable at a public HTTPS origin
- control of access logging on every proxy in front of that origin
- a secret manager ready for the generated credentials
- a new high-entropy setup-state secret containing at least 32 bytes.

The setup-state secret must be separate from every GitHub credential. Don't
use a shared browser profile, share the screen, terminate TLS on an untrusted
proxy, or allow any proxy to record callback query strings.

## 1. Start an isolated setup process

Configure a short-lived development process:

```text
EXTRA_CODEOWNERS_ENVIRONMENT=development
EXTRA_CODEOWNERS_PUBLIC_URL=https://extra-codeowners-setup.example.com
EXTRA_CODEOWNERS_SETUP_ENABLED=true
EXTRA_CODEOWNERS_SETUP_STATE_SECRET=REPLACE_WITH_A_SETUP_ONLY_SECRET
```

Replace the example origin and inject the state secret through your deployment
secret manager. The public URL must be an HTTPS origin without credentials,
path, query, or fragment. Do not pass the secret on the command line or commit
it to a file.

Disable query-string logging before starting the process, especially for
`/setup/callback`.

From the reviewed checkout, migrate the setup database and start the service:

```bash
uv run python -m extra_codeowners database migrate
uv run python -m extra_codeowners serve
```

The first command must report the bundled migration head. The second keeps
running and serves the setup page.

This process does not need App credentials, so `/health/live` returns
HTTP 200 while `/health/ready` returns HTTP 503. Don't route ordinary
webhook traffic to it.

## 2. Open the registration page

For an organization-owned App, replace `ORGANIZATION` and open:

```text
https://extra-codeowners-setup.example.com/setup?organization=ORGANIZATION
```

For a user-owned App, omit the query string:

```text
https://extra-codeowners-setup.example.com/setup
```

Select **Continue to GitHub**. GitHub lets you edit the proposed registration,
so review it before creating the App.

### Verify the identity and URLs

- Give the App a unique name no longer than 34 characters. A short
  deployment-specific name such as `eco-ORG-dev` leaves room for the
  required uniqueness.
- Confirm that the App is private.
- Confirm that the webhook URL is the expected HTTPS origin followed by
  `/webhooks/github`.
- Confirm that the App does not request user authorization.

The final name identifies this checker deployment. It is not the name of an
application whose review may be delegated.

### Verify permissions

The manifest must request:

| Permission | Access |
| --- | --- |
| Checks | Read and write |
| Contents | Read-only |
| Members | Read-only |
| Metadata | Read-only |
| Pull requests | Read-only |
| Statuses | Read and write |

Statuses write is a registration permission needed before GitHub offers the
App as an expected source in organization rulesets. Extra CODEOWNERS
downscopes runtime installation tokens and omits Statuses, so the service
cannot write commit statuses. It publishes Check Runs.

### Verify event subscriptions

The explicit subscriptions must be:

- Check run
- Installation target
- Label
- Member
- Membership
- Organization
- Pull request
- Pull request review
- Push
- Repository
- Team
- Team add.

The manifest deliberately omits Installation and Installation repositories.
GitHub sends both events to every App by default, and Extra CODEOWNERS handles
them.

Stop if the owner, name, visibility, URL, permission, or event list differs
from this contract.

## 3. Store the one-time credentials

!!! warning
    Do not save the callback page, synchronize it through the browser, paste it
    into chat or a ticket, or put any value in shell history. If you cannot
    confirm secure storage, rotate the credentials before installing the App.

After creation, GitHub redirects to `/setup/callback`. Extra CODEOWNERS
validates the short-lived state token, exchanges GitHub's one-use code, and
shows the complete conversion response. The response uses no-store headers,
and Extra CODEOWNERS does not retain it.

Store these values directly in the secret manager:

- App ID
- PEM private key
- webhook secret
- App slug
- client secret, if GitHub returned one.

Verify each secret-manager entry, then close the page.

## 4. Disable setup

Stop the bootstrap process. Remove its setup-state secret and configure the
normal service:

```text
EXTRA_CODEOWNERS_SETUP_ENABLED=false
```

Add the new App ID, private key, webhook secret, and production database
configuration. Prefer the file-based secret settings in the
[GitHub configuration reference](../reference/configuration.md#github-settings).

GitHub keeps the webhook URL from the manifest. Once setup is disabled,
`EXTRA_CODEOWNERS_PUBLIC_URL` is optional because webhook processing does
not use it.

Start the normal service and confirm `/health/ready` returns HTTP 200.
Verify:

- `/setup` returns `404`
- `/setup/complete` returns `404`
- `/setup/callback?code=test&state=test` returns `404`.

The callback probe includes its required query parameters so FastAPI reaches
the disabled route instead of returning a parameter-validation error.

## 5. Install the App and test least privilege

Install the private App on:

- the organization-policy repository, `ORGANIZATION/.github` by default
- one disposable target repository.

GitHub may visit `/setup/complete` after installation. A `404` from
the now-disabled setup process does not undo the installation.

In the App settings, open **Advanced**, find the
`installation.created` delivery, and select **Redeliver**. Confirm that
GitHub receives HTTP `202` from `/webhooks/github` and the verified
webhook metric increases.

Check application, proxy, and load-balancer logs. None may contain a credential
or callback query string.

On the disposable repository's default branch, commit this disabled policy at
the effective policy path:

```toml
schema_version = 1
enabled = false
```

Open a pull request. Extra CODEOWNERS must publish a failing
`Extra CODEOWNERS / approval` check that says repository policy is
disabled. That result proves Contents read and Checks write access without
granting delegated authority or satisfying a required check.

Without repository policy, a repository with no previous managed check
receives no check. Organization policy alone never opts a repository in.

Continue with
[Configure organization and repository policy](configure.md).

## Recover an interrupted registration

If the callback fails or expires, don't reuse the conversion code. Return to
`/setup` for a new state token and create a new App Manifest conversion.

Before deleting an incomplete or duplicate App, confirm that it is not
installed and none of its keys are in use. If GitHub displayed credentials but
you cannot prove they were stored safely, delete the generated private key and
rotate the webhook secret before installing the App.
