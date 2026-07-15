# Configure organization and repository policy

Enroll a trusted GitHub App for the organization, then delegate a narrow set of repository paths to it. If you're working from source, complete the [development installation tutorial](../tutorials/development-installation.md) first.

## Prerequisites

You need:

- administrator access to the organization's `.github` repository
- permission to change policy in the target repository
- the trusted App's immutable App ID, bot user ID, and public slug
- an existing standard `CODEOWNERS` file containing human users or teams.

Enroll the automation that submits approving reviews, such as Stampbot. Don't enroll the Extra CODEOWNERS checker App that publishes the required check.

Don't add an App bot account to `CODEOWNERS`. GitHub skips lines with invalid syntax, and its errors endpoint reports mixed human and App-bot lines as `Invalid owner`. Treat the whole line as unusable; don't assume its human owners remain effective. After every ownership change, use GitHub's CODEOWNERS error view or the [API check](../explanation/native-codeowners.md#the-gap).

The examples use the `.github` organization-policy repository and `.github/extra-codeowners.toml` policy path. If the operator changed `EXTRA_CODEOWNERS_ORG_CONFIG_REPOSITORY` or `EXTRA_CODEOWNERS_POLICY_PATH`, substitute those deployment-wide values in both scopes.

## 1. Record the application identity

Find the numeric App ID in the App's GitHub settings. Then obtain the bot account ID from GitHub's API. From any directory in a POSIX-compatible shell, run [GitHub CLI](https://cli.github.com/) authenticated for public metadata:

```bash
APP_SLUG=example-automation
gh api "users/${APP_SLUG}%5Bbot%5D" --jq .id
```

The output is a numeric user ID:

```text
234567
```

Record both IDs from GitHub. Don't infer an identity from a display name, review text, or copied configuration.

## 2. Enroll the application at organization scope

In the organization's `.github` repository, add `.github/extra-codeowners.toml` on a human-reviewed branch:

```toml
schema_version = 1

[apps.example-automation]
slug = "example-automation"
app_id = 123456
bot_user_id = 234567

[guardrails]
non_delegable_paths = [
  "infrastructure/production/**",
]
```

Replace the example slug and IDs with the values from the previous step.

Keep this organization policy under native human CODEOWNERS and repository rules. The initial single-path schema doesn't let the `.github` repository use this file as its own Extra CODEOWNERS repository policy. Leave GitHub's native code-owner rule enabled there, and don't require the Extra CODEOWNERS check.

## 3. Delegate repository paths

In the target repository, add `.github/extra-codeowners.toml`:

```toml
schema_version = 1
enabled = true

[[delegations]]
app = "example-automation"
paths = [
  "docs/**",
  "**/*.lock",
]
for_owners = ["@example-org/platform"]
required_labels = ["automation-approved"]
```

Start with the smallest path set that covers the automation. Set `for_owners` to the owner group the App may replace; the field is mandatory so a delegation can't silently apply to another group. If the App should replace any owner, make that broad choice explicit with `for_owners = ["*"]`.

Treat labels only as restrictions. The configured App must still submit an approving review for the current pull-request head. If a label such as `needs-security-review` must disable the delegation, add it to `forbidden_labels`. Required and forbidden label matching is case-insensitive.

Extra CODEOWNERS reads labels but doesn't create, remove, or rename them. Define their lifecycle and permissions separately.

From an Extra CODEOWNERS source checkout with the development dependencies and CLI installed, validate both files. Pass paths to local checkouts of the target repository and the organization's `.github` repository:

```bash
uv run python -m extra_codeowners validate-policy \
  --repository ../target-repository/.github/extra-codeowners.toml \
  --organization ../organization-dot-github/.github/extra-codeowners.toml
```

Expect:

```text
Policy files are valid.
```

This command checks TOML structure and field constraints. The live check also verifies cross-file application aliases, GitHub identities, CODEOWNERS, repository access, and current pull-request evidence.

## 4. Protect the policy boundary

Don't set `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES` to make a test pull request pass. It weakens every installation served by the process.

Verify that the standard `CODEOWNERS` file assigns the following built-in non-delegable paths to appropriate humans or teams:

- every standard CODEOWNERS location
- the Extra CODEOWNERS repository policy
- Stampbot's root `/stampbot.toml`
- `.github/workflows/**`
- repository-local actions under `.github/actions/**`.

Non-delegable patterns prevent an App from replacing a human; they don't create ownership.

For every enrolled App other than Stampbot, add organization guardrails for its repository policy or configuration and for any code that controls what it may approve. An App must not replace a human on a change that expands its own future authority. Include its configuration, rules, prompts, scripts, and generated-policy inputs.

Protect every other owned sensitive surface, including release configuration, deployment policy, production infrastructure, and repository scripts invoked by privileged workflows. Extra CODEOWNERS can't infer transitive execution paths. For example, if a release workflow runs `scripts/publish/**`, make that path non-delegable.

## 5. Verify with a test pull request

Open a pull request that changes one delegated, low-risk file. Apply any required label, then have the configured App approve the current head commit.

Verify all of these results in GitHub:

1. The repository's ordinary required review count is satisfied.
2. The expected Extra CODEOWNERS App installation reports `Extra CODEOWNERS / approval`.
3. The check summary names the delegation that satisfied the owned path.
4. Removing the label or dismissing the App review triggers reevaluation and a non-successful check.
5. Pushing a commit makes the old approval stop counting until the App approves the new head.

Next, open a second pull request that changes a non-delegable path. When testing Stampbot, change its root `/stampbot.toml`. For another App, change one of its organization-guardrail control paths. Confirm that the App review doesn't satisfy the path and that an appropriate human CODEOWNER must approve it.

If a negative test passes when it shouldn't, stop. Remove the Extra CODEOWNERS required check, restore GitHub's native **Require review from Code Owners** rule, and find the cause before trying again.
