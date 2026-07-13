# Configure organization and repository policy

Use this guide to enroll a trusted GitHub App at organization scope and delegate a narrow set of repository paths. Complete the [development installation tutorial](../tutorials/development-installation.md) first when working from source.

## Prerequisites

You need:

- administrator access to the organization's `.github` repository;
- permission to change policy in the target repository;
- the trusted App's immutable App ID, bot user ID, and public slug; and
- an existing standard `CODEOWNERS` file containing human users or teams.

The application enrolled in this guide is the automation that submits approving reviews, such as Stampbot. It is not the Extra CODEOWNERS checker App that publishes the required check.

Do not add an App bot account to `CODEOWNERS`. GitHub documents that invalid-syntax lines are skipped, and its errors endpoint reports mixed human/App-bot lines as `Invalid owner`; treat the whole line as unusable rather than assuming the human owners remain effective. Use GitHub's CODEOWNERS error view or the [API check](../explanation/native-codeowners.md#the-gap) after every ownership change.

The examples below use the default organization-policy repository `.github` and policy path `.github/extra-codeowners.toml`. If the operator changed `EXTRA_CODEOWNERS_ORG_CONFIG_REPOSITORY` or `EXTRA_CODEOWNERS_POLICY_PATH`, substitute those deployment-wide values consistently in both scopes.

## 1. Record the application identity

Find the numeric App ID in the App's GitHub settings. Obtain the bot account ID from GitHub's API. With [GitHub CLI](https://cli.github.com/) authenticated for public metadata, run this command from any directory in a POSIX-compatible shell:

```bash
APP_SLUG=example-automation
gh api "users/${APP_SLUG}%5Bbot%5D" --jq .id
```

Sample output:

```text
234567
```

Record the IDs from GitHub. Do not infer them from display names, review text, or a copied configuration.

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

Replace the example slug and IDs with the values recorded in the previous step. Keep the organization policy itself protected by native human CODEOWNERS and repository rules. The initial single-path schema does not let the `.github` repository use this organization-policy file as its own Extra CODEOWNERS repository policy, so do not disable GitHub's native code-owner rule or require the Extra CODEOWNERS check there.

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

Start with the smallest path set that covers the intended automation. `for_owners` is mandatory so a path delegation cannot silently apply to an unrelated owner group. If broad owner substitution is intentional, write `for_owners = ["*"]` and make that choice visible in review.

The label is a restriction, not evidence of approval. The configured application must still submit an approving review for the current pull-request head. Use `forbidden_labels` when a delegation must stop applying under a condition such as `needs-security-review`; required and forbidden label matching is case-insensitive. Extra CODEOWNERS reads labels but does not create, remove, or rename them, so define label lifecycle and permissions separately.

Validate both files from the Extra CODEOWNERS source checkout, where the development dependencies and CLI are installed. Pass paths to local checkouts of the target repository and the organization's `.github` repository:

```bash
uv run python -m extra_codeowners validate-policy \
  --repository ../target-repository/.github/extra-codeowners.toml \
  --organization ../organization-dot-github/.github/extra-codeowners.toml
```

Expected output:

```text
Policy files are valid.
```

This command validates TOML structure and field constraints. The live check also verifies cross-file application aliases, GitHub identities, CODEOWNERS, repository access, and current pull-request evidence.

## 4. Protect the policy boundary

The built-in non-delegable paths already prevent application substitution for the standard CODEOWNERS locations, the Extra CODEOWNERS repository policy, Stampbot's root `/stampbot.toml`, `.github/workflows/**`, and repository-local actions under `.github/actions/**`. Verify that the standard CODEOWNERS file assigns those paths to appropriate humans or teams; non-delegable patterns do not create ownership.

For every enrolled application other than Stampbot, add organization guardrails for its repository-local policy or configuration and any code that controls what it may approve. An application must not substitute for a human on a change that expands its own future approval authority. Inventory each App's configuration, rules, prompts, scripts, and generated-policy inputs.

Also protect other owned sensitive surfaces such as release configuration, deployment policy, production infrastructure, and repository-specific scripts invoked by privileged workflows. The service cannot infer those transitive execution paths. For example, if a release workflow executes `scripts/publish/**`, make that path non-delegable as well.

Do not enable `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES` merely to get a test pull request passing. That setting affects every installation served by the process.

## 5. Verify with a test pull request

Open a pull request that changes only one delegated, low-risk file. Apply any required label and have the configured application approve the current head commit.

Verify all of the following in GitHub:

1. The ordinary required review count is satisfied according to your repository rules.
2. `Extra CODEOWNERS / approval` is reported by the expected Extra CODEOWNERS App installation.
3. The check summary identifies the delegation that satisfied the owned path.
4. Removing the label or dismissing the application review causes reevaluation and a non-successful check.
5. Pushing a new commit causes the old approval to stop counting until the application approves the new head.

Then open a second pull request that changes a non-delegable path. When testing Stampbot, include its root `/stampbot.toml`; for another App, include one of its organization-guardrail control paths. Confirm that the application review does not satisfy the path and an appropriate human CODEOWNER must approve it.

If any negative test passes unexpectedly, remove the Extra CODEOWNERS required check and restore GitHub's native **Require review from Code Owners** rule until the configuration is understood.
