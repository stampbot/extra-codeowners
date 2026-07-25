# Configure App delegation

Extra CODEOWNERS uses two policy files. Organization policy says which GitHub
Apps may be trusted at all. Repository policy opts one repository in and gives
an enrolled App a smaller, explicit scope.

This guide enrolls one App and delegates a few low-risk paths. Complete the
[first-check tutorial](../tutorials/development-installation.md)
first if you do not already have a test service.

## Before you begin

You need:

- administrator access to the organization's policy repository, `.github` by
  default
- permission to change policy in the target repository
- the approving App's numeric App ID, numeric bot user ID, and public slug
- a standard `CODEOWNERS` file with human users or teams.

Enroll the App that submits approving reviews, such as Stampbot. The Extra
CODEOWNERS checker belongs here only if it independently submits reviews too.

Keep App bot logins out of `CODEOWNERS`. GitHub documents that file for users
and teams with write access, not for GitHub App bot accounts. Extra CODEOWNERS
uses separate policy so its authority doesn't depend on undocumented native
behavior. The
[native CODEOWNERS comparison](../explanation/native-codeowners.md#keep-people-in-codeowners)
explains the distinction and shows how to check the standard file for errors.

The examples use the default policy location,
`.github/extra-codeowners.toml`. If the deployment changes
`EXTRA_CODEOWNERS_ORG_CONFIG_REPOSITORY` or
`EXTRA_CODEOWNERS_POLICY_PATH`, use the configured repository and path in both
scopes.

## 1. Record the App's immutable identity

Find the App ID in the App's GitHub settings. Obtain the bot account's numeric
user ID with an authenticated [GitHub CLI](https://cli.github.com/) session:

```bash
APP_SLUG=example-automation
gh api "users/${APP_SLUG}%5Bbot%5D" --jq .id
```

The response is a number such as:

```text
234567
```

Record the slug and both IDs directly from GitHub. A display name, review body,
or copied policy file is not identity evidence.

## 2. Enroll the App for the organization

Add `.github/extra-codeowners.toml` to the default branch of the organization's
policy repository:

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

Replace the example identity. Keep this change under native human CODEOWNERS
and normal repository rules.

A complete organization and repository pair lives in the repository's
[`examples/policy/`](https://github.com/stampbot/extra-codeowners/tree/main/examples/policy)
directory. CI compiles those files together.

Organization policy does not opt any member repository in. In schema version
1, the policy repository also cannot use this same file as its own repository
policy. Leave native code-owner enforcement enabled there, and do not require
the Extra CODEOWNERS check on it.

## 3. Delegate paths in one repository

Add `.github/extra-codeowners.toml` to the target repository:

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
forbidden_labels = ["needs-security-review"]
```

Each delegation is one complete alternative. It applies only when all of these
conditions hold:

- the review came from the enrolled App on the current pull-request head
- the changed path matches `paths`
- its effective CODEOWNERS set contains an entry in `for_owners`
- every required label is present and every forbidden label is absent.

Start with the smallest useful path list. `for_owners` is mandatory so a rule
cannot silently replace a different team. If broad owner coverage is truly
intended, spell it out with `for_owners = ["*"]`.

Labels gate whether a delegation is eligible. They never count as approval,
and Extra CODEOWNERS does not create or manage them.

Do not use labels to contain a compromised approving App. The pull-request
write permission needed to approve also authorizes GitHub's
[add-labels endpoint](https://docs.github.com/en/rest/issues/labels#add-labels-to-an-issue).
Use required and forbidden labels for operator intent or workflow routing; use
paths, owners, and non-delegable files for the security boundary.

Validate both files from a source checkout with development dependencies
installed:

```bash
mise exec -- uv run python -m extra_codeowners validate-policy \
  --repository ../target-repository/.github/extra-codeowners.toml \
  --organization ../organization-dot-github/.github/extra-codeowners.toml
```

The successful result is:

```text
Policy files are valid.
```

This command parses both files, validates field and path constraints, and
compiles repository policy against organization enrollment. Live evaluation
also checks App identity and repository access against GitHub, resolves
`CODEOWNERS`, and evaluates current pull-request evidence.

## 4. Protect the approval boundary

Do not enable `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES` to get through a test.
It removes the built-in guardrails for every installation served by that
process.

The built-in list prevents App substitution on:

- all standard `CODEOWNERS` locations
- the effective Extra CODEOWNERS repository policy
- Stampbot's root `/stampbot.toml`
- `.github/workflows/**`
- `.github/actions/**`.

These patterns prevent an App from standing in for a human. They do not assign
an owner, so your standard `CODEOWNERS` file must still cover them.

The service cannot discover every file that controls another App. Add
organization guardrails for each enrolled App's policy, configuration, rules,
prompts, generated inputs, and decision code. Cover transitive code too. If a
privileged workflow calls `scripts/publish/**`, protecting the workflow file
alone is not enough.

Apply the same reasoning to release settings, deployment policy, production
infrastructure, and other owned paths that can expand authority. An approving
App must not approve the change that broadens what it may approve next.

## 5. Test the boundary

Open a pull request that changes one delegated, low-risk file. Add the required
label and have the enrolled App approve the current head. In GitHub, confirm:

1. The repository's ordinary approval-count rule is still satisfied.
2. The expected Extra CODEOWNERS App publishes
   `Extra CODEOWNERS / approval`.
3. The check explains which delegation covered the path and owner set.
4. Removing the label or dismissing the App review makes the check
   non-successful.
5. Pushing another commit makes the approval stale until the App approves the
   new head.

Next, change a protected control file. For Stampbot, use `/stampbot.toml`; for
another App, use one of the control paths you added to organization
guardrails. Its approval must not satisfy that path. The appropriate human
CODEOWNER should still be required.

Test an undelegated path and a pull request that mixes delegated and
undelegated files as well. Every effective owner set must be covered.

If any negative case succeeds, stop the rollout. Restore GitHub's native
**Require review from Code Owners** rule, remove the Extra CODEOWNERS required
check, and diagnose the mismatch before continuing.
