# Policy examples

These two files form one complete Extra CODEOWNERS policy:

- `organization.toml` enrolls an example App and adds an organization
  guardrail.
- `repository.toml` opts in one repository and delegates two path patterns.

The names and numeric IDs are deliberately fake. Replace the App slug, App ID,
bot user ID, owner, paths, and labels before using the files.

From the repository root, validate the pair with:

```bash
mise exec -- uv run python -m extra_codeowners validate-policy \
  --repository examples/policy/repository.toml \
  --organization examples/policy/organization.toml
```

Success prints:

```text
Policy files are valid.
```

The normal test suite also parses and compiles these exact files. That keeps
the published examples aligned with the policy models.
