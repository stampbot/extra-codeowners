# Support

Extra CODEOWNERS is in early development and does not yet have a supported production release or service-level commitment.

## Get help

Use [GitHub Discussions](https://github.com/stampbot/extra-codeowners/discussions) for usage questions, deployment design, and policy-model feedback. Search existing discussions before opening a new one.

Use [GitHub Issues](https://github.com/stampbot/extra-codeowners/issues) for reproducible defects and scoped feature requests. Include:

- the Extra CODEOWNERS version or commit;
- the deployment method;
- the GitHub event and redacted delivery identifier;
- the check summary and relevant logs; and
- a minimal, redacted `CODEOWNERS` and Extra CODEOWNERS policy example.

Do not include GitHub App private keys, webhook secrets, installation tokens, authorization headers, full webhook payloads from private repositories, or private repository contents.

## Security reports

Do not report a vulnerability in a public issue or discussion. Follow [SECURITY.md](SECURITY.md) for the private reporting channel and supported-version policy.

## Operational incidents

Self-hosted operators own availability and incident response for their deployment. If a required Extra CODEOWNERS check is stale or missing, fail safe: stop merges that depend on the check, inspect webhook delivery and worker health, and follow the [operations guide](docs/how-to/operate.md). Never weaken repository rules merely to clear a stuck check.
