# Support

Extra CODEOWNERS has no tagged release or hosted service. Maintainer support is best-effort, with no response-time commitment.

## Get help

Use [GitHub Discussions](https://github.com/stampbot/extra-codeowners/discussions) for usage questions, deployment design, and policy feedback. Search before you start a new discussion.

Use [GitHub Issues](https://github.com/stampbot/extra-codeowners/issues) for reproducible defects and scoped feature requests. Include:

- the Extra CODEOWNERS version or commit
- the deployment method
- the GitHub event and redacted delivery identifier
- the check summary and relevant logs
- a minimal, redacted `CODEOWNERS` and Extra CODEOWNERS policy example

Never include:

- GitHub App private keys or webhook secrets
- installation tokens or authorization headers
- full webhook payloads or repository contents from private repositories

## Security reports

Do not report a vulnerability in public. [SECURITY.md](SECURITY.md) explains how to send a private report and which versions receive fixes.

## Operational incidents

Self-hosted operators own availability and incident response. If a required check is stale or missing, stop merges that depend on it. Inspect webhook delivery and worker health, then follow the [operations guide](docs/how-to/operate.md).

Do not weaken repository rules to clear a stuck check.
