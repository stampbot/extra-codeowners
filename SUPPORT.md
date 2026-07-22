# Support

Extra CODEOWNERS does not yet have a tagged release or a hosted service.
Maintainer support is best-effort, with no response-time commitment.

## Choose the right channel

Use [GitHub Discussions](https://github.com/stampbot/extra-codeowners/discussions)
for usage questions, deployment design, and policy feedback. Search existing
discussions before starting one.

Use [GitHub Issues](https://github.com/stampbot/extra-codeowners/issues) for a
reproducible defect or a scoped feature request. A useful report includes:

- the Extra CODEOWNERS version or commit
- the deployment method
- the GitHub event and a redacted delivery identifier
- the check summary and relevant logs
- minimal, redacted CODEOWNERS and Extra CODEOWNERS policy examples.

Remove secrets and private repository data before posting. In particular, do
not include:

- a GitHub App private key or webhook secret
- an installation token or authorization header
- a complete webhook payload or private repository contents.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability.
[SECURITY.md](SECURITY.md) explains how to send a private report and which
versions receive fixes.

## Handle an operational incident

Self-hosted operators own availability and incident response. If a required
check is stale or missing, stop merges that depend on it. Inspect GitHub webhook
delivery and worker health, then follow the
[operations guide](docs/how-to/operate.md).

Do not weaken repository rules to clear a stuck check.
