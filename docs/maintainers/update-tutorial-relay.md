# Update the tutorial webhook relay

The first-check tutorial uses Cloudflare Quick Tunnels because GitHub needs a
public HTTPS webhook URL while Extra CODEOWNERS runs on a workstation. Treat
that relay as a development dependency, not part of the production design.

Cloudflare can read the proxied payload, and Quick Tunnels have no availability
guarantee. The pinned `cloudflared` client is open source; the pin does not make
Cloudflare's edge service reproducible or independently auditable.

## Before you begin

You need GitHub CLI, `curl`, Python 3, and `sha256sum` or `shasum`. Work from a
clean Extra CODEOWNERS checkout. Use a public, disposable GitHub repository for
the final round trip.

## 1. Review the upstream change

Choose an exact Cloudflare release tag. Review its release notes and the
`cloudflared` source changes since the current pin. Pay particular attention to
request-body streaming, header forwarding, redirects, and Quick Tunnel setup.

Do not update to `latest`, a branch, or an unreviewed release artifact.

## 2. Verify every supported asset

The tutorial supports x86-64 and arm64 Linux and macOS. Download those four
assets into a new directory:

```bash
export CLOUDFLARED_TAG='REPLACE_WITH_EXACT_TAG'
export VERIFY_ROOT
VERIFY_ROOT="$(mktemp -d)"
: >"${VERIFY_ROOT}/.extra-codeowners-relay-review"
printf 'VERIFY_ROOT=%s\n' "$VERIFY_ROOT"

for asset in \
  cloudflared-linux-amd64 \
  cloudflared-linux-arm64 \
  cloudflared-darwin-amd64.tgz \
  cloudflared-darwin-arm64.tgz
do
  gh release download "$CLOUDFLARED_TAG" \
    --repo cloudflare/cloudflared \
    --pattern "$asset" \
    --dir "$VERIFY_ROOT"
done
```

Hash the downloads locally:

```bash
if command -v sha256sum >/dev/null; then
  sha256sum "$VERIFY_ROOT"/cloudflared-*
else
  shasum -a 256 "$VERIFY_ROOT"/cloudflared-*
fi
```

Compare every result with GitHub's recorded digest:

```bash
gh api "repos/cloudflare/cloudflared/releases/tags/${CLOUDFLARED_TAG}" \
  --jq '.assets[]
    | select(.name
        | test("^cloudflared-(linux-(amd64|arm64)|darwin-(amd64|arm64)\\.tgz)$"))
    | [.name, .digest]
    | @tsv'
```

Stop if a local hash, GitHub digest, asset name, or expected platform is
missing or different.

## 3. Update and exercise the pin

Change the version and all four asset/checksum pairs in `mise.tutorial.toml`.
Update the version and asset constants in
`tests/test_documentation_examples.py`, plus the tutorial's displayed version,
in the same change. Then force a clean install for your platform and print the
installed version:

```bash
export MISE_DATA_DIR
MISE_DATA_DIR="$(mktemp -d)"
export MISE_CACHE_DIR
MISE_CACHE_DIR="$(mktemp -d)"
: >"${MISE_DATA_DIR}/.extra-codeowners-relay-review"
: >"${MISE_CACHE_DIR}/.extra-codeowners-relay-review"
printf 'MISE_DATA_DIR=%s\nMISE_CACHE_DIR=%s\n' \
  "$MISE_DATA_DIR" "$MISE_CACHE_DIR"
mise install -E tutorial tutorial-cloudflared
"$(mise where -E tutorial tutorial-cloudflared)/cloudflared" --version
```

## 4. Prove byte and HMAC preservation

Create disposable evidence in the first terminal:

```bash
python3 -c \
  'import secrets, sys; open(sys.argv[1], "wb").write(secrets.token_bytes(32))' \
  "${VERIFY_ROOT}/probe.secret"
printf '{"z":1, "a":2}\n' >"${VERIFY_ROOT}/probe.json"
python3 examples/tutorial/relay_probe.py receive \
  --secret-file "${VERIFY_ROOT}/probe.secret" \
  --payload-file "${VERIFY_ROOT}/probe.json"
```

Leave the receiver running. In a second terminal, start the candidate
`cloudflared` with an empty configuration:

```bash
cd /absolute/path/to/extra-codeowners
export VERIFY_ROOT='REPLACE_WITH_PRINTED_VERIFY_ROOT'
export MISE_DATA_DIR='REPLACE_WITH_PRINTED_MISE_DATA_DIR'
export MISE_CACHE_DIR='REPLACE_WITH_PRINTED_MISE_CACHE_DIR'
printf '{}\n' >"${VERIFY_ROOT}/cloudflared.yml"
"$(mise where -E tutorial tutorial-cloudflared)/cloudflared" tunnel \
  --config "${VERIFY_ROOT}/cloudflared.yml" \
  --no-autoupdate \
  --url http://127.0.0.1:8000
```

Copy the printed `trycloudflare.com` URL. In a third terminal, send the exact
payload and its locally calculated GitHub-style signature:

```bash
cd /absolute/path/to/extra-codeowners
export VERIFY_ROOT='REPLACE_WITH_PRINTED_VERIFY_ROOT'
export TUNNEL_URL='REPLACE_WITH_PRINTED_TRYCLOUDFLARE_URL'
python3 examples/tutorial/relay_probe.py send \
  --secret-file "${VERIFY_ROOT}/probe.secret" \
  --payload-file "${VERIFY_ROOT}/probe.json" \
  --url "${TUNNEL_URL}/probe"
```

The sender must report HTTP `204`, and the receiver must report that the relay
preserved the exact body and HMAC. A mismatch or timeout is a failed update.
Stop the tunnel after the probe.

Run the [first-check tutorial](../tutorials/development-installation.md) through
one real GitHub delivery as the integration check. Extra CODEOWNERS must accept
GitHub's `X-Hub-Signature-256` without any verification exception.

Finally, run:

```bash
mise run check
```

The pull request should include the upstream source comparison, four locally
computed digests, installed-version output, and byte-for-byte signed-delivery
evidence. After review, remove only the three marked temporary directories:

```bash
for directory in "$VERIFY_ROOT" "$MISE_DATA_DIR" "$MISE_CACHE_DIR"; do
  if ! test -f "${directory}/.extra-codeowners-relay-review"; then
    echo "Refusing to remove unmarked path: ${directory}" >&2
    exit 1
  fi
  find "$directory" -depth -delete
done
unset CLOUDFLARED_TAG MISE_CACHE_DIR MISE_DATA_DIR TUNNEL_URL VERIFY_ROOT
```
