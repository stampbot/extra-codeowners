#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s CONTRACT WORK\n' "$0" >&2
  exit 2
fi

contract="$1"
work="$2"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/../.." && pwd)"
wheelhouse_tool="${script_directory}/native_wheelhouse.py"

if [[ "$repository_root" != "$PWD" ]]; then
  printf 'Native-wheelhouse verification must run from the repository root.\n' >&2
  exit 1
fi
if [[ ! -f "$contract" ]]; then
  printf 'Native-wheelhouse consumer contract is missing.\n' >&2
  exit 1
fi
if [[ -e "$work" ]]; then
  printf 'Refusing to reuse a native-wheelhouse verification directory.\n' >&2
  exit 1
fi

umask 077
install --directory --mode=0700 "$work"
python "$wheelhouse_tool" validate-consumer-contract \
  --contract "$contract"

image="$(jq -er '.image' "$contract")"
index_digest="$(jq -er '.index_digest' "$contract")"
certificate_identity="$(jq -er '.signature.certificate_identity' "$contract")"
oidc_issuer="$(jq -er '.signature.oidc_issuer' "$contract")"
image_reference="${image}@${index_digest}"
cosign_home="${work}/cosign-home"
install --directory --mode=0700 "$cosign_home"

HOME="$cosign_home" cosign verify \
  --certificate-identity "$certificate_identity" \
  --certificate-oidc-issuer "$oidc_issuer" \
  "$image_reference" \
  >"${work}/signature-verification.json"
rm -rf "$cosign_home"

docker buildx imagetools inspect \
  "$image_reference" \
  --raw \
  >"${work}/index.json"
python "$wheelhouse_tool" verify-consumer-index \
  --contract "$contract" \
  --index "${work}/index.json"
