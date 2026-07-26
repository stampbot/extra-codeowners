#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  printf 'usage: %s CONTRACT INPUTS OUTPUT WORK\n' "$0" >&2
  exit 2
fi

contract="$1"
inputs="$2"
output="$3"
work="$4"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/../.." && pwd)"
wheelhouse_tool="${script_directory}/native_wheelhouse.py"

if [[ "$repository_root" != "$PWD" ]]; then
  printf 'Native-wheelhouse fetch must run from the repository root.\n' >&2
  exit 1
fi
if [[ -e "$output" || -e "$work" ]]; then
  printf 'Refusing to reuse a native-wheelhouse output or work directory.\n' >&2
  exit 1
fi
if [[ ! -f "$contract" || ! -f "$inputs" ]]; then
  printf 'Native-wheelhouse contract or input policy is missing.\n' >&2
  exit 1
fi

umask 077
bash "${script_directory}/verify-native-wheelhouse-index.sh" \
  "$contract" \
  "$work"

image="$(jq -er '.image' "$contract")"
source_revision="$(jq -er '.source_revision' "$contract")"
manifest_schema="$(jq -er '.manifest_schema_version | tostring' "$contract")"

container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker rm --force "$container_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for architecture in amd64 arm64; do
  platform="linux/${architecture}"
  manifest_digest="$(
    jq -er \
      --arg platform "$platform" \
      '.platforms[$platform].manifest_digest' \
      "$contract"
  )"
  platform_reference="${image}@${manifest_digest}"
  destination="${work}/wheelhouse-${architecture}"
  install --directory --mode=0700 "$destination"

  docker pull --quiet \
    --platform "$platform" \
    "$platform_reference"
  container_id="$(
    docker create \
      --platform "$platform" \
      "$platform_reference" \
      /wheelhouse-not-executed
  )"
  labels="$(docker inspect --format '{{json .Config.Labels}}' "$container_id")"
  jq -e \
    --arg revision "$source_revision" \
    --arg schema "$manifest_schema" \
    '
      .["org.opencontainers.image.revision"] == $revision
      and .["org.opencontainers.image.source"]
        == "https://github.com/stampbot/extra-codeowners"
      and .["org.stampbot.extra-codeowners.python"] == "CPython 3.14.6"
      and .["org.stampbot.extra-codeowners.wheelhouse.schema"] == $schema
    ' \
    <<<"$labels" \
    >/dev/null
  docker cp \
    "${container_id}:/wheelhouse/." \
    "$destination"
  docker rm "$container_id" >/dev/null
  container_id=""
done

python "$wheelhouse_tool" create-consumer-store \
  --inputs "$inputs" \
  --contract "$contract" \
  --amd64-wheelhouse "${work}/wheelhouse-amd64" \
  --arm64-wheelhouse "${work}/wheelhouse-arm64" \
  --output "$output" \
  --work "${work}/create-store"

for architecture in amd64 arm64; do
  python "$wheelhouse_tool" verify-consumer-store \
    --inputs "$inputs" \
    --contract "$contract" \
    --store "$output" \
    --platform "linux/${architecture}" \
    --work "${work}/verify-store-${architecture}"
done

trap - EXIT
cleanup

# Keep the signed index and verification output as bounded diagnostics. The
# extracted working copies are redundant once the immutable consumer store has
# passed both platform verifiers.
rm -rf \
  "${work}/create-store" \
  "${work}/verify-store-amd64" \
  "${work}/verify-store-arm64" \
  "${work}/wheelhouse-amd64" \
  "${work}/wheelhouse-arm64"
