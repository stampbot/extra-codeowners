#!/usr/bin/env bash
# Common postcondition for a fresh publication, a retry, or an existing release.
set -euo pipefail

: "${GITHUB_REPOSITORY:?}" "${TAG:?}" "${PRERELEASE:?}" "${VERSION:?}" "${REVISION:?}"
: "${IMAGE:?}" "${CHART_REFERENCE:?}" "${PYTHON_VERSION:?}"
staged="${1:-}"
scratch="$(mktemp -d)"
trap 'rm -rf -- "${scratch}"' EXIT
assets="${scratch}/assets"
metadata="${scratch}/release.json"

retry() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    fi
    printf 'Command attempt %d failed.\n' "${attempt}" >&2
    if (( attempt < 3 )); then
      sleep "$((attempt * 5))"
    else
      return 1
    fi
  done
}

if [[ -z "${staged}" ]]; then
  test "$(git cat-file -t "refs/tags/${TAG}")" = tag
  test "$(git rev-parse --verify "refs/tags/${TAG}^{commit}")" = "${REVISION}"
fi

for attempt in 1 2 3; do
  if gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}" >"${metadata}"; then
    if jq -e --arg tag "${TAG}" --argjson prerelease "${PRERELEASE}" '
      .tag_name == $tag and
      .draft == false and
      .immutable == true and
      .prerelease == $prerelease and
      (.assets | type == "array") and (.assets | length > 0) and
      ([.assets[].name] | length == (unique | length)) and
      all(.assets[];
        (.name | type == "string") and
        (.size | type == "number") and .size > 0 and
        (.digest | type == "string") and
        (.digest | test("^sha256:[0-9a-f]{64}$")))
    ' "${metadata}" >/dev/null; then
      break
    fi
    printf 'Release postcondition attempt %d is incomplete or inconsistent.\n' "${attempt}" >&2
  else
    printf 'Published-release lookup attempt %d failed.\n' "${attempt}" >&2
  fi
  (( attempt < 3 )) || exit 1
  sleep "$((attempt * 5))"
done

download_assets() {
  rm -rf -- "${assets}"
  mkdir "${assets}"
  gh release download "${TAG}" --repo "${GITHUB_REPOSITORY}" --dir "${assets}" --clobber
}
retry download_assets
python3 -I -B tools/published_release_assets.py "${metadata}" "${assets}" "${staged}"

if [[ -z "${staged}" ]]; then
  required_assets=(
    "extra_codeowners-${PYTHON_VERSION}-py3-none-any.whl"
    "extra_codeowners-${PYTHON_VERSION}-py3-none-any.whl.sigstore.json"
    "extra_codeowners-${PYTHON_VERSION}.tar.gz"
    "extra_codeowners-${PYTHON_VERSION}.tar.gz.sigstore.json"
    "extra-codeowners-${VERSION}.tgz"
    "extra-codeowners-${VERSION}.tgz.sigstore.json"
    chart-reference.txt
    build-index-amd64.txt
    build-index-arm64.txt
    digest-amd64.txt
    digest-arm64.txt
    image-reference.txt
    "extra-codeowners-${VERSION}.openvex.json"
    "extra-codeowners-${VERSION}.openvex.json.sigstore.json"
    distribution-inventory-amd64.json
    distribution-inventory-amd64.json.sigstore.json
    recipient-notices-amd64.tar.gz
    recipient-notices-amd64.tar.gz.sigstore.json
    native-components-amd64.cdx.json
    native-components-amd64.cdx.json.sigstore.json
    cpython-source-amd64.tar.gz
    cpython-source-amd64.tar.gz.sigstore.json
    python-source-amd64.tar.gz
    python-source-amd64.tar.gz.sigstore.json
    rust-source-amd64.tar.gz
    rust-source-amd64.tar.gz.sigstore.json
    distribution-inventory-arm64.json
    distribution-inventory-arm64.json.sigstore.json
    recipient-notices-arm64.tar.gz
    recipient-notices-arm64.tar.gz.sigstore.json
    native-components-arm64.cdx.json
    native-components-arm64.cdx.json.sigstore.json
    cpython-source-arm64.tar.gz
    cpython-source-arm64.tar.gz.sigstore.json
    python-source-arm64.tar.gz
    python-source-arm64.tar.gz.sigstore.json
    rust-source-arm64.tar.gz
    rust-source-arm64.tar.gz.sigstore.json
    debian-source.tar
    debian-source.tar.sigstore.json
    vulnerability-report-amd64.json
    vulnerability-report-arm64.json
  )
  for asset in "${required_assets[@]}"; do
    test -f "${assets}/${asset}"
  done

  retry docker buildx imagetools inspect "${IMAGE}:${VERSION}" >"${scratch}/image-manifest"
  manifest="$(<"${scratch}/image-manifest")"
  grep -Fq 'linux/amd64' <<<"${manifest}"
  grep -Fq 'linux/arm64' <<<"${manifest}"
  image_digest="$(awk '$1 == "Digest:" {print $2; exit}' "${scratch}/image-manifest")"
  if ! [[ "${image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'Could not resolve the published image digest.\n' >&2
    exit 1
  fi
  test "$(<"${assets}/image-reference.txt")" = "${IMAGE}@${image_digest}"
  retry docker buildx imagetools inspect --raw "${IMAGE}@${image_digest}" \
    >"${scratch}/image-manifest.json"
  for architecture in amd64 arm64; do
    released_digest="$(<"${assets}/digest-${architecture}.txt")"
    published_digest="$(
      jq -er --arg architecture "${architecture}" \
        '[.manifests[] | select(
          .platform.os == "linux" and .platform.architecture == $architecture
        ) | .digest] | if length == 1 then .[0] else error(
          "expected exactly one manifest for " + $architecture
          ) end' "${scratch}/image-manifest.json"
    )"
    test "${published_digest}" = "${released_digest}"
  done

  retry helm show chart \
    "oci://${CHART_REFERENCE}" \
    --version "${VERSION}" >"${scratch}/published-chart"
  grep -Fxq "version: ${VERSION}" "${scratch}/published-chart"
  grep -Fxq "appVersion: ${VERSION}" "${scratch}/published-chart"
  chart_reference="${CHART_REFERENCE}"
  retry docker buildx imagetools inspect "${chart_reference}:${VERSION}" \
    --format '{{json .Manifest}}' >"${scratch}/chart-manifest.json"
  chart_digest="$(jq -er .digest "${scratch}/chart-manifest.json")"
  if ! [[ "${chart_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'Could not resolve the published chart digest.\n' >&2
    exit 1
  fi
  test "$(<"${assets}/chart-reference.txt")" = \
    "${chart_reference}@${chart_digest}"
  mkdir -p "${scratch}/published-chart-artifact"
  retry helm pull "oci://${chart_reference}" --version "${VERSION}" \
    --destination "${scratch}/published-chart-artifact"
  cmp --silent \
    "${assets}/extra-codeowners-${VERSION}.tgz" \
    "${scratch}/published-chart-artifact/extra-codeowners-${VERSION}.tgz"
else
  # The publication job already checked the registry against its staged bytes.
  chart_reference="${CHART_REFERENCE}"
  image_digest="${IMAGE_DIGEST:?}"
  chart_digest="${CHART_DIGEST:?}"
fi

.github/scripts/verify-release-provenance.sh \
  "${assets}" "${IMAGE}" "${image_digest}" "${chart_reference}" "${chart_digest}" \
  "${PYTHON_VERSION}" "${VERSION}" "${REVISION}"
