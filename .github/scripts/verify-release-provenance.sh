#!/usr/bin/env bash

# Verify the cryptographic evidence for a completed immutable release without
# modifying its GitHub Release, tags, or registry artifacts.
set -euo pipefail

asset_directory="${1:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
image="${2:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
image_digest="${3:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
chart_reference="${4:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
chart_digest="${5:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
python_version="${6:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
version="${7:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"
revision="${8:?usage: verify-release-provenance.sh ASSET_DIRECTORY IMAGE IMAGE_DIGEST CHART_REFERENCE CHART_DIGEST PYTHON_VERSION VERSION REVISION}"

if ! [[ "${image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  ! [[ "${chart_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  ! [[ "${revision}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Release provenance inputs contain an invalid digest or revision.\n' >&2
  exit 2
fi

temporary_directory="$(mktemp -d "${RUNNER_TEMP:-/tmp}/extra-codeowners-provenance.XXXXXX")"
cleanup() {
  find "${temporary_directory}" -depth -delete
}
trap cleanup EXIT

certificate_identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/heads/main"
signer_workflow="${GITHUB_REPOSITORY}/.github/workflows/release.yml"
cosign_identity=(
  --certificate-identity "${certificate_identity}"
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
  --certificate-github-workflow-repository "${GITHUB_REPOSITORY}"
  --certificate-github-workflow-ref refs/heads/main
  --certificate-github-workflow-sha "${revision}"
  --certificate-github-workflow-trigger push
)

retry() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    fi
    printf 'Verification command attempt %d failed.\n' "${attempt}" >&2
    if (( attempt < 3 )); then
      sleep "$((attempt * 5))"
    fi
  done
  return 1
}

retry_to_file() {
  local destination="$1"
  shift
  local attempt
  for attempt in 1 2 3; do
    if "$@" >"${destination}"; then
      return 0
    fi
    printf 'Verification command attempt %d failed.\n' "${attempt}" >&2
    if (( attempt < 3 )); then
      sleep "$((attempt * 5))"
    fi
  done
  return 1
}

verify_github_attestation() {
  local artifact="$1"
  local subject_name="$2"
  local subject_digest="$3"
  local output
  output="${temporary_directory}/attestation-$(basename "${subject_name}").json"

  retry_to_file "${output}" gh attestation verify "${artifact}" \
    --repo "${GITHUB_REPOSITORY}" \
    --signer-workflow "${signer_workflow}" \
    --source-digest "${revision}" \
    --source-ref refs/heads/main \
    --deny-self-hosted-runners \
    --format json

  jq -e \
    --arg certificate_identity "${certificate_identity}" \
    --arg subject_name "${subject_name}" \
    --arg subject_digest "${subject_digest}" \
    'type == "array" and
      length > 0 and
      all(.[];
        .verificationResult.signature.certificate.subjectAlternativeName == $certificate_identity and
        ([.verificationResult.statement.subject[]? |
          select(.name == $subject_name and .digest.sha256 == $subject_digest)] | length == 1))' \
    "${output}" >/dev/null
}

verify_release_file() {
  local artifact="$1"
  local subject_name
  local subject_digest
  subject_name="$(basename "${artifact}")"
  subject_digest="$(sha256sum "${artifact}" | awk '{print $1}')"

  test -s "${artifact}"
  test -s "${artifact}.sigstore.json"
  verify_github_attestation "${artifact}" "${subject_name}" "${subject_digest}"
  retry cosign verify-blob \
    --bundle "${artifact}.sigstore.json" \
    "${cosign_identity[@]}" \
    "${artifact}"
}

verify_raw_container_inventory() {
  local inventory="$1"
  local architecture="$2"
  local platform_digest="$3"

  if ! [[ "${platform_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'Raw container inventory has an invalid %s platform digest.\n' "${architecture}" >&2
    exit 2
  fi
  test -s "${inventory}"
  jq -e \
    --arg architecture "${architecture}" \
    --arg platform_digest "${platform_digest}" \
    'type == "object" and
      .schema_version == 2 and
      (.image | type == "object") and
      (.image.architecture == $architecture) and
      (.image.distro | type == "string" and test("^debian-[0-9]+$")) and
      (.image.os_release_path == "usr/lib/os-release") and
      (.image.os_release_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.image.os_release_size | type == "number" and . > 0 and floor == .) and
      (.image.platform_digest == $platform_digest) and
      ((.image | keys | sort) == [
        "architecture",
        "distro",
        "os_release_path",
        "os_release_sha256",
        "os_release_size",
        "platform_digest"
      ]) and
      (.debian | type == "object") and
      .debian.status_path == "var/lib/dpkg/status" and
      (.debian.status_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.debian.packages | type == "array" and length > 0) and
      (.debian.copyright_files | type == "array") and
      (.debian.shared_license_files | type == "array") and
      (.python | type == "object") and
      (.python.distributions | type == "array" and length > 0) and
      (.python.embedded_sboms | type == "array") and
      (.python.native_files | type == "array")' \
    "${inventory}" >/dev/null
  verify_release_file "${inventory}"
}

verify_openvex_image_attestation() {
  local vex="$1"
  local attestations="${temporary_directory}/openvex-attestations.json"

  retry_to_file "${attestations}" cosign verify-attestation --type openvex \
    "${cosign_identity[@]}" \
    "${image}@${image_digest}"
  python -I -S -B tools/release_vex.py verify-attestation \
    --vex "${vex}" \
    --attestations "${attestations}" \
    --image "${image}" \
    --image-digest "${image_digest}"
}

wheel="${asset_directory}/extra_codeowners-${python_version}-py3-none-any.whl"
sdist="${asset_directory}/extra_codeowners-${python_version}.tar.gz"
chart="${asset_directory}/extra-codeowners-${version}.tgz"
amd64_inventory="${asset_directory}/distribution-inventory-amd64.json"
arm64_inventory="${asset_directory}/distribution-inventory-arm64.json"
vex="${asset_directory}/extra-codeowners-${version}.openvex.json"

verify_release_file "${wheel}"
verify_release_file "${sdist}"
verify_release_file "${chart}"
verify_raw_container_inventory \
  "${amd64_inventory}" \
  amd64 \
  "$(<"${asset_directory}/digest-amd64.txt")"
verify_raw_container_inventory \
  "${arm64_inventory}" \
  arm64 \
  "$(<"${asset_directory}/digest-arm64.txt")"
verify_release_file "${vex}"
python -I -S -B tools/release_vex.py stage \
  --source "${vex}" \
  --inventory "${amd64_inventory}" \
  --inventory "${arm64_inventory}"
verify_openvex_image_attestation "${vex}"
verify_github_attestation \
  "oci://${image}@${image_digest}" \
  "${image}" \
  "${image_digest#sha256:}"
retry cosign verify "${cosign_identity[@]}" "${image}@${image_digest}"
retry cosign verify "${cosign_identity[@]}" "${chart_reference}@${chart_digest}"
