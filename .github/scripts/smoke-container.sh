#!/usr/bin/env bash

set -euo pipefail

image="${1:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME VERSION PYTHON_VERSION REVISION}"
expected_architecture="${2:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME VERSION PYTHON_VERSION REVISION}"
container_name="${3:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME VERSION PYTHON_VERSION REVISION}"
expected_version="${4:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME VERSION PYTHON_VERSION REVISION}"
expected_python_version="${5:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME VERSION PYTHON_VERSION REVISION}"
expected_revision="${6:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME VERSION PYTHON_VERSION REVISION}"
database_volume="${container_name}-database"
database_url="sqlite:////var/lib/extra-codeowners/extra-codeowners.db"

cleanup() {
  docker rm --force "${container_name}" >/dev/null 2>&1 || true
  docker volume rm --force "${database_volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

actual_architecture="$(docker image inspect --format '{{.Architecture}}' "${image}")"
if [[ "${actual_architecture}" != "${expected_architecture}" ]]; then
  printf 'Expected architecture %s, found %s.\n' \
    "${expected_architecture}" "${actual_architecture}" >&2
  exit 1
fi

actual_version="$(
  docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' \
    "${image}"
)"
actual_revision="$(
  docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "${image}"
)"
if [[ "${actual_version}" != "${expected_version}" ]]; then
  printf 'Expected image version %s, found %s.\n' "${expected_version}" "${actual_version}" >&2
  exit 1
fi
if [[ "${actual_revision}" != "${expected_revision}" ]]; then
  printf 'Expected image revision %s, found %s.\n' "${expected_revision}" "${actual_revision}" >&2
  exit 1
fi
if [[ "$(docker image inspect --format '{{.Config.User}}' "${image}")" != "65532:65532" ]]; then
  printf 'Container image must run as UID/GID 65532.\n' >&2
  exit 1
fi

docker volume create "${database_volume}" >/dev/null

# Docker user-namespace remapping makes host-directory ownership unreliable.
# Prepare an isolated named volume as root without giving the application
# container any additional capability.
docker run --rm \
  --user 0:0 \
  --network none \
  --read-only \
  --volume "${database_volume}:/var/lib/extra-codeowners" \
  --cap-drop ALL \
  --cap-add CHOWN \
  --security-opt no-new-privileges \
  --entrypoint /opt/venv/bin/python \
  "${image}" -c '
import os

os.chmod("/var/lib/extra-codeowners", 0o700)
os.chown("/var/lib/extra-codeowners", 65532, 65532)
'

docker run --rm \
  --platform "linux/${expected_architecture}" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --volume "${database_volume}:/var/lib/extra-codeowners" \
  --env "EXTRA_CODEOWNERS_DATABASE_URL=${database_url}" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  "${image}" database migrate >/dev/null

docker run --detach \
  --name "${container_name}" \
  --platform "linux/${expected_architecture}" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --volume "${database_volume}:/var/lib/extra-codeowners" \
  --env "EXTRA_CODEOWNERS_DATABASE_URL=${database_url}" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  "${image}" >/dev/null

docker exec \
  --env "EXPECTED_PYTHON_VERSION=${expected_python_version}" \
  --env "EXPECTED_REVISION=${expected_revision}" \
  "${container_name}" /opt/venv/bin/python -c '
import importlib.metadata
import os
import platform
import stat
from pathlib import Path

import cryptography
import extra_codeowners
import greenlet
import pydantic_core
import psycopg
from extra_codeowners.build_identity import BUILD_IDENTITY_PATH, load_build_identity

assert importlib.metadata.version("extra-codeowners") == os.environ["EXPECTED_PYTHON_VERSION"]
assert platform.libc_ver()[0] == "glibc"
assert psycopg.pq.__impl__ == "binary"
assert Path(extra_codeowners.__file__).stat().st_uid == 0
assert not os.access(Path(extra_codeowners.__file__), os.W_OK)
assert not any(Path("/usr/local/bin").glob("pip*"))
assert not Path("/usr/local/lib/python3.14/ensurepip").exists()
assert "Apache License" in Path("/usr/share/licenses/extra-codeowners/LICENSE").read_text()
identity = load_build_identity()
assert identity is not None
assert identity.source_revision == os.environ["EXPECTED_REVISION"]
assert BUILD_IDENTITY_PATH.stat().st_uid == 0
assert stat.S_IMODE(BUILD_IDENTITY_PATH.stat().st_mode) == 0o444
'

for _ in $(seq 1 45); do
  if docker exec "${container_name}" /opt/venv/bin/python -c '
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8000/health/live", timeout=3) as response:
    assert response.status == 200
' 2>/dev/null; then
    docker exec \
      --env "EXPECTED_PYTHON_VERSION=${expected_python_version}" \
      --env "EXPECTED_REVISION=${expected_revision}" \
      "${container_name}" /opt/venv/bin/python -c '
import json
import os
import urllib.error
import urllib.request

with urllib.request.urlopen(
    "http://127.0.0.1:8000/api/runtime-identity",
    timeout=3,
) as response:
    assert response.status == 200
    assert response.headers.get("Cache-Control") == "no-store, max-age=0"
    identity = json.load(response)
assert identity["application_version"] == os.environ["EXPECTED_PYTHON_VERSION"]
assert identity["build_revision"] == os.environ["EXPECTED_REVISION"]
assert identity["database_backend"] == "sqlite"

try:
    urllib.request.urlopen("http://127.0.0.1:8000/health/ready", timeout=3)
except urllib.error.HTTPError as error:
    assert error.code == 503
else:
    raise AssertionError("unconfigured container must not report ready")
'
    exit 0
  fi
  sleep 1
done

docker logs "${container_name}" >&2
printf 'Container did not become live within 45 seconds.\n' >&2
exit 1
