#!/usr/bin/env bash

set -euo pipefail

image="${1:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME}"
expected_architecture="${2:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME}"
container_name="${3:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME}"
database_volume="${container_name}-database"
database_url="sqlite:////var/lib/extra-codeowners/extra-codeowners.db"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  docker volume rm --force "$database_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker volume create "$database_volume" >/dev/null

actual_architecture="$(docker image inspect --format '{{.Architecture}}' "$image")"
if [[ "$actual_architecture" != "$expected_architecture" ]]; then
  printf 'Expected architecture %s, found %s.\n' \
    "$expected_architecture" "$actual_architecture" >&2
  exit 1
fi

expected_build_revision="$(
  docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "$image"
)"
expected_wheel_sha256="$(
  docker image inspect \
    --format '{{ index .Config.Labels "org.stampbot.extra-codeowners.application-wheel.sha256" }}' \
    "$image"
)"
expected_selection_record_sha256="$(
  docker image inspect \
    --format \
      '{{ index .Config.Labels "org.stampbot.extra-codeowners.python-selection-record.sha256" }}' \
    "$image"
)"
if ! [[ "$expected_build_revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Container image has an invalid source-revision label.\n' >&2
  exit 1
fi
for digest in "$expected_wheel_sha256" "$expected_selection_record_sha256"; do
  if ! [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'Container image has an invalid application-artifact label.\n' >&2
    exit 1
  fi
done

if [[ "$(docker image inspect --format '{{.Config.User}}' "$image")" != "65532:65532" ]]; then
  printf 'Container image must run as UID/GID 65532.\n' >&2
  exit 1
fi

# Docker user-namespace remapping makes host-directory ownership unreliable.
# Prepare an isolated named volume without network access, then run both real
# application commands as the image's default non-root UID/GID.
docker run --rm \
  --user 0:0 \
  --network none \
  --read-only \
  --volume "$database_volume:/var/lib/extra-codeowners" \
  --cap-drop ALL \
  --cap-add CHOWN \
  --security-opt no-new-privileges \
  --entrypoint /opt/venv/bin/python \
  "$image" -c '
import os

os.chmod("/var/lib/extra-codeowners", 0o700)
os.chown("/var/lib/extra-codeowners", 65532, 65532)
'

docker run --rm \
  --platform "linux/${expected_architecture}" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --volume "$database_volume:/var/lib/extra-codeowners" \
  --env "EXTRA_CODEOWNERS_DATABASE_URL=$database_url" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  "$image" database migrate >/dev/null

docker run --detach \
  --name "$container_name" \
  --platform "linux/${expected_architecture}" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --volume "$database_volume:/var/lib/extra-codeowners" \
  --env "EXTRA_CODEOWNERS_DATABASE_URL=$database_url" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  "$image" >/dev/null

docker exec \
  --env "EXPECTED_BUILD_REVISION=$expected_build_revision" \
  --env "EXPECTED_SELECTION_RECORD_SHA256=$expected_selection_record_sha256" \
  --env "EXPECTED_WHEEL_SHA256=$expected_wheel_sha256" \
  "$container_name" /opt/venv/bin/python -c '
import os
import stat
from pathlib import Path

import extra_codeowners
from extra_codeowners.build_identity import BUILD_IDENTITY_PATH, load_build_identity

path = Path(extra_codeowners.__file__)
assert path.stat().st_uid == 0, "application code must be root-owned"
assert not os.access(path, os.W_OK), "runtime UID must not be able to rewrite application code"
assert not Path("/build").exists(), "builder and test sources must not enter the runtime image"
assert not Path("/sbin/apk").exists(), "runtime image must not include the apk executable"
assert not Path("/usr/local/lib/python3.14/ensurepip").exists(), "runtime image must not bootstrap pip"
assert not any(Path("/usr/local/bin").glob("pip*")), "runtime image must not include pip entry points"
assert not any(Path("/usr/local/lib/python3.14/site-packages").glob("pip*")), (
    "runtime image must not include the system pip package"
)
assert not any(
    path.suffix in {".pyc", ".pyo"}
    for path in Path("/opt/venv").rglob("*")
    if path.is_file()
), "runtime virtual environment must not contain executable bytecode caches"
assert not Path("/opt/venv/lib/python3.14/site-packages/_virtualenv.py").exists()
assert not Path("/opt/venv/lib/python3.14/site-packages/_virtualenv.pth").exists()
assert not Path("/opt/venv/bin/activate").exists()
assert not Path("/opt/venv/.lock").exists()

license_path = Path("/usr/share/licenses/extra-codeowners/LICENSE")
assert "Apache License" in license_path.read_text(encoding="utf-8")
assert license_path.stat().st_uid == 0, "license must be root-owned"
assert stat.S_IMODE(license_path.stat().st_mode) == 0o644
for parent in (license_path.parent, license_path.parent.parent):
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755, f"unsafe license parent: {parent}"
assert not os.access(license_path, os.W_OK), "runtime UID must not rewrite the license"

build_identity = load_build_identity()
assert build_identity is not None, "official image must contain verified build identity"
assert build_identity.source_revision == os.environ["EXPECTED_BUILD_REVISION"]
assert build_identity.wheel_sha256 == os.environ["EXPECTED_WHEEL_SHA256"]
assert (
    build_identity.selection_record_sha256
    == os.environ["EXPECTED_SELECTION_RECORD_SHA256"]
)
assert BUILD_IDENTITY_PATH.stat().st_uid == 0, "build identity must be root-owned"
assert stat.S_IMODE(BUILD_IDENTITY_PATH.stat().st_mode) == 0o444
assert not os.access(BUILD_IDENTITY_PATH, os.W_OK), (
    "runtime UID must not rewrite build identity"
)
'

docker exec --interactive "$container_name" /opt/venv/bin/python - \
  <"${script_directory}/verify-container-runtime.py"

for _ in $(seq 1 45); do
  if docker exec "$container_name" /opt/venv/bin/python -c '
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8000/health/live", timeout=3) as response:
    assert response.status == 200
' 2>/dev/null; then
    if ! docker exec \
      --env "EXPECTED_BUILD_REVISION=$expected_build_revision" \
      "$container_name" /opt/venv/bin/python -c '
import json
import os
import urllib.request

with urllib.request.urlopen(
    "http://127.0.0.1:8000/api/runtime-identity",
    timeout=3,
) as response:
    assert response.status == 200
    assert response.headers.get("Cache-Control") == "no-store, max-age=0"
    identity = json.load(response)
assert identity["build_revision"] == os.environ["EXPECTED_BUILD_REVISION"]
assert identity["database_backend"] == "sqlite"
'; then
      docker logs "$container_name" >&2
      printf 'Container runtime-identity endpoint failed build binding.\n' >&2
      exit 1
    fi
    if ! docker exec "$container_name" /opt/venv/bin/python -c '
import urllib.error
import urllib.request

try:
    urllib.request.urlopen("http://127.0.0.1:8000/health/ready", timeout=3)
except urllib.error.HTTPError as error:
    assert error.code == 503, "unconfigured readiness must return HTTP 503"
else:
    raise AssertionError("unconfigured container must not report ready")
'; then
      docker logs "$container_name" >&2
      printf 'Container readiness endpoint failed closed-state validation.\n' >&2
      exit 1
    fi
    exit 0
  fi
  sleep 1
done

docker logs "$container_name" >&2
printf 'Container did not become live within 45 seconds.\n' >&2
exit 1
