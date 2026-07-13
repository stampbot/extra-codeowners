#!/usr/bin/env bash

set -euo pipefail

image="${1:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME}"
expected_architecture="${2:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME}"
container_name="${3:?usage: smoke-container.sh IMAGE ARCHITECTURE CONTAINER_NAME}"

cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

actual_architecture="$(docker image inspect --format '{{.Architecture}}' "$image")"
if [[ "$actual_architecture" != "$expected_architecture" ]]; then
  printf 'Expected architecture %s, found %s.\n' \
    "$expected_architecture" "$actual_architecture" >&2
  exit 1
fi

if [[ "$(docker image inspect --format '{{.Config.User}}' "$image")" != "65532:65532" ]]; then
  printf 'Container image must run as UID/GID 65532.\n' >&2
  exit 1
fi

docker run --detach \
  --name "$container_name" \
  --platform "linux/${expected_architecture}" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  "$image" >/dev/null

docker exec "$container_name" python -c '
import os
from pathlib import Path

import extra_codeowners

path = Path(extra_codeowners.__file__)
assert path.stat().st_uid == 0, "application code must be root-owned"
assert not os.access(path, os.W_OK), "runtime UID must not be able to rewrite application code"

license_path = Path("/usr/share/licenses/extra-codeowners/LICENSE")
assert "Apache License" in license_path.read_text(encoding="utf-8")
assert license_path.stat().st_uid == 0, "license must be root-owned"
assert not os.access(license_path, os.W_OK), "runtime UID must not rewrite the license"
'

for _ in $(seq 1 45); do
  if docker exec "$container_name" python -c '
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8000/health/live", timeout=3) as response:
    assert response.status == 200
' 2>/dev/null; then
    if ! docker exec "$container_name" python -c '
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
