# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS builder

ENV UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy \
    UV_NO_INSTALLER_METADATA=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md mise.toml ./

# Bind the reviewed version to the executable selected by the immutable image digest.
RUN python - <<'PY'
import subprocess
import tomllib
from pathlib import Path

expected = tomllib.loads(Path("mise.toml").read_text(encoding="utf-8"))["tools"]["uv"]
reported = subprocess.check_output(["uv", "--version"], text=True).split()
actual = reported[1] if len(reported) >= 2 and reported[0] == "uv" else ""
if actual != expected:
    raise SystemExit(f"digest-selected uv is {actual!r}; reviewed version is {expected!r}")
PY

COPY extra_codeowners/ ./extra_codeowners/

RUN python -c 'import sys; assert sys.version_info[:3] == (3, 14, 6), sys.version'

# Suppress uv's installer-only metadata. In particular, uv_cache.json records
# source ctime and would make the RECORD identity vary across clean checkouts.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --reinstall-package extra-codeowners && \
    rm -f \
      /opt/venv/.gitignore \
      /opt/venv/.lock \
      /opt/venv/CACHEDIR.TAG \
      /opt/venv/bin/activate* \
      /opt/venv/bin/deactivate.bat \
      /opt/venv/bin/pydoc.bat \
      /opt/venv/lib64 \
      /opt/venv/lib/python3.14/site-packages/_virtualenv.py \
      /opt/venv/lib/python3.14/site-packages/_virtualenv.pth && \
    chown -R 0:0 /opt/venv && \
    find /opt/venv -type d -exec chmod 0755 {} + && \
    find /opt/venv -type f -exec chmod 0644 {} + && \
    find /opt/venv/bin -type f -exec chmod 0755 {} +

FROM builder AS test

# Source-binding tests exercise Git object reads. This test-only stage is never
# copied into or published as the runtime image.
RUN apk add --no-cache git=2.54.0-r0

COPY tests/ ./tests/
COPY tools/ ./tools/
COPY .github/dependabot.yml ./.github/dependabot.yml
COPY .github/scripts/container_evidence.py .github/scripts/release_readiness.py ./.github/scripts/
COPY .github/workflows/ ./.github/workflows/
COPY .compliance/container-policy.json ./.compliance/container-policy.json
COPY docs/reference/upgrade-notes.md ./docs/reference/upgrade-notes.md
COPY Dockerfile mise.toml renovate.json ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --group dev --no-editable --reinstall-package extra-codeowners

CMD ["/opt/venv/bin/python", "-m", "pytest", "--no-cov"]

FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS runtime

ARG VCS_REF="unknown"
ARG VERSION="0.0.0"

LABEL org.opencontainers.image.title="Extra CODEOWNERS" \
      org.opencontainers.image.description="Delegated GitHub App approvals for CODEOWNERS policy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/stampbot/extra-codeowners" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}"

ENV PATH="/opt/venv/bin:${PATH}" \
    EXTRA_CODEOWNERS_DATABASE_URL="sqlite:////tmp/extra-codeowners.db" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

# Keep Alpine's installed-package database for SBOM and vulnerability scanners,
# but remove package installers from the immutable application runtime. Create
# the license parents with their final metadata before COPY so no historical
# layer contains unsafe directory headers.
RUN install -d -o 0 -g 0 -m 0755 \
      /usr/share/licenses \
      /usr/share/licenses/extra-codeowners && \
    rm -rf \
    /sbin/apk \
    /usr/local/bin/pip \
    /usr/local/bin/pip3 \
    /usr/local/bin/pip3.14 \
    /usr/local/lib/python3.14/ensurepip \
    /usr/local/lib/python3.14/site-packages/pip \
    /usr/local/lib/python3.14/site-packages/pip-*.dist-info

COPY --chown=0:0 --chmod=0644 LICENSE /usr/share/licenses/extra-codeowners/LICENSE

USER 65532:65532

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"]

ENTRYPOINT ["/opt/venv/bin/python", "-m", "extra_codeowners"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
