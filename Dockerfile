# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS python-base

FROM python-base AS builder

ENV UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy \
    UV_NO_INSTALLER_METADATA=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /build

COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./

# Install the locked runtime graph before copying application sources so normal
# source changes retain the dependency layer. --no-build also proves that every
# supported platform has a published wheel.
RUN --mount=type=cache,target=/root/.cache/uv \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    uv sync \
      --frozen \
      --no-dev \
      --no-install-project \
      --no-build

# The build backend and its complete transitive closure come from uv.lock. The
# isolated environment never enters the runtime image.
RUN --mount=type=cache,target=/root/.cache/uv \
    UV_PROJECT_ENVIRONMENT=/opt/build-venv \
    uv sync \
      --frozen \
      --only-group build \
      --no-install-project \
      --no-build

COPY extra_codeowners/ ./extra_codeowners/

ARG VERSION=0.0.0+local
ARG SOURCE_REVISION=0000000000000000000000000000000000000000

# Git tags supply VERSION in release builds. A local build receives the honest
# 0.0.0+local fallback instead of claiming a published version.
RUN --mount=type=cache,target=/root/.cache/uv \
    --network=none \
    VIRTUAL_ENV=/opt/build-venv \
    SETUPTOOLS_SCM_PRETEND_VERSION="${VERSION}" \
    uv build \
      --python /opt/build-venv/bin/python \
      --no-build-isolation \
      --wheel \
      --out-dir /dist && \
    uv pip install \
      --python /opt/venv \
      --offline \
      --no-index \
      --no-deps \
      --no-build \
      --strict \
      /dist/extra_codeowners-*.whl && \
    /opt/venv/bin/python -c \
      'import importlib.metadata; assert importlib.metadata.version("extra-codeowners")'

RUN SOURCE_REVISION="${SOURCE_REVISION}" python - <<'PY'
import json
import os
import re
from pathlib import Path

revision = os.environ["SOURCE_REVISION"]
if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
    raise SystemExit("SOURCE_REVISION must be a full lowercase Git object ID")
content = json.dumps(
    {"schema_version": 2, "source_revision": revision},
    sort_keys=True,
    separators=(",", ":"),
) + "\n"
path = Path("/build-identity.json")
path.write_text(content, encoding="utf-8")
path.chmod(0o444)
PY

FROM python-base AS runtime

ARG VERSION=0.0.0+local
ARG SOURCE_REVISION=0000000000000000000000000000000000000000

LABEL org.opencontainers.image.title="Extra CODEOWNERS" \
      org.opencontainers.image.description="Delegated GitHub App approvals for CODEOWNERS policy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/stampbot/extra-codeowners" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="${VERSION}"

ENV PATH="/opt/venv/bin:${PATH}" \
    EXTRA_CODEOWNERS_DATABASE_URL="sqlite:////tmp/extra-codeowners.db" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp

WORKDIR /app

RUN groupadd --gid 65532 extra-codeowners && \
    useradd \
      --uid 65532 \
      --gid 65532 \
      --no-create-home \
      --home-dir /nonexistent \
      --shell /usr/sbin/nologin \
      extra-codeowners && \
    install -d -o 0 -g 0 -m 0755 \
      /usr/share/licenses \
      /usr/share/licenses/extra-codeowners && \
    rm -rf \
      /usr/local/bin/pip \
      /usr/local/bin/pip3 \
      /usr/local/bin/pip3.14 \
      /usr/local/lib/python3.14/ensurepip \
      /usr/local/lib/python3.14/site-packages/pip \
      /usr/local/lib/python3.14/site-packages/pip-*.dist-info

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=0:0 --chmod=0444 /build-identity.json /app/build-identity.json
COPY --chown=0:0 --chmod=0644 LICENSE /usr/share/licenses/extra-codeowners/LICENSE

USER 65532:65532

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"]

ENTRYPOINT ["/opt/venv/bin/python", "-I", "-B", "-u", "-m", "extra_codeowners"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
