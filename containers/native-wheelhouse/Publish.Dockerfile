# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

ARG TARGETARCH

FROM wheelhouse-amd64 AS amd64
FROM wheelhouse-arm64 AS arm64
FROM ${TARGETARCH} AS selected

FROM scratch

ARG SOURCE_REVISION

LABEL org.opencontainers.image.title="Extra CODEOWNERS native wheelhouse" \
      org.opencontainers.image.description="Reproducible native Python wheels for Extra CODEOWNERS" \
      org.opencontainers.image.source="https://github.com/stampbot/extra-codeowners" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.stampbot.extra-codeowners.python="CPython 3.14.6" \
      org.stampbot.extra-codeowners.wheelhouse.schema="2"

COPY --from=selected / /wheelhouse/
