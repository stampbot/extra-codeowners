# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS toolchain

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONNOUSERSITE=1 \
    PYTHONPATH=/usr/lib/python3.14/site-packages

RUN apk add --no-cache \
    binutils=2.45.1-r1 \
    build-base=0.5-r4 \
    cargo=1.96.1-r0 \
    cython=3.2.4-r2 \
    libffi-dev=3.5.2-r1 \
    libpq-dev=18.4-r0 \
    maturin=1.11.5-r1 \
    py3-build=1.4.2-r0 \
    py3-setuptools=82.0.1-r1 \
    py3-wheel=0.47.0-r0 \
    rust=1.96.1-r0 && \
    addgroup -g 65532 native-builder && \
    adduser -D -H -u 65532 -G native-builder native-builder && \
    install -d -o 65532 -g 65532 -m 0700 /build-root

WORKDIR /wheelhouse-build

COPY --chown=0:0 --chmod=0444 containers/native-wheelhouse/inputs.json ./inputs.json
COPY --chown=0:0 --chmod=0444 .github/scripts/native_wheelhouse.py ./native_wheelhouse.py

ADD --checksum=sha256:2a31842634fc3f9975c67ec82928b68f66d9a95b8c93b88b0ed36fa560003468 --chmod=0444 \
    https://github.com/python-cffi/cffi/archive/d9f6f70adac5ca9f260abf5405cf4d0373767b65.tar.gz \
    /wheelhouse-build/sources/cffi.tar.gz
ADD --checksum=sha256:714f0e916a0d239f42dc0554bab31cd2b79d9d11b7a96cd397116dba7c658abf --chmod=0444 \
    https://github.com/psycopg/psycopg/archive/refs/tags/3.3.4.tar.gz \
    /wheelhouse-build/sources/psycopg.tar.gz
ADD --checksum=sha256:62f875393d7f270851f20523dd2e29f082bcc82292d66db2b64ea71f64b6e1c1 --chmod=0444 \
    https://files.pythonhosted.org/packages/9d/56/921726b776ace8d8f5db44c4ef961006580d91dc52b803c489fafd1aa249/pydantic_core-2.46.4.tar.gz \
    /wheelhouse-build/sources/pydantic-core.tar.gz
ADD --checksum=sha256:7342096b2de0309193cbddb1c446a2d0ae763dac17368413af15b25088edd290 --chmod=0444 \
    https://github.com/pypa/setuptools/archive/f37845bce6bb06ec25c24cf30210a485e945d21e.tar.gz \
    /wheelhouse-build/sources/setuptools.tar.gz

RUN chmod 0555 ./sources && \
    python ./native_wheelhouse.py validate-inputs --inputs ./inputs.json

USER 65532:65532

FROM toolchain AS cargo-inputs

# This is the only unbounded dependency-fetch step. Cargo.lock supplies the
# exact crate versions and checksums; the script rejects any extra or missing
# registry archive before a later stage can compile it.
RUN python ./native_wheelhouse.py prepare-cargo \
      --inputs ./inputs.json \
      --sources ./sources \
      --cargo-home /build-root/cargo-home \
      --work /build-root/cargo-work

FROM toolchain AS build-a

COPY --from=cargo-inputs --chown=65532:65532 /build-root/cargo-home /build-root/cargo-home

RUN --network=none python ./native_wheelhouse.py build-pass \
      --inputs ./inputs.json \
      --sources ./sources \
      --cargo-home /build-root/cargo-home \
      --output /build-root/pass \
      --work /build-root/work \
      --pass-name first

FROM toolchain AS build-b

COPY --from=cargo-inputs --chown=65532:65532 /build-root/cargo-home /build-root/cargo-home

RUN --network=none python ./native_wheelhouse.py build-pass \
      --inputs ./inputs.json \
      --sources ./sources \
      --cargo-home /build-root/cargo-home \
      --output /build-root/pass \
      --work /build-root/work \
      --pass-name second

FROM toolchain AS assemble

COPY --from=cargo-inputs --chown=65532:65532 /build-root/cargo-home /build-root/cargo-home
COPY --from=build-a --chown=0:0 /build-root/pass /build-root/pass-a
COPY --from=build-b --chown=0:0 /build-root/pass /build-root/pass-b

RUN --network=none python ./native_wheelhouse.py assemble \
      --inputs ./inputs.json \
      --sources ./sources \
      --cargo-home /build-root/cargo-home \
      --first /build-root/pass-a \
      --second /build-root/pass-b \
      --output /build-root/wheelhouse \
      --work /build-root/assemble-work

FROM scratch AS wheelhouse

ARG SOURCE_REVISION

LABEL org.opencontainers.image.title="Extra CODEOWNERS native wheelhouse" \
      org.opencontainers.image.description="Reproducible native Python wheels for Extra CODEOWNERS" \
      org.opencontainers.image.source="https://github.com/stampbot/extra-codeowners" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.stampbot.extra-codeowners.python="CPython 3.14.6" \
      org.stampbot.extra-codeowners.wheelhouse.schema="1"

COPY --from=assemble /build-root/wheelhouse/ /wheelhouse/
