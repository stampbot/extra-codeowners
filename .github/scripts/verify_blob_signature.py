#!/usr/bin/env python3
"""Verify one acquired release asset and its exact Sigstore bundle."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, ObjectIdentifier

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_actions_build_provenance as actions_provenance  # noqa: E402
import verify_github_release as github_release  # noqa: E402
from release_controller import (  # noqa: E402
    MAX_ID,
    Asset,
    ControllerError,
    ReleasePlan,
    canonical_json,
    load_manifest,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/authenticated-blob-signature"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MINIMUM_COSIGN_VERSION = (3, 0, 6)
MINIMUM_COSIGN_VERSION_TEXT = "3.0.6"
MAX_COSIGN_MAJOR_VERSION = 3
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_JSON_ITEMS = 40_000
MAX_JSON_DEPTH = 64
MAX_STRING_BYTES = 16 * 1024
MAX_CERTIFICATE_BYTES = 32 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_TLOG_BODY_BYTES = 256 * 1024
MAX_TLOG_PROOF_HASHES = 128
MAX_TIMESTAMP_COUNT = 8
MAX_COMMAND_OUTPUT_BYTES = 1024
MAX_COMMAND_ERROR_BYTES = 16 * 1024
MAX_VERSION_OUTPUT_BYTES = 4096
READ_CHUNK_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 180.0
MAX_TIMEOUT_SECONDS = 600.0
TERMINATION_GRACE_SECONDS = 2.0

COSIGN_VERSION = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")
GO_VERSION = re.compile(r"^go[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
PLATFORM = re.compile(r"^linux/(?:amd64|arm64)$")
RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")

FULCIO_OID_PREFIX = "1.3.6.1.4.1.57264.1."
OID_ISSUER_V2 = ObjectIdentifier(f"{FULCIO_OID_PREFIX}8")
OID_BUILD_SIGNER_URI = ObjectIdentifier(f"{FULCIO_OID_PREFIX}9")
OID_BUILD_SIGNER_DIGEST = ObjectIdentifier(f"{FULCIO_OID_PREFIX}10")
OID_RUNNER_ENVIRONMENT = ObjectIdentifier(f"{FULCIO_OID_PREFIX}11")
OID_SOURCE_REPOSITORY_URI = ObjectIdentifier(f"{FULCIO_OID_PREFIX}12")
OID_SOURCE_REPOSITORY_DIGEST = ObjectIdentifier(f"{FULCIO_OID_PREFIX}13")
OID_SOURCE_REPOSITORY_REF = ObjectIdentifier(f"{FULCIO_OID_PREFIX}14")
OID_SOURCE_REPOSITORY_ID = ObjectIdentifier(f"{FULCIO_OID_PREFIX}15")
OID_SOURCE_REPOSITORY_OWNER_URI = ObjectIdentifier(f"{FULCIO_OID_PREFIX}16")
OID_SOURCE_REPOSITORY_OWNER_ID = ObjectIdentifier(f"{FULCIO_OID_PREFIX}17")
OID_BUILD_CONFIG_URI = ObjectIdentifier(f"{FULCIO_OID_PREFIX}18")
OID_BUILD_CONFIG_DIGEST = ObjectIdentifier(f"{FULCIO_OID_PREFIX}19")
OID_BUILD_TRIGGER = ObjectIdentifier(f"{FULCIO_OID_PREFIX}20")
OID_RUN_INVOCATION_URI = ObjectIdentifier(f"{FULCIO_OID_PREFIX}21")
OID_SOURCE_REPOSITORY_VISIBILITY = ObjectIdentifier(f"{FULCIO_OID_PREFIX}22")
OID_DEPLOYMENT_ENVIRONMENT = ObjectIdentifier(f"{FULCIO_OID_PREFIX}23")
OID_TOKEN_SUBJECT = ObjectIdentifier(f"{FULCIO_OID_PREFIX}24")


class BlobVerificationError(RuntimeError):
    """The selected blob signature could not be authenticated."""


class CosignClient(Protocol):
    """Bounded Cosign operations used by the verification boundary."""

    def check_version(self) -> str:
        raise NotImplementedError

    def verify_blob(
        self,
        blob: Path,
        *,
        bundle: Path,
        certificate_identity: str,
        workflow_ref: str,
        workflow_sha: str,
        repository: str,
    ) -> None:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class BundleIdentity:
    """Stable facts independently decoded from a verified Sigstore bundle."""

    certificate_sha256: str
    integrated_time: int
    log_id: str
    log_index: int
    message_signature_sha256: str
    timestamp_count: int
    tree_size: int


def _bounded_string(value: object, source: str, *, maximum: int = MAX_STRING_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise BlobVerificationError(f"{source} must be a bounded nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise BlobVerificationError(f"{source} is not valid Unicode") from None
    if len(encoded) > maximum:
        raise BlobVerificationError(f"{source} must be a bounded nonempty string")
    return value


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise BlobVerificationError(f"{source} must contain exactly {sorted(fields)}")
    return cast(Mapping[str, Any], value)


def _canonical_decimal(value: object, source: str) -> int:
    if not isinstance(value, str) or CANONICAL_DECIMAL.fullmatch(value) is None:
        raise BlobVerificationError(f"{source} is not a canonical decimal integer")
    parsed = int(value)
    if parsed > MAX_ID:
        raise BlobVerificationError(f"{source} is outside its integer bound")
    return parsed


def _decode_base64(
    value: object,
    source: str,
    *,
    minimum: int = 1,
    maximum: int,
) -> bytes:
    encoded = _bounded_string(value, source, maximum=((maximum + 2) // 3) * 4 + 4)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BlobVerificationError(f"{source} is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise BlobVerificationError(f"{source} is not canonical base64")
    if not minimum <= len(decoded) <= maximum:
        raise BlobVerificationError(f"{source} is outside its decoded byte bound")
    return decoded


def _json_shape(value: object, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise BlobVerificationError("Sigstore JSON exceeds its depth bound")
    if isinstance(value, dict):
        return 1 + sum(
            _json_shape(key, depth + 1) + _json_shape(item, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return 1 + sum(_json_shape(item, depth + 1) for item in value)
    return 1


def _strict_json(raw: bytes, source: str, *, maximum: int) -> object:
    if not 1 <= len(raw) <= maximum:
        raise BlobVerificationError(f"{source} is outside its byte bound")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def reject_float(_value: str) -> float:
        raise ValueError("floating-point JSON is not accepted")

    def bounded_integer(value: str) -> int:
        if len(value) > 20:
            raise ValueError("JSON integer is outside its lexical bound")
        parsed = int(value)
        if not -(2**63) <= parsed <= MAX_ID:
            raise ValueError("JSON integer is outside its value bound")
        return parsed

    def reject_constant(_value: str) -> object:
        raise ValueError("non-finite JSON is not accepted")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=reject_float,
            parse_int=bounded_integer,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise BlobVerificationError(f"{source} is not strict bounded JSON") from exc
    if _json_shape(value) > MAX_JSON_ITEMS:
        raise BlobVerificationError(f"{source} exceeds its item bound")
    return value


def _rekor_canonical_json(value: object) -> bytes:
    """Encode Rekor's compact canonical JSON without a record newline."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise BlobVerificationError(
            "Sigstore transparency-log body cannot be canonicalized"
        ) from exc


def _read_retained_file(
    retained: actions_provenance.RetainedAsset,
    asset: Asset,
    *,
    maximum: int,
    source: str,
) -> bytes:
    if asset.size > maximum:
        raise BlobVerificationError(f"{source} is outside its byte bound")
    chunks: list[bytes] = []
    position = 0
    remaining = asset.size
    try:
        while remaining:
            chunk = os.pread(retained.descriptor, min(READ_CHUNK_BYTES, remaining), position)
            if not chunk:
                raise BlobVerificationError(f"{source} was truncated")
            chunks.append(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(retained.descriptor, 1, position):
            raise BlobVerificationError(f"{source} has trailing bytes")
    except OSError as exc:
        raise BlobVerificationError(f"cannot read {source}") from exc
    return b"".join(chunks)


def _der_utf8_string(value: bytes, source: str) -> str:
    if len(value) < 2 or value[0] != 0x0C:
        raise BlobVerificationError(f"{source} is not a DER UTF8String")
    first_length = value[1]
    offset = 2
    if first_length < 0x80:
        length = first_length
    else:
        count = first_length & 0x7F
        if count == 0 or count > 2 or len(value) < offset + count:
            raise BlobVerificationError(f"{source} has an invalid DER length")
        length_bytes = value[offset : offset + count]
        if length_bytes[0] == 0 or (count == 1 and length_bytes[0] < 0x80):
            raise BlobVerificationError(f"{source} has a noncanonical DER length")
        length = int.from_bytes(length_bytes, "big")
        offset += count
    encoded = value[offset:]
    if length != len(encoded) or not 1 <= length <= MAX_STRING_BYTES:
        raise BlobVerificationError(f"{source} has an invalid DER length")
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BlobVerificationError(f"{source} is not valid UTF-8") from exc


def _certificate_extension(certificate: x509.Certificate, oid: ObjectIdentifier) -> str:
    try:
        extension = certificate.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound as exc:
        raise BlobVerificationError(
            f"Fulcio certificate is missing extension {oid.dotted_string}"
        ) from exc
    if not isinstance(extension.value, x509.UnrecognizedExtension):
        raise BlobVerificationError(f"Fulcio extension {oid.dotted_string} has the wrong type")
    return _der_utf8_string(
        extension.value.value,
        f"Fulcio extension {oid.dotted_string}",
    )


def _validate_certificate(
    raw: bytes,
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
) -> x509.Certificate:
    try:
        certificate = x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise BlobVerificationError("Sigstore certificate is not valid DER X.509") from exc

    expected_ref = f"refs/tags/{plan.tag}"
    expected_identity = f"https://github.com/{plan.repository}/{plan.workflow_path}@{expected_ref}"
    expected_run = f"{workflow.url}/attempts/{workflow.run_attempt}"
    owner = plan.repository.partition("/")[0]
    expected_extensions = {
        OID_ISSUER_V2: OIDC_ISSUER,
        OID_BUILD_SIGNER_URI: expected_identity,
        OID_BUILD_SIGNER_DIGEST: plan.workflow_sha,
        OID_RUNNER_ENVIRONMENT: "github-hosted",
        OID_SOURCE_REPOSITORY_URI: f"https://github.com/{plan.repository}",
        OID_SOURCE_REPOSITORY_DIGEST: plan.target_commit,
        OID_SOURCE_REPOSITORY_REF: expected_ref,
        OID_SOURCE_REPOSITORY_ID: str(plan.repository_id),
        OID_SOURCE_REPOSITORY_OWNER_URI: f"https://github.com/{owner}",
        OID_SOURCE_REPOSITORY_OWNER_ID: str(workflow.owner_id),
        OID_BUILD_CONFIG_URI: expected_identity,
        OID_BUILD_CONFIG_DIGEST: plan.workflow_sha,
        OID_BUILD_TRIGGER: "push",
        OID_RUN_INVOCATION_URI: expected_run,
        OID_SOURCE_REPOSITORY_VISIBILITY: "public",
        OID_TOKEN_SUBJECT: f"repo:{plan.repository}:ref:{expected_ref}",
    }
    for oid, expected in expected_extensions.items():
        if _certificate_extension(certificate, oid) != expected:
            raise BlobVerificationError(
                f"Fulcio certificate extension {oid.dotted_string} does not match the release"
            )
    try:
        certificate.extensions.get_extension_for_oid(OID_DEPLOYMENT_ENVIRONMENT)
    except x509.ExtensionNotFound:
        pass
    else:
        raise BlobVerificationError(
            "Fulcio certificate unexpectedly names a deployment environment"
        )

    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound as exc:
        raise BlobVerificationError("Fulcio certificate has no subject alternative name") from exc
    if not isinstance(san, x509.SubjectAlternativeName):
        raise BlobVerificationError("Fulcio certificate has an invalid subject alternative name")
    names = list(san)
    if (
        len(names) != 1
        or not isinstance(names[0], x509.UniformResourceIdentifier)
        or names[0].value != expected_identity
    ):
        raise BlobVerificationError("Fulcio certificate has a different signer identity")

    try:
        basic = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        key_usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        extended = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound as exc:
        raise BlobVerificationError(
            "Fulcio certificate lacks a required signing constraint"
        ) from exc
    if (
        not isinstance(basic, x509.BasicConstraints)
        or basic.ca
        or not isinstance(key_usage, x509.KeyUsage)
        or not key_usage.digital_signature
        or key_usage.key_cert_sign
        or not isinstance(extended, x509.ExtendedKeyUsage)
        or set(extended) != {ExtendedKeyUsageOID.CODE_SIGNING}
    ):
        raise BlobVerificationError("Fulcio certificate has invalid signing constraints")
    return certificate


def _validate_timestamp_material(value: object) -> int:
    material = _exact_mapping(
        value,
        {"rfc3161Timestamps"},
        "Sigstore timestamp verification data",
    )
    timestamps = material["rfc3161Timestamps"]
    if not isinstance(timestamps, list) or not 1 <= len(timestamps) <= MAX_TIMESTAMP_COUNT:
        raise BlobVerificationError("Sigstore bundle has an invalid timestamp count")
    for index, item in enumerate(timestamps):
        timestamp = _exact_mapping(
            item,
            {"signedTimestamp"},
            f"Sigstore timestamp {index}",
        )
        _decode_base64(
            timestamp["signedTimestamp"],
            f"Sigstore timestamp {index}",
            maximum=MAX_TLOG_BODY_BYTES,
        )
    return len(timestamps)


def _validate_tlog_entry(
    value: object,
    *,
    asset: Asset,
    certificate: x509.Certificate,
    message_signature: str,
) -> tuple[int, int, int, str]:
    entry = _exact_mapping(
        value,
        {
            "canonicalizedBody",
            "inclusionPromise",
            "inclusionProof",
            "integratedTime",
            "kindVersion",
            "logId",
            "logIndex",
        },
        "Sigstore transparency-log entry",
    )
    log_index = _canonical_decimal(entry["logIndex"], "Sigstore global log index")
    integrated_time = _canonical_decimal(entry["integratedTime"], "Sigstore integrated time")
    kind = _exact_mapping(
        entry["kindVersion"],
        {"kind", "version"},
        "Sigstore transparency-log kind",
    )
    if kind != {"kind": "hashedrekord", "version": "0.0.1"}:
        raise BlobVerificationError("Sigstore bundle does not contain a hashedrekord v0.0.1 entry")
    log_id = _exact_mapping(entry["logId"], {"keyId"}, "Sigstore transparency-log ID")
    _decode_base64(
        log_id["keyId"],
        "Sigstore transparency-log key ID",
        minimum=32,
        maximum=32,
    )
    promise = _exact_mapping(
        entry["inclusionPromise"],
        {"signedEntryTimestamp"},
        "Sigstore inclusion promise",
    )
    _decode_base64(
        promise["signedEntryTimestamp"],
        "Sigstore signed-entry timestamp",
        maximum=MAX_SIGNATURE_BYTES,
    )
    proof = _exact_mapping(
        entry["inclusionProof"],
        {"checkpoint", "hashes", "logIndex", "rootHash", "treeSize"},
        "Sigstore inclusion proof",
    )
    tree_index = _canonical_decimal(proof["logIndex"], "Sigstore tree log index")
    tree_size = _canonical_decimal(proof["treeSize"], "Sigstore tree size")
    if not tree_size or tree_index >= tree_size:
        raise BlobVerificationError("Sigstore inclusion proof has invalid tree bounds")
    _decode_base64(
        proof["rootHash"],
        "Sigstore inclusion root hash",
        minimum=32,
        maximum=32,
    )
    hashes = proof["hashes"]
    if not isinstance(hashes, list) or len(hashes) > MAX_TLOG_PROOF_HASHES:
        raise BlobVerificationError("Sigstore inclusion proof has an invalid hash count")
    for index, item in enumerate(hashes):
        _decode_base64(
            item,
            f"Sigstore inclusion hash {index}",
            minimum=32,
            maximum=32,
        )
    checkpoint = _exact_mapping(
        proof["checkpoint"],
        {"envelope"},
        "Sigstore transparency-log checkpoint",
    )
    _bounded_string(
        checkpoint["envelope"],
        "Sigstore transparency-log checkpoint",
        maximum=MAX_TLOG_BODY_BYTES,
    )

    body_bytes = _decode_base64(
        entry["canonicalizedBody"],
        "Sigstore canonicalized transparency-log body",
        maximum=MAX_TLOG_BODY_BYTES,
    )
    body_value = _strict_json(
        body_bytes,
        "Sigstore canonicalized transparency-log body",
        maximum=MAX_TLOG_BODY_BYTES,
    )
    if _rekor_canonical_json(body_value) != body_bytes:
        raise BlobVerificationError("Sigstore transparency-log body is not canonical JSON")
    body = _exact_mapping(
        body_value,
        {"apiVersion", "kind", "spec"},
        "Sigstore transparency-log body",
    )
    if body["apiVersion"] != "0.0.1" or body["kind"] != "hashedrekord":
        raise BlobVerificationError("Sigstore transparency-log body has the wrong type")
    spec = _exact_mapping(
        body["spec"],
        {"data", "signature"},
        "Sigstore transparency-log specification",
    )
    data = _exact_mapping(spec["data"], {"hash"}, "Sigstore transparency-log data")
    digest = _exact_mapping(
        data["hash"],
        {"algorithm", "value"},
        "Sigstore transparency-log hash",
    )
    if digest != {"algorithm": "sha256", "value": asset.sha256}:
        raise BlobVerificationError("Sigstore transparency-log body names different blob bytes")
    signature = _exact_mapping(
        spec["signature"],
        {"content", "publicKey"},
        "Sigstore transparency-log signature",
    )
    if signature["content"] != message_signature:
        raise BlobVerificationError("Sigstore transparency-log body contains a different signature")
    public_key = _exact_mapping(
        signature["publicKey"],
        {"content"},
        "Sigstore transparency-log public key",
    )
    expected_pem = certificate.public_bytes(serialization.Encoding.PEM)
    expected_pem_base64 = base64.b64encode(expected_pem).decode("ascii")
    if public_key["content"] != expected_pem_base64:
        raise BlobVerificationError(
            "Sigstore transparency-log body contains a different certificate"
        )

    try:
        integrated = dt.datetime.fromtimestamp(integrated_time, tz=dt.UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise BlobVerificationError("Sigstore integrated time is outside its time bound") from exc
    if not certificate.not_valid_before_utc <= integrated <= certificate.not_valid_after_utc:
        raise BlobVerificationError(
            "Sigstore integrated time is outside the certificate validity interval"
        )
    return log_index, integrated_time, tree_size, cast(str, log_id["keyId"])


def validate_bundle(
    raw: bytes,
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
    asset: Asset,
) -> BundleIdentity:
    """Decode and bind one Cosign v3 message-signature bundle."""

    value = _strict_json(raw, "Sigstore bundle", maximum=MAX_BUNDLE_BYTES)
    bundle = _exact_mapping(
        value,
        {"mediaType", "messageSignature", "verificationMaterial"},
        "Sigstore bundle",
    )
    if bundle["mediaType"] != SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise BlobVerificationError("Sigstore bundle has an unsupported media type")
    message = _exact_mapping(
        bundle["messageSignature"],
        {"messageDigest", "signature"},
        "Sigstore message signature",
    )
    digest = _exact_mapping(
        message["messageDigest"],
        {"algorithm", "digest"},
        "Sigstore message digest",
    )
    digest_bytes = _decode_base64(
        digest["digest"],
        "Sigstore message digest",
        minimum=32,
        maximum=32,
    )
    if digest["algorithm"] != "SHA2_256" or digest_bytes.hex() != asset.sha256:
        raise BlobVerificationError("Sigstore message signature names different blob bytes")
    message_signature = _bounded_string(
        message["signature"],
        "Sigstore message signature",
        maximum=((MAX_SIGNATURE_BYTES + 2) // 3) * 4 + 4,
    )
    signature_bytes = _decode_base64(
        message_signature,
        "Sigstore message signature",
        maximum=MAX_SIGNATURE_BYTES,
    )

    material_value = bundle["verificationMaterial"]
    if not isinstance(material_value, dict) or set(material_value) not in (
        {"certificate", "tlogEntries"},
        {"certificate", "timestampVerificationData", "tlogEntries"},
    ):
        raise BlobVerificationError("Sigstore verification material has unsupported fields")
    material = cast(Mapping[str, Any], material_value)
    certificate_record = _exact_mapping(
        material["certificate"],
        {"rawBytes"},
        "Sigstore certificate",
    )
    certificate_der = _decode_base64(
        certificate_record["rawBytes"],
        "Sigstore certificate",
        maximum=MAX_CERTIFICATE_BYTES,
    )
    certificate = _validate_certificate(certificate_der, plan, workflow)
    timestamps = (
        _validate_timestamp_material(material["timestampVerificationData"])
        if "timestampVerificationData" in material
        else 0
    )
    entries = material["tlogEntries"]
    if not isinstance(entries, list) or len(entries) != 1:
        raise BlobVerificationError(
            "Sigstore bundle must contain exactly one transparency-log entry"
        )
    log_index, integrated_time, tree_size, log_id = _validate_tlog_entry(
        entries[0],
        asset=asset,
        certificate=certificate,
        message_signature=message_signature,
    )
    return BundleIdentity(
        certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
        integrated_time=integrated_time,
        log_id=log_id,
        log_index=log_index,
        message_signature_sha256=hashlib.sha256(signature_bytes).hexdigest(),
        timestamp_count=timestamps,
        tree_size=tree_size,
    )


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run_bounded(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout: float,
    maximum_stdout: int,
) -> bytes:
    try:
        process = subprocess.Popen(  # noqa: S603 - executable was resolved and inspected
            tuple(command),
            close_fds=True,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise BlobVerificationError("cannot start Cosign") from exc
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise BlobVerificationError("cannot capture Cosign output")

    output = bytearray()
    errors = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise BlobVerificationError("Cosign command timed out")
            for key, _events in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fd, READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                retained = output if key.data == "stdout" else errors
                maximum = maximum_stdout if key.data == "stdout" else MAX_COMMAND_ERROR_BYTES
                if len(retained) + len(chunk) > maximum:
                    _stop_process(process)
                    stream = "output" if key.data == "stdout" else "diagnostics"
                    raise BlobVerificationError(f"Cosign {stream} exceeds its byte bound")
                retained.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise BlobVerificationError("Cosign command timed out")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _stop_process(process)
            raise BlobVerificationError("Cosign command timed out") from None
    except OSError as exc:
        _stop_process(process)
        raise BlobVerificationError("cannot read Cosign output") from exc
    except BaseException:
        if process.poll() is None:
            _stop_process(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if return_code != 0:
        raise BlobVerificationError(f"Cosign command failed with exit status {return_code}")
    return bytes(output)


def _cosign_environment(source: Mapping[str, str], home: Path) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "TERM": "dumb",
        "XDG_CACHE_HOME": str(home / ".cache"),
    }
    for key in (
        "HTTPS_PROXY",
        "NO_PROXY",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "https_proxy",
        "no_proxy",
    ):
        if value := source.get(key):
            environment[key] = value
    return environment


def _validate_cosign_home(path: Path) -> Path:
    if not path.is_absolute():
        raise BlobVerificationError("Cosign home must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BlobVerificationError("cannot inspect Cosign home") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise BlobVerificationError("Cosign home must be one verifier-owned mode-0700 directory")
    return Path(os.path.abspath(path))


class CosignCLI:
    """Bounded access to a patched Cosign verifier."""

    __slots__ = ("_environment", "_executable", "_home", "_timeout")

    def __init__(
        self,
        *,
        home: Path,
        executable: str = "cosign",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < float(timeout) <= MAX_TIMEOUT_SECONDS
        ):
            raise BlobVerificationError("Cosign timeout is outside its bounds")
        resolved = shutil.which(executable)
        if resolved is None:
            raise BlobVerificationError("cannot find the Cosign executable")
        try:
            metadata = os.stat(resolved)
        except OSError as exc:
            raise BlobVerificationError("cannot inspect the Cosign executable") from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise BlobVerificationError("Cosign executable is not an executable regular file")
        self._executable = resolved
        self._home = _validate_cosign_home(home)
        self._timeout = float(timeout)
        self._environment = _cosign_environment(
            dict(os.environ if environment is None else environment),
            self._home,
        )

    def _run(self, arguments: Sequence[str], *, maximum_stdout: int) -> bytes:
        return _run_bounded(
            (self._executable, *arguments),
            environment=self._environment,
            timeout=self._timeout,
            maximum_stdout=maximum_stdout,
        )

    def check_version(self) -> str:
        raw = self._run(("version", "--json"), maximum_stdout=MAX_VERSION_OUTPUT_BYTES)
        value = _strict_json(raw, "Cosign version response", maximum=MAX_VERSION_OUTPUT_BYTES)
        record = _exact_mapping(
            value,
            {
                "buildDate",
                "compiler",
                "gitCommit",
                "gitTreeState",
                "gitVersion",
                "goVersion",
                "platform",
            },
            "Cosign version response",
        )
        version_text = _bounded_string(record["gitVersion"], "Cosign version", maximum=64)
        match = COSIGN_VERSION.fullmatch(version_text)
        if match is None:
            raise BlobVerificationError("Cosign returned an invalid version")
        version = tuple(int(part) for part in match.groups())
        if version < MINIMUM_COSIGN_VERSION or version[0] > MAX_COSIGN_MAJOR_VERSION:
            raise BlobVerificationError(
                f"Cosign {MINIMUM_COSIGN_VERSION_TEXT} through major version "
                f"{MAX_COSIGN_MAJOR_VERSION} is required"
            )
        if (
            not isinstance(record["gitCommit"], str)
            or HEX40.fullmatch(record["gitCommit"]) is None
            or record["gitTreeState"] != "clean"
            or not isinstance(record["goVersion"], str)
            or GO_VERSION.fullmatch(record["goVersion"]) is None
            or record["compiler"] != "gc"
            or not isinstance(record["platform"], str)
            or PLATFORM.fullmatch(record["platform"]) is None
            or not isinstance(record["buildDate"], str)
            or RFC3339_UTC.fullmatch(record["buildDate"]) is None
        ):
            raise BlobVerificationError("Cosign returned an untrusted build identity")
        return ".".join(match.groups())

    def verify_blob(
        self,
        blob: Path,
        *,
        bundle: Path,
        certificate_identity: str,
        workflow_ref: str,
        workflow_sha: str,
        repository: str,
    ) -> None:
        if not blob.is_absolute() or not bundle.is_absolute():
            raise BlobVerificationError("Cosign inputs must use absolute paths")
        output = self._run(
            (
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                OIDC_ISSUER,
                "--certificate-github-workflow-trigger",
                "push",
                "--certificate-github-workflow-sha",
                workflow_sha,
                "--certificate-github-workflow-repository",
                repository,
                "--certificate-github-workflow-ref",
                workflow_ref,
                "--max-workers",
                "1",
                str(blob),
            ),
            maximum_stdout=MAX_COMMAND_OUTPUT_BYTES,
        )
        if output != b"Verified OK\n":
            raise BlobVerificationError("Cosign returned an unexpected success response")


def _select_asset(
    acquired: actions_provenance.AcquiredAssets,
    name: str,
    source: str,
) -> tuple[Asset, int]:
    selected = [(asset, asset_id) for asset, asset_id in acquired.assets if asset.name == name]
    if len(selected) != 1:
        raise BlobVerificationError(f"{source} is not named exactly once by the acquisition record")
    return selected[0]


def _asset_record(asset: Asset, asset_id: int) -> Mapping[str, object]:
    return {
        "github_asset_id": asset_id,
        "name": asset.name,
        "path": asset.name,
        "sha256": asset.sha256,
        "size": asset.size,
    }


def verify_blob_signature(
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
    acquired: actions_provenance.AcquiredAssets,
    *,
    expected_manifest_sha256: str,
    asset_root: Path,
    asset_name: str,
    client: CosignClient,
) -> Mapping[str, object]:
    """Verify one acquired blob against its exact keyless Sigstore bundle."""

    actions_provenance._digest(expected_manifest_sha256, "trusted manifest SHA-256")
    if plan.manifest_sha256 != expected_manifest_sha256:
        raise BlobVerificationError("release manifest does not match the trusted SHA-256")
    if plan.workflow_sha != plan.target_commit:
        raise BlobVerificationError("release workflow SHA does not match the tagged target commit")
    if workflow.authenticated_release_sha256 != acquired.authenticated_release_sha256:
        raise BlobVerificationError(
            "workflow and acquisition records name different authenticated releases"
        )
    if workflow.owner_id != acquired.owner_id:
        raise BlobVerificationError(
            "workflow and acquisition records name different repository owners"
        )
    asset, asset_id = _select_asset(acquired, asset_name, "selected asset")
    bundle_name = f"{asset.name}.sigstore.json"
    if len(bundle_name.encode("utf-8")) > 255:
        raise BlobVerificationError("derived Sigstore bundle name is outside its byte bound")
    bundle, bundle_id = _select_asset(acquired, bundle_name, "derived Sigstore bundle")

    retained_asset = actions_provenance._open_retained_asset(asset_root, plan, asset)
    retained_bundle: actions_provenance.RetainedAsset | None = None
    try:
        retained_bundle = actions_provenance._open_retained_asset(asset_root, plan, bundle)
        bundle_raw = _read_retained_file(
            retained_bundle,
            bundle,
            maximum=MAX_BUNDLE_BYTES,
            source="Sigstore bundle",
        )
        bundle_identity = validate_bundle(bundle_raw, plan, workflow, asset)
        version = client.check_version()
        expected_ref = f"refs/tags/{plan.tag}"
        signer_identity = (
            f"https://github.com/{plan.repository}/{plan.workflow_path}@{expected_ref}"
        )
        client.verify_blob(
            asset_root / asset.name,
            bundle=asset_root / bundle.name,
            certificate_identity=signer_identity,
            workflow_ref=expected_ref,
            workflow_sha=plan.workflow_sha,
            repository=plan.repository,
        )
        actions_provenance._require_retained_asset(retained_asset, asset_root, asset)
        actions_provenance._require_retained_asset(retained_bundle, asset_root, bundle)
    finally:
        for retained in (retained_asset, retained_bundle):
            if retained is None:
                continue
            with contextlib.suppress(OSError):
                os.close(retained.descriptor)
            with contextlib.suppress(OSError):
                os.close(retained.root_descriptor)

    return {
        "acquired_assets": {"sha256": acquired.record_sha256},
        "asset": _asset_record(asset, asset_id),
        "authenticated_release": {"sha256": acquired.authenticated_release_sha256},
        "authenticated_workflow": {"sha256": workflow.record_sha256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "cosign": {
            "maximum_major_version": MAX_COSIGN_MAJOR_VERSION,
            "minimum_version": MINIMUM_COSIGN_VERSION_TEXT,
            "version": version,
        },
        "kind": RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": plan.repository_id,
            "name": plan.repository,
            "owner_id": workflow.owner_id,
        },
        "schema_version": SCHEMA_VERSION,
        "signature_bundle": {
            **_asset_record(bundle, bundle_id),
            "certificate_sha256": bundle_identity.certificate_sha256,
            "integrated_time": bundle_identity.integrated_time,
            "log_id": bundle_identity.log_id,
            "log_index": bundle_identity.log_index,
            "media_type": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "message_signature_sha256": bundle_identity.message_signature_sha256,
            "timestamp_count": bundle_identity.timestamp_count,
            "transparency_log_entry_count": 1,
            "tree_size": bundle_identity.tree_size,
        },
        "tag": {"name": plan.tag, "target_commit": plan.target_commit},
        "workflow": {
            "file_sha256": workflow.file_sha256,
            "id": workflow.workflow_id,
            "path": plan.workflow_path,
            "ref": f"refs/tags/{plan.tag}",
            "run_attempt": workflow.run_attempt,
            "run_id": plan.run_id,
            "sha": plan.workflow_sha,
            "signer_identity": (
                f"https://github.com/{plan.repository}/{plan.workflow_path}@refs/tags/{plan.tag}"
            ),
            "url": workflow.url,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify one acquired release asset and its exact Sigstore bundle."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authenticated-workflow-record", type=Path, required=True)
    parser.add_argument("--authenticated-workflow-record-sha256", required=True)
    parser.add_argument("--acquisition-record", type=Path, required=True)
    parser.add_argument("--acquisition-record-sha256", required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--asset-name", required=True)
    parser.add_argument("--cosign-home", type=Path, required=True)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        try:
            plan = load_manifest(arguments.manifest)
        except ControllerError as exc:
            raise BlobVerificationError("release-controller manifest is invalid") from exc
        workflow = actions_provenance.load_authenticated_workflow(
            arguments.authenticated_workflow_record,
            expected_sha256=arguments.authenticated_workflow_record_sha256,
            plan=plan,
        )
        acquired = actions_provenance.load_acquired_assets(
            arguments.acquisition_record,
            expected_sha256=arguments.acquisition_record_sha256,
            plan=plan,
        )
        client = CosignCLI(
            executable=arguments.cosign,
            home=arguments.cosign_home,
            timeout=arguments.timeout_seconds,
        )
        result = verify_blob_signature(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256=arguments.manifest_sha256,
            asset_root=arguments.asset_root,
            asset_name=arguments.asset_name,
            client=client,
        )
        sys.stdout.buffer.write(canonical_json(result))
    except (
        BlobVerificationError,
        actions_provenance.ProvenanceVerificationError,
        github_release.VerificationError,
    ) as exc:
        sys.stderr.write(f"Blob-signature verification failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
