#!/usr/bin/env python3
"""Acquire and authenticate one exact GHCR OCI index without selecting platforms."""

from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import datetime as dt
import hashlib
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from http.client import HTTPMessage
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import acquire_github_release_assets as github_acquisition  # noqa: E402
import verify_actions_build_provenance as actions_provenance  # noqa: E402
import verify_blob_signature as blob_signature  # noqa: E402
import verify_github_release as github_release  # noqa: E402
from release_controller import (  # noqa: E402
    SAFE_SEGMENT,
    Asset,
    ControllerError,
    ReleasePlan,
    canonical_json,
    load_manifest,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/authenticated-oci-index"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
COSIGN_SIGNATURE_PREDICATE_TYPE = "https://sigstore.dev/cosign/sign/v1"
GHCR_HOST = "ghcr.io"
INDEX_NAME = "index.json"
SIGNATURE_NAME = "signature.sigstore.json"
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_SIGNATURE_DOWNLOAD_BYTES = 16 * 1024 * 1024
MAX_SIGNATURE_BUNDLES = 32
MAX_INDEX_DESCRIPTORS = 128
MAX_REGISTRY_TIMEOUT_SECONDS = 120.0
DEFAULT_REGISTRY_TIMEOUT_SECONDS = 30.0
READ_CHUNK_BYTES = 64 * 1024

DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
CONTENT_LENGTH = re.compile(r"^(?:0|[1-9][0-9]{0,7})$")
BEARER_TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]+$")


class OCIIndexError(RuntimeError):
    """The exact OCI index or its keyless signature could not be authenticated."""


@dataclasses.dataclass(frozen=True)
class FetchedIndex:
    """One digest-addressed registry response retained in memory."""

    raw: bytes
    manifest_url: str
    token_url: str


@dataclasses.dataclass(frozen=True)
class SignatureIdentity:
    """Stable facts decoded from one locally verified OCI signature bundle."""

    bundle_sha256: str
    certificate_sha256: str
    envelope_sha256: str
    integrated_time: int
    log_id: str
    log_index: int
    payload_sha256: str
    signature_sha256: str
    timestamp_count: int
    tree_size: int


class RegistryClient(Protocol):
    """Read-only registry operation used by the acquisition boundary."""

    def fetch_index(self, repository: str, digest: str) -> FetchedIndex:
        raise NotImplementedError


class CosignClient(Protocol):
    """Bounded Cosign operations used by the acquisition boundary."""

    def check_version(self) -> str:
        raise NotImplementedError

    def download_signatures(self, reference: str) -> bytes:
        raise NotImplementedError

    def verify_bundle(
        self,
        bundle: Path,
        *,
        digest_hex: str,
        certificate_identity: str,
        workflow_ref: str,
        workflow_sha: str,
        repository: str,
    ) -> None:
        raise NotImplementedError


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep bearer credentials from crossing an unreviewed redirect boundary."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _media_type(value: str | None, source: str) -> str:
    if value is None or len(value) > 256:
        raise OCIIndexError(f"{source} has no bounded Content-Type")
    media_type = value.partition(";")[0].strip().lower()
    if not media_type:
        raise OCIIndexError(f"{source} has no bounded Content-Type")
    return media_type


def _header(
    headers: Any,
    name: str,
    source: str,
    *,
    required: bool = True,
) -> str | None:
    get_all = getattr(headers, "get_all", None)
    values = get_all(name) if callable(get_all) else None
    if values is None:
        value = headers.get(name)
        values = [] if value is None else [value]
    if len(values) > 1:
        raise OCIIndexError(f"{source} returned an ambiguous {name} header")
    if not values:
        if required:
            raise OCIIndexError(f"{source} did not return a {name} header")
        return None
    value = values[0]
    if not isinstance(value, str) or len(value) > 4096:
        raise OCIIndexError(f"{source} returned an invalid {name} header")
    return value


def _read_response(response: Any, *, maximum: int, source: str) -> bytes:
    try:
        raw = response.read(maximum + 1)
    except OSError as exc:
        raise OCIIndexError(f"cannot read {source}") from exc
    if not 1 <= len(raw) <= maximum:
        raise OCIIndexError(f"{source} is outside its byte bound")
    return cast(bytes, raw)


class GHCRClient:
    """Anonymous, no-redirect GHCR client for one exact manifest digest."""

    __slots__ = ("_opener", "_timeout")

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_REGISTRY_TIMEOUT_SECONDS,
        opener: Any | None = None,
    ) -> None:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < float(timeout) <= MAX_REGISTRY_TIMEOUT_SECONDS
        ):
            raise OCIIndexError("registry timeout is outside its bounds")
        self._timeout = float(timeout)
        self._opener = urllib.request.build_opener(_RejectRedirects()) if opener is None else opener

    def _open(self, request: urllib.request.Request, source: str) -> Any:
        try:
            return self._opener.open(request, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise OCIIndexError(f"{source} attempted an untrusted redirect") from exc
            raise OCIIndexError(f"{source} failed with HTTP status {exc.code}") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise OCIIndexError(f"cannot request {source}") from exc

    def fetch_index(self, repository: str, digest: str) -> FetchedIndex:
        _digest(digest, "requested OCI index digest")
        if repository != repository.lower():
            raise OCIIndexError("GHCR repository must be lowercase")
        if not repository or len(repository) > 255:
            raise OCIIndexError("GHCR repository is outside its byte bound")
        expected_scope = f"repository:{repository}:pull"
        token_url = "https://ghcr.io/token?" + urllib.parse.urlencode(
            {"service": GHCR_HOST, "scope": expected_scope}
        )
        token_request = urllib.request.Request(  # noqa: S310 - literal HTTPS GHCR endpoint
            token_url,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            method="GET",
        )
        token_response = self._open(token_request, "GHCR token endpoint")
        try:
            if token_response.status != 200 or token_response.geturl() != token_url:
                raise OCIIndexError("GHCR token endpoint returned an unexpected response")
            if (
                _media_type(
                    _header(
                        token_response.headers,
                        "Content-Type",
                        "GHCR token endpoint",
                    ),
                    "GHCR token endpoint",
                )
                != "application/json"
            ):
                raise OCIIndexError("GHCR token endpoint returned the wrong media type")
            token_raw = _read_response(
                token_response,
                maximum=MAX_TOKEN_RESPONSE_BYTES,
                source="GHCR token response",
            )
        finally:
            token_response.close()
        try:
            token_value = blob_signature._strict_json(
                token_raw,
                "GHCR token response",
                maximum=MAX_TOKEN_RESPONSE_BYTES,
            )
            token_record = blob_signature._exact_mapping(
                token_value,
                {"token"},
                "GHCR token response",
            )
            token = blob_signature._bounded_string(
                token_record["token"],
                "GHCR bearer token",
                maximum=MAX_TOKEN_BYTES,
            )
            if BEARER_TOKEN.fullmatch(token) is None:
                raise OCIIndexError("GHCR bearer token has invalid characters")
        except blob_signature.BlobVerificationError as exc:
            raise OCIIndexError("GHCR token response is invalid") from exc

        manifest_url = (
            f"https://{GHCR_HOST}/v2/{repository}/manifests/{urllib.parse.quote(digest, safe=':')}"
        )
        manifest_request = urllib.request.Request(  # noqa: S310 - literal HTTPS GHCR endpoint
            manifest_url,
            headers={
                "Accept": OCI_INDEX_MEDIA_TYPE,
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {token}",
            },
            method="GET",
        )
        manifest_response = self._open(manifest_request, "GHCR manifest endpoint")
        try:
            if manifest_response.status != 200 or manifest_response.geturl() != manifest_url:
                raise OCIIndexError("GHCR manifest endpoint returned an unexpected response")
            if (
                _media_type(
                    _header(
                        manifest_response.headers,
                        "Content-Type",
                        "GHCR manifest endpoint",
                    ),
                    "GHCR manifest endpoint",
                )
                != OCI_INDEX_MEDIA_TYPE
            ):
                raise OCIIndexError("GHCR manifest endpoint returned the wrong media type")
            if _header(
                manifest_response.headers,
                "Content-Encoding",
                "GHCR manifest endpoint",
                required=False,
            ) not in (None, "identity"):
                raise OCIIndexError("GHCR manifest endpoint returned encoded bytes")
            response_digest = _header(
                manifest_response.headers,
                "Docker-Content-Digest",
                "GHCR manifest endpoint",
            )
            if response_digest != digest:
                raise OCIIndexError("GHCR manifest response names a different digest")
            length_text = _header(
                manifest_response.headers,
                "Content-Length",
                "GHCR manifest endpoint",
            )
            if length_text is None or CONTENT_LENGTH.fullmatch(length_text) is None:
                raise OCIIndexError("GHCR manifest response has an invalid Content-Length")
            expected_length = int(length_text)
            if not 1 <= expected_length <= MAX_INDEX_BYTES:
                raise OCIIndexError("GHCR manifest response is outside its byte bound")
            raw = _read_response(
                manifest_response,
                maximum=MAX_INDEX_BYTES,
                source="GHCR OCI index",
            )
            if len(raw) != expected_length:
                raise OCIIndexError("GHCR manifest response has the wrong byte length")
        finally:
            manifest_response.close()
        if hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
            raise OCIIndexError("GHCR returned bytes that do not match the requested digest")
        return FetchedIndex(raw=raw, manifest_url=manifest_url, token_url=token_url)


class CosignCLI(blob_signature.CosignCLI):
    """Bounded Cosign access for registry download and local bundle verification."""

    def download_signatures(self, reference: str) -> bytes:
        return self._run(
            ("download", "signature", reference),
            maximum_stdout=MAX_SIGNATURE_DOWNLOAD_BYTES,
        )

    def verify_bundle(
        self,
        bundle: Path,
        *,
        digest_hex: str,
        certificate_identity: str,
        workflow_ref: str,
        workflow_sha: str,
        repository: str,
    ) -> None:
        if not bundle.is_absolute():
            raise OCIIndexError("Cosign bundle input must use an absolute path")
        output = self._run(
            (
                "verify-blob-attestation",
                "--bundle",
                str(bundle),
                "--digest",
                digest_hex,
                "--digestAlg",
                "sha256",
                "--type",
                COSIGN_SIGNATURE_PREDICATE_TYPE,
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                blob_signature.OIDC_ISSUER,
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
            ),
            maximum_stdout=blob_signature.MAX_COMMAND_OUTPUT_BYTES,
        )
        if output:
            raise OCIIndexError("Cosign returned unexpected standard output")


def _digest(value: str, source: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise OCIIndexError(f"{source} must be a lowercase SHA-256 digest")
    return value


def _validate_index(raw: bytes) -> int:
    try:
        value = blob_signature._strict_json(
            raw,
            "OCI index",
            maximum=MAX_INDEX_BYTES,
        )
    except blob_signature.BlobVerificationError as exc:
        raise OCIIndexError("OCI index is not strict bounded JSON") from exc
    if not isinstance(value, dict):
        raise OCIIndexError("OCI index must be a JSON object")
    allowed = {
        "annotations",
        "artifactType",
        "manifests",
        "mediaType",
        "schemaVersion",
        "subject",
    }
    if not {"manifests", "mediaType", "schemaVersion"} <= set(value) or not set(value) <= allowed:
        raise OCIIndexError("OCI index has unsupported fields")
    if value["schemaVersion"] != 2 or value["mediaType"] != OCI_INDEX_MEDIA_TYPE:
        raise OCIIndexError("OCI index has the wrong schema or media type")
    manifests = value["manifests"]
    if not isinstance(manifests, list) or not 1 <= len(manifests) <= MAX_INDEX_DESCRIPTORS:
        raise OCIIndexError("OCI index has an invalid descriptor count")
    if any(not isinstance(item, dict) for item in manifests):
        raise OCIIndexError("OCI index contains a non-object descriptor")
    return len(manifests)


def _decode_envelope(
    raw: bytes,
) -> tuple[
    Mapping[str, Any],
    Mapping[str, Any],
    bytes,
    str,
    bytes,
]:
    try:
        value = blob_signature._strict_json(
            raw,
            "OCI signature bundle",
            maximum=blob_signature.MAX_BUNDLE_BYTES,
        )
        bundle = blob_signature._exact_mapping(
            value,
            {"dsseEnvelope", "mediaType", "verificationMaterial"},
            "OCI signature bundle",
        )
        if bundle["mediaType"] != blob_signature.SIGSTORE_BUNDLE_MEDIA_TYPE:
            raise OCIIndexError("OCI signature bundle has an unsupported media type")
        envelope = blob_signature._exact_mapping(
            bundle["dsseEnvelope"],
            {"payload", "payloadType", "signatures"},
            "OCI signature DSSE envelope",
        )
        if envelope["payloadType"] != INTOTO_PAYLOAD_TYPE:
            raise OCIIndexError("OCI signature bundle has an unsupported payload type")
        payload = blob_signature._decode_base64(
            envelope["payload"],
            "OCI signature payload",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )
        statement_value = blob_signature._strict_json(
            payload,
            "OCI signature statement",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )
        statement = blob_signature._exact_mapping(
            statement_value,
            {"_type", "predicate", "predicateType", "subject"},
            "OCI signature statement",
        )
        if statement["_type"] != INTOTO_STATEMENT_TYPE:
            raise OCIIndexError("OCI signature statement has the wrong type")
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1:
            raise OCIIndexError("OCI signature bundle must contain exactly one DSSE signature")
        signature = blob_signature._exact_mapping(
            signatures[0],
            {"sig"},
            "OCI DSSE signature",
        )
        signature_text = blob_signature._bounded_string(
            signature["sig"],
            "OCI DSSE signature",
            maximum=((blob_signature.MAX_SIGNATURE_BYTES + 2) // 3) * 4 + 4,
        )
        signature_bytes = blob_signature._decode_base64(
            signature_text,
            "OCI DSSE signature",
            maximum=blob_signature.MAX_SIGNATURE_BYTES,
        )
    except blob_signature.BlobVerificationError as exc:
        raise OCIIndexError("OCI signature bundle is invalid") from exc
    return bundle, envelope, payload, signature_text, signature_bytes


def _certificate_from_bundle(bundle: Mapping[str, Any]) -> bytes:
    try:
        material = bundle["verificationMaterial"]
        if not isinstance(material, dict):
            raise OCIIndexError("OCI signature verification material must be an object")
        certificate = blob_signature._exact_mapping(
            material.get("certificate"),
            {"rawBytes"},
            "OCI signature certificate",
        )
        return blob_signature._decode_base64(
            certificate["rawBytes"],
            "OCI signature certificate",
            maximum=blob_signature.MAX_CERTIFICATE_BYTES,
        )
    except blob_signature.BlobVerificationError as exc:
        raise OCIIndexError("OCI signature certificate is invalid") from exc


def _claims_current_run(
    certificate_der: bytes,
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
) -> bool:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        expected_ref = f"refs/tags/{plan.tag}"
        expected_identity = (
            f"https://github.com/{plan.repository}/{plan.workflow_path}@{expected_ref}"
        )
        expected_run = f"{workflow.url}/attempts/{workflow.run_attempt}"
        return (
            blob_signature._certificate_extension(
                certificate,
                blob_signature.OID_BUILD_SIGNER_URI,
            )
            == expected_identity
            and blob_signature._certificate_extension(
                certificate,
                blob_signature.OID_RUN_INVOCATION_URI,
            )
            == expected_run
        )
    except (ValueError, blob_signature.BlobVerificationError):
        return False


def _validate_dsse_tlog(
    value: object,
    *,
    certificate: x509.Certificate,
    envelope: Mapping[str, Any],
    payload: bytes,
    signature_text: str,
) -> tuple[int, int, int, str]:
    try:
        entry = blob_signature._exact_mapping(
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
            "OCI signature transparency-log entry",
        )
        log_index = blob_signature._canonical_decimal(
            entry["logIndex"],
            "OCI signature global log index",
        )
        integrated_time = blob_signature._canonical_decimal(
            entry["integratedTime"],
            "OCI signature integrated time",
        )
        kind = blob_signature._exact_mapping(
            entry["kindVersion"],
            {"kind", "version"},
            "OCI signature transparency-log kind",
        )
        if kind != {"kind": "dsse", "version": "0.0.1"}:
            raise OCIIndexError("OCI signature bundle does not contain a DSSE v0.0.1 entry")
        log_id = blob_signature._exact_mapping(
            entry["logId"],
            {"keyId"},
            "OCI signature transparency-log ID",
        )
        blob_signature._decode_base64(
            log_id["keyId"],
            "OCI signature transparency-log key ID",
            minimum=32,
            maximum=32,
        )
        promise = blob_signature._exact_mapping(
            entry["inclusionPromise"],
            {"signedEntryTimestamp"},
            "OCI signature inclusion promise",
        )
        blob_signature._decode_base64(
            promise["signedEntryTimestamp"],
            "OCI signature signed-entry timestamp",
            maximum=blob_signature.MAX_SIGNATURE_BYTES,
        )
        proof = blob_signature._exact_mapping(
            entry["inclusionProof"],
            {"checkpoint", "hashes", "logIndex", "rootHash", "treeSize"},
            "OCI signature inclusion proof",
        )
        tree_index = blob_signature._canonical_decimal(
            proof["logIndex"],
            "OCI signature tree log index",
        )
        tree_size = blob_signature._canonical_decimal(
            proof["treeSize"],
            "OCI signature tree size",
        )
        if not tree_size or tree_index >= tree_size:
            raise OCIIndexError("OCI signature inclusion proof has invalid tree bounds")
        blob_signature._decode_base64(
            proof["rootHash"],
            "OCI signature inclusion root hash",
            minimum=32,
            maximum=32,
        )
        hashes = proof["hashes"]
        if not isinstance(hashes, list) or len(hashes) > blob_signature.MAX_TLOG_PROOF_HASHES:
            raise OCIIndexError("OCI signature inclusion proof has an invalid hash count")
        for index, item in enumerate(hashes):
            blob_signature._decode_base64(
                item,
                f"OCI signature inclusion hash {index}",
                minimum=32,
                maximum=32,
            )
        checkpoint = blob_signature._exact_mapping(
            proof["checkpoint"],
            {"envelope"},
            "OCI signature transparency-log checkpoint",
        )
        blob_signature._bounded_string(
            checkpoint["envelope"],
            "OCI signature transparency-log checkpoint",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )

        body_bytes = blob_signature._decode_base64(
            entry["canonicalizedBody"],
            "OCI signature canonicalized transparency-log body",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )
        body_value = blob_signature._strict_json(
            body_bytes,
            "OCI signature canonicalized transparency-log body",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )
        if blob_signature._rekor_canonical_json(body_value) != body_bytes:
            raise OCIIndexError("OCI signature transparency-log body is not canonical JSON")
        body = blob_signature._exact_mapping(
            body_value,
            {"apiVersion", "kind", "spec"},
            "OCI signature transparency-log body",
        )
        if body["apiVersion"] != "0.0.1" or body["kind"] != "dsse":
            raise OCIIndexError("OCI signature transparency-log body has the wrong type")
        spec = blob_signature._exact_mapping(
            body["spec"],
            {"envelopeHash", "payloadHash", "signatures"},
            "OCI signature transparency-log specification",
        )
        envelope_hash = blob_signature._exact_mapping(
            spec["envelopeHash"],
            {"algorithm", "value"},
            "OCI signature envelope hash",
        )
        expected_envelope_hash = hashlib.sha256(
            blob_signature._rekor_canonical_json(envelope)
        ).hexdigest()
        if envelope_hash != {
            "algorithm": "sha256",
            "value": expected_envelope_hash,
        }:
            raise OCIIndexError("OCI transparency log names a different DSSE envelope")
        payload_hash = blob_signature._exact_mapping(
            spec["payloadHash"],
            {"algorithm", "value"},
            "OCI signature payload hash",
        )
        if payload_hash != {
            "algorithm": "sha256",
            "value": hashlib.sha256(payload).hexdigest(),
        }:
            raise OCIIndexError("OCI transparency log names a different DSSE payload")
        signatures = spec["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1:
            raise OCIIndexError("OCI transparency log has an invalid signature count")
        signature = blob_signature._exact_mapping(
            signatures[0],
            {"signature", "verifier"},
            "OCI transparency-log signature",
        )
        if signature["signature"] != signature_text:
            raise OCIIndexError("OCI transparency log contains a different signature")
        expected_pem = certificate.public_bytes(serialization.Encoding.PEM)
        if signature["verifier"] != base64.b64encode(expected_pem).decode("ascii"):
            raise OCIIndexError("OCI transparency log contains a different certificate")
    except blob_signature.BlobVerificationError as exc:
        raise OCIIndexError(f"OCI signature transparency-log entry is invalid: {exc}") from exc

    try:
        integrated = dt.datetime.fromtimestamp(integrated_time, tz=dt.UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise OCIIndexError("OCI signature integrated time is outside its time bound") from exc
    if not certificate.not_valid_before_utc <= integrated <= certificate.not_valid_after_utc:
        raise OCIIndexError(
            "OCI signature integrated time is outside the certificate validity interval"
        )
    return log_index, integrated_time, tree_size, cast(str, log_id["keyId"])


def validate_signature_bundle(
    raw: bytes,
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
    digest: str,
) -> SignatureIdentity:
    """Decode one Cosign v3 DSSE image-signature bundle and bind all identities."""

    bundle, envelope, payload, signature_text, signature_bytes = _decode_envelope(raw)
    try:
        statement_value = blob_signature._strict_json(
            payload,
            "OCI signature statement",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )
        statement = blob_signature._exact_mapping(
            statement_value,
            {"_type", "predicate", "predicateType", "subject"},
            "OCI signature statement",
        )
        if (
            statement["_type"] != INTOTO_STATEMENT_TYPE
            or statement["predicateType"] != COSIGN_SIGNATURE_PREDICATE_TYPE
            or statement["predicate"] != {}
        ):
            raise OCIIndexError("OCI bundle is not an empty Cosign signature statement")
        subjects = statement["subject"]
        if not isinstance(subjects, list) or len(subjects) != 1:
            raise OCIIndexError("OCI signature statement must contain exactly one subject")
        subject = blob_signature._exact_mapping(
            subjects[0],
            {"annotations", "digest"},
            "OCI signature subject",
        )
        subject_digest = blob_signature._exact_mapping(
            subject["digest"],
            {"sha256"},
            "OCI signature subject digest",
        )
        if subject["annotations"] != {} or subject_digest != {
            "sha256": digest.removeprefix("sha256:")
        }:
            raise OCIIndexError("OCI signature statement names a different index digest")

        certificate_der = _certificate_from_bundle(bundle)
        certificate = blob_signature._validate_certificate(certificate_der, plan, workflow)
        material_value = bundle["verificationMaterial"]
        if not isinstance(material_value, dict) or set(material_value) not in (
            {"certificate", "tlogEntries"},
            {"certificate", "timestampVerificationData", "tlogEntries"},
        ):
            raise OCIIndexError("OCI signature verification material has unsupported fields")
        material = cast(Mapping[str, Any], material_value)
        timestamp_count = (
            blob_signature._validate_timestamp_material(material["timestampVerificationData"])
            if "timestampVerificationData" in material
            else 0
        )
        entries = material["tlogEntries"]
        if not isinstance(entries, list) or len(entries) != 1:
            raise OCIIndexError(
                "OCI signature bundle must contain exactly one transparency-log entry"
            )
        log_index, integrated_time, tree_size, log_id = _validate_dsse_tlog(
            entries[0],
            certificate=certificate,
            envelope=envelope,
            payload=payload,
            signature_text=signature_text,
        )
    except blob_signature.BlobVerificationError as exc:
        raise OCIIndexError(f"OCI signature bundle is invalid: {exc}") from exc
    return SignatureIdentity(
        bundle_sha256=hashlib.sha256(raw).hexdigest(),
        certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
        envelope_sha256=hashlib.sha256(blob_signature._rekor_canonical_json(envelope)).hexdigest(),
        integrated_time=integrated_time,
        log_id=log_id,
        log_index=log_index,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        signature_sha256=hashlib.sha256(signature_bytes).hexdigest(),
        timestamp_count=timestamp_count,
        tree_size=tree_size,
    )


def _signature_lines(raw: bytes) -> tuple[bytes, ...]:
    if not raw or len(raw) > MAX_SIGNATURE_DOWNLOAD_BYTES or not raw.endswith(b"\n"):
        raise OCIIndexError("Cosign signature download is not bounded JSON Lines")
    lines = raw[:-1].split(b"\n")
    if not 1 <= len(lines) <= MAX_SIGNATURE_BUNDLES or any(not line for line in lines):
        raise OCIIndexError("Cosign signature download has an invalid bundle count")
    if any(len(line) > blob_signature.MAX_BUNDLE_BYTES for line in lines):
        raise OCIIndexError("Cosign signature bundle is outside its byte bound")
    return tuple(line + b"\n" for line in lines)


def _predicate_type(raw: bytes) -> tuple[str, Mapping[str, Any]]:
    bundle, _envelope, payload, _signature, _signature_bytes = _decode_envelope(raw)
    try:
        statement_value = blob_signature._strict_json(
            payload,
            "OCI signature statement",
            maximum=blob_signature.MAX_TLOG_BODY_BYTES,
        )
        statement = blob_signature._exact_mapping(
            statement_value,
            {"_type", "predicate", "predicateType", "subject"},
            "OCI signature statement",
        )
        predicate = blob_signature._bounded_string(
            statement["predicateType"],
            "OCI signature predicate type",
        )
    except blob_signature.BlobVerificationError as exc:
        raise OCIIndexError("OCI signature statement is invalid") from exc
    return predicate, bundle


def _select_signature(
    raw: bytes,
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
    digest: str,
) -> tuple[bytes, SignatureIdentity]:
    matches: list[tuple[bytes, SignatureIdentity]] = []
    for line in _signature_lines(raw):
        predicate, bundle = _predicate_type(line)
        if predicate != COSIGN_SIGNATURE_PREDICATE_TYPE:
            continue
        certificate_der = _certificate_from_bundle(bundle)
        if not _claims_current_run(certificate_der, plan, workflow):
            continue
        matches.append(
            (
                line,
                validate_signature_bundle(line, plan, workflow, digest),
            )
        )
    if len(matches) != 1:
        raise OCIIndexError(
            "expected exactly one signed OCI index bundle from the authenticated run"
        )
    return matches[0]


def _write_all(descriptor: int, raw: bytes, source: str) -> None:
    offset = 0
    try:
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OCIIndexError(f"cannot retain {source}")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise OCIIndexError(f"cannot retain {source}") from exc


def _asset(name: str, raw: bytes) -> Asset:
    return Asset(
        name=name,
        relative_path=name,
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def acquire_oci_index(
    plan: ReleasePlan,
    workflow: actions_provenance.AuthenticatedWorkflow,
    *,
    expected_manifest_sha256: str,
    index_digest: str,
    output_root: Path,
    registry: RegistryClient,
    cosign: CosignClient,
) -> Mapping[str, object]:
    """Acquire one root index and retain only its exact current-run signature bundle."""

    try:
        actions_provenance._digest(expected_manifest_sha256, "trusted manifest SHA-256")
    except actions_provenance.ProvenanceVerificationError as exc:
        raise OCIIndexError("trusted manifest SHA-256 is invalid") from exc
    if plan.manifest_sha256 != expected_manifest_sha256:
        raise OCIIndexError("release manifest does not match the trusted SHA-256")
    if plan.workflow_sha != plan.target_commit:
        raise OCIIndexError("release workflow SHA does not match the tagged target commit")
    digest = _digest(index_digest, "trusted OCI index digest")
    if plan.repository != plan.repository.lower():
        raise OCIIndexError("release repository must be lowercase for GHCR")
    if output_root.name in {"", ".", ".."} or SAFE_SEGMENT.fullmatch(output_root.name) is None:
        raise OCIIndexError("output directory name is unsafe")

    reference = f"{GHCR_HOST}/{plan.repository}@{digest}"
    fetched = registry.fetch_index(plan.repository, digest)
    if hashlib.sha256(fetched.raw).hexdigest() != digest.removeprefix("sha256:"):
        raise OCIIndexError("registry client returned bytes for a different index digest")
    descriptor_count = _validate_index(fetched.raw)
    version = cosign.check_version()
    downloaded = cosign.download_signatures(reference)
    selected_raw, signature_identity = _select_signature(
        downloaded,
        plan,
        workflow,
        digest,
    )

    index_asset = _asset(INDEX_NAME, fetched.raw)
    signature_asset = _asset(SIGNATURE_NAME, selected_raw)
    output_parent_path = Path(os.path.abspath(output_root.parent))
    try:
        parent = github_acquisition._open_output_parent(output_parent_path)
    except github_acquisition.AcquisitionError as exc:
        raise OCIIndexError("cannot open OCI output parent safely") from exc
    staging_name = ""
    staging = -1
    index_descriptor = -1
    signature_descriptor = -1
    promoted = False
    try:
        try:
            github_acquisition._require_absent(parent, output_root.name)
            staging_name, staging = github_acquisition._create_staging(parent)
            index_descriptor = github_acquisition._create_asset(staging, index_asset)
            _write_all(index_descriptor, fetched.raw, "OCI index")
            index_identity = github_acquisition._verify_descriptor(
                index_descriptor,
                index_asset,
            )
            signature_descriptor = github_acquisition._create_asset(
                staging,
                signature_asset,
            )
            _write_all(signature_descriptor, selected_raw, "OCI signature bundle")
            signature_file_identity = github_acquisition._verify_descriptor(
                signature_descriptor,
                signature_asset,
            )
        except github_acquisition.AcquisitionError as exc:
            raise OCIIndexError("cannot create private OCI acquisition output") from exc

        bundle_path = output_parent_path / staging_name / SIGNATURE_NAME
        expected_ref = f"refs/tags/{plan.tag}"
        signer_identity = (
            f"https://github.com/{plan.repository}/{plan.workflow_path}@{expected_ref}"
        )
        cosign.verify_bundle(
            bundle_path,
            digest_hex=digest.removeprefix("sha256:"),
            certificate_identity=signer_identity,
            workflow_ref=expected_ref,
            workflow_sha=plan.workflow_sha,
            repository=plan.repository,
        )
        try:
            if (
                github_acquisition._verify_descriptor(
                    index_descriptor,
                    index_asset,
                    expected_identity=index_identity,
                )
                != index_identity
                or github_acquisition._verify_descriptor(
                    signature_descriptor,
                    signature_asset,
                    expected_identity=signature_file_identity,
                )
                != signature_file_identity
            ):
                raise OCIIndexError("retained OCI output changed during verification")
            if github_acquisition._inventory(staging) != {INDEX_NAME, SIGNATURE_NAME}:
                raise OCIIndexError("private OCI output has an unexpected inventory")
            os.fsync(staging)
            github_acquisition._require_retained_directory(parent, staging_name, staging)
            github_acquisition._require_output_parent_unchanged(output_parent_path, parent)
            github_acquisition._require_absent(parent, output_root.name)
            github_acquisition._rename_noreplace(parent, staging_name, output_root.name)
            promoted = True
            staging_name = ""
            with contextlib.suppress(OSError):
                os.fsync(parent)
        except github_acquisition.AcquisitionError as exc:
            raise OCIIndexError(
                f"cannot atomically retain authenticated OCI output: {exc}"
            ) from exc
    finally:
        for descriptor in (index_descriptor, signature_descriptor):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
        if staging >= 0:
            if staging_name and not promoted:
                github_acquisition._remove_staging(parent, staging_name, staging)
            with contextlib.suppress(OSError):
                os.close(staging)
        with contextlib.suppress(OSError):
            os.close(parent)

    return {
        "authenticated_workflow": {"sha256": workflow.record_sha256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "cosign": {
            "maximum_major_version": blob_signature.MAX_COSIGN_MAJOR_VERSION,
            "minimum_version": blob_signature.MINIMUM_COSIGN_VERSION_TEXT,
            "version": version,
        },
        "image": {
            "digest": digest,
            "index": {
                "descriptor_count": descriptor_count,
                "media_type": OCI_INDEX_MEDIA_TYPE,
                "path": INDEX_NAME,
                "sha256": index_asset.sha256,
                "size": index_asset.size,
            },
            "reference": reference,
            "repository": f"{GHCR_HOST}/{plan.repository}",
        },
        "kind": RECORD_KIND,
        "publication_allowed": False,
        "registry": {
            "host": GHCR_HOST,
            "manifest_url": fetched.manifest_url,
            "redirects": [],
            "token_url": fetched.token_url,
        },
        "repository": {
            "id": plan.repository_id,
            "name": plan.repository,
            "owner_id": workflow.owner_id,
        },
        "schema_version": SCHEMA_VERSION,
        "signature_bundle": {
            "certificate_sha256": signature_identity.certificate_sha256,
            "envelope_sha256": signature_identity.envelope_sha256,
            "integrated_time": signature_identity.integrated_time,
            "log_id": signature_identity.log_id,
            "log_index": signature_identity.log_index,
            "media_type": blob_signature.SIGSTORE_BUNDLE_MEDIA_TYPE,
            "path": SIGNATURE_NAME,
            "payload_sha256": signature_identity.payload_sha256,
            "sha256": signature_asset.sha256,
            "signature_sha256": signature_identity.signature_sha256,
            "size": signature_asset.size,
            "timestamp_count": signature_identity.timestamp_count,
            "transparency_log_entry_count": 1,
            "tree_size": signature_identity.tree_size,
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
        description=(
            "Acquire one digest-addressed GHCR OCI index and its exact current-run signature."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authenticated-workflow-record", type=Path, required=True)
    parser.add_argument("--authenticated-workflow-record-sha256", required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cosign-home", type=Path, required=True)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument(
        "--registry-timeout-seconds",
        type=float,
        default=DEFAULT_REGISTRY_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--cosign-timeout-seconds",
        type=float,
        default=blob_signature.DEFAULT_TIMEOUT_SECONDS,
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        try:
            plan = load_manifest(arguments.manifest)
        except ControllerError as exc:
            raise OCIIndexError("release-controller manifest is invalid") from exc
        workflow = actions_provenance.load_authenticated_workflow(
            arguments.authenticated_workflow_record,
            expected_sha256=arguments.authenticated_workflow_record_sha256,
            plan=plan,
        )
        result = acquire_oci_index(
            plan,
            workflow,
            expected_manifest_sha256=arguments.manifest_sha256,
            index_digest=arguments.index_digest,
            output_root=arguments.output_dir,
            registry=GHCRClient(timeout=arguments.registry_timeout_seconds),
            cosign=CosignCLI(
                executable=arguments.cosign,
                home=arguments.cosign_home,
                timeout=arguments.cosign_timeout_seconds,
            ),
        )
        sys.stdout.buffer.write(canonical_json(result))
    except (
        OCIIndexError,
        actions_provenance.ProvenanceVerificationError,
        blob_signature.BlobVerificationError,
        github_release.VerificationError,
    ) as exc:
        sys.stderr.write(f"OCI-index acquisition failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
