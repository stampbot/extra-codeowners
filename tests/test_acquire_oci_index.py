"""Adversarial tests for digest-bound OCI index acquisition."""

from __future__ import annotations

import base64
import copy
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import sys
import urllib.error
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


controller: Any = load_script("release_controller")
workflow_verifier: Any = load_script("verify_release_workflow")
actions_provenance: Any = load_script("verify_actions_build_provenance")
blob_signature: Any = load_script("verify_blob_signature")
verifier: Any = load_script("acquire_oci_index")

REPOSITORY = "stampbot/extra-codeowners"
REPOSITORY_ID = 1_299_090_885
OWNER_ID = 1_234_567
WORKFLOW_ID = 44_556_677
RUN_ID = 12_345_678
RUN_ATTEMPT = 2
TAG = "v0.1.0"
COMMIT = "a" * 40
WORKFLOW_PATH = ".github/workflows/release.yml"
WORKFLOW_FILE_SHA256 = "b" * 64
INTEGRATED_TIME = 1_788_000_000


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def signer_identity() -> str:
    return f"https://github.com/{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/{TAG}"


def run_invocation(attempt: int = RUN_ATTEMPT) -> str:
    return f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{attempt}"


def der_utf8(value: str) -> bytes:
    encoded = value.encode()
    if len(encoded) < 128:
        return b"\x0c" + bytes([len(encoded)]) + encoded
    return b"\x0c\x81" + bytes([len(encoded)]) + encoded


def expected_extensions(*, attempt: int = RUN_ATTEMPT) -> dict[ObjectIdentifier, str]:
    owner = REPOSITORY.partition("/")[0]
    ref = f"refs/tags/{TAG}"
    return {
        blob_signature.OID_ISSUER_V2: blob_signature.OIDC_ISSUER,
        blob_signature.OID_BUILD_SIGNER_URI: signer_identity(),
        blob_signature.OID_BUILD_SIGNER_DIGEST: COMMIT,
        blob_signature.OID_RUNNER_ENVIRONMENT: "github-hosted",
        blob_signature.OID_SOURCE_REPOSITORY_URI: f"https://github.com/{REPOSITORY}",
        blob_signature.OID_SOURCE_REPOSITORY_DIGEST: COMMIT,
        blob_signature.OID_SOURCE_REPOSITORY_REF: ref,
        blob_signature.OID_SOURCE_REPOSITORY_ID: str(REPOSITORY_ID),
        blob_signature.OID_SOURCE_REPOSITORY_OWNER_URI: f"https://github.com/{owner}",
        blob_signature.OID_SOURCE_REPOSITORY_OWNER_ID: str(OWNER_ID),
        blob_signature.OID_BUILD_CONFIG_URI: signer_identity(),
        blob_signature.OID_BUILD_CONFIG_DIGEST: COMMIT,
        blob_signature.OID_BUILD_TRIGGER: "push",
        blob_signature.OID_RUN_INVOCATION_URI: run_invocation(attempt),
        blob_signature.OID_SOURCE_REPOSITORY_VISIBILITY: "public",
        blob_signature.OID_TOKEN_SUBJECT: f"repo:{REPOSITORY}:ref:{ref}",
    }


def certificate_der(
    *,
    attempt: int = RUN_ATTEMPT,
    overrides: dict[ObjectIdentifier, str] | None = None,
    omitted: set[ObjectIdentifier] | None = None,
) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test Fulcio")])
    integrated = dt.datetime.fromtimestamp(INTEGRATED_TIME, tz=dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(integrated - dt.timedelta(minutes=5))
        .not_valid_after(integrated + dt.timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(signer_identity())]),
            critical=True,
        )
    )
    extensions = expected_extensions(attempt=attempt)
    extensions.update(overrides or {})
    for oid, value in extensions.items():
        if oid in (omitted or set()):
            continue
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, der_utf8(value)),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def index_bytes(*, descriptors: int = 4) -> bytes:
    return canonical(
        {
            "manifests": [{} for _ in range(descriptors)],
            "mediaType": verifier.OCI_INDEX_MEDIA_TYPE,
            "schemaVersion": 2,
        }
    )


def signature_bundle(
    digest: str,
    *,
    certificate: bytes | None = None,
    predicate_type: str = verifier.COSIGN_SIGNATURE_PREDICATE_TYPE,
    include_timestamp: bool = True,
) -> dict[str, object]:
    certificate = certificate_der() if certificate is None else certificate
    payload = canonical(
        {
            "_type": verifier.INTOTO_STATEMENT_TYPE,
            "predicate": {},
            "predicateType": predicate_type,
            "subject": [
                {
                    "annotations": {},
                    "digest": {"sha256": digest.removeprefix("sha256:")},
                }
            ],
        }
    )
    signature = base64.b64encode(b"s" * 64).decode()
    envelope = {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": verifier.INTOTO_PAYLOAD_TYPE,
        "signatures": [{"sig": signature}],
    }
    certificate_object = x509.load_der_x509_certificate(certificate)
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(canonical(envelope)).hexdigest(),
            },
            "payloadHash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(payload).hexdigest(),
            },
            "signatures": [
                {
                    "signature": signature,
                    "verifier": base64.b64encode(
                        certificate_object.public_bytes(serialization.Encoding.PEM)
                    ).decode(),
                }
            ],
        },
    }
    material: dict[str, object] = {
        "certificate": {"rawBytes": base64.b64encode(certificate).decode()},
        "tlogEntries": [
            {
                "canonicalizedBody": base64.b64encode(canonical(body)).decode(),
                "inclusionPromise": {"signedEntryTimestamp": base64.b64encode(b"p" * 64).decode()},
                "inclusionProof": {
                    "checkpoint": {"envelope": "rekor.example\n1\nroot\n"},
                    "hashes": [],
                    "logIndex": "0",
                    "rootHash": base64.b64encode(b"r" * 32).decode(),
                    "treeSize": "1",
                },
                "integratedTime": str(INTEGRATED_TIME),
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "logId": {"keyId": base64.b64encode(b"l" * 32).decode()},
                "logIndex": "1234",
            }
        ],
    }
    if include_timestamp:
        material["timestampVerificationData"] = {
            "rfc3161Timestamps": [{"signedTimestamp": base64.b64encode(b"t" * 64).decode()}]
        }
    return {
        "dsseEnvelope": envelope,
        "mediaType": blob_signature.SIGSTORE_BUNDLE_MEDIA_TYPE,
        "verificationMaterial": material,
    }


def bundle_bytes(value: dict[str, object]) -> bytes:
    return canonical(value) + b"\n"


def plan() -> Any:
    value = {
        "assets": [
            {
                "name": "placeholder.txt",
                "path": "placeholder.txt",
                "sha256": hashlib.sha256(b"placeholder").hexdigest(),
                "size": len(b"placeholder"),
            }
        ],
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "run_id": RUN_ID,
        "schema_version": 1,
        "tag": TAG,
        "target_commit": COMMIT,
        "workflow_path": WORKFLOW_PATH,
        "workflow_sha": COMMIT,
    }
    raw = controller.canonical_json(value)
    return controller.validate_manifest(value, hashlib.sha256(raw).hexdigest())


def workflow() -> Any:
    return actions_provenance.AuthenticatedWorkflow(
        record_sha256="c" * 64,
        authenticated_release_sha256="d" * 64,
        owner_id=OWNER_ID,
        workflow_id=WORKFLOW_ID,
        run_attempt=RUN_ATTEMPT,
        url=f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        file_sha256=WORKFLOW_FILE_SHA256,
    )


@dataclasses.dataclass
class FakeRegistry:
    raw: bytes

    def fetch_index(self, repository: str, digest: str) -> Any:
        assert repository == REPOSITORY
        assert digest == f"sha256:{hashlib.sha256(self.raw).hexdigest()}"
        return verifier.FetchedIndex(
            raw=self.raw,
            manifest_url=f"https://ghcr.io/v2/{repository}/manifests/{digest}",
            token_url=(
                "https://ghcr.io/token?"
                f"service=ghcr.io&scope=repository%3A{repository.replace('/', '%2F')}%3Apull"
            ),
        )


class FakeCosign:
    def __init__(
        self,
        downloaded: bytes,
        *,
        mutation: Callable[[Path], None] | None = None,
        version: str = "3.0.6",
    ) -> None:
        self.downloaded = downloaded
        self.mutation = mutation
        self.version = version
        self.calls: list[tuple[str, object]] = []

    def check_version(self) -> str:
        self.calls.append(("version", None))
        return self.version

    def download_signatures(self, reference: str) -> bytes:
        self.calls.append(("download", reference))
        return self.downloaded

    def verify_bundle(self, bundle: Path, **kwargs: object) -> None:
        self.calls.append(
            (
                "verify",
                {
                    "bundle": bundle,
                    "raw": bundle.read_bytes(),
                    **kwargs,
                },
            )
        )
        if self.mutation is not None:
            self.mutation(bundle)


@dataclasses.dataclass
class Fixture:
    plan: Any
    workflow: Any
    index: bytes
    digest: str
    signature: dict[str, object]


def fixture() -> Fixture:
    raw_index = index_bytes()
    digest = f"sha256:{hashlib.sha256(raw_index).hexdigest()}"
    return Fixture(
        plan=plan(),
        workflow=workflow(),
        index=raw_index,
        digest=digest,
        signature=signature_bundle(digest),
    )


def acquire(
    item: Fixture,
    output: Path,
    *,
    downloaded: bytes | None = None,
    cosign: FakeCosign | None = None,
    registry: Any | None = None,
) -> tuple[dict[str, object], FakeCosign]:
    selected_cosign = (
        FakeCosign(bundle_bytes(item.signature))
        if cosign is None and downloaded is None
        else FakeCosign(cast(bytes, downloaded))
        if cosign is None
        else cosign
    )
    result = verifier.acquire_oci_index(
        item.plan,
        item.workflow,
        expected_manifest_sha256=item.plan.manifest_sha256,
        index_digest=item.digest,
        output_root=output,
        registry=FakeRegistry(item.index) if registry is None else registry,
        cosign=selected_cosign,
    )
    return cast(dict[str, object], result), selected_cosign


def tlog_entry(value: dict[str, object]) -> dict[str, object]:
    material = cast(dict[str, object], value["verificationMaterial"])
    return cast(list[dict[str, object]], material["tlogEntries"])[0]


def tlog_body(value: dict[str, object]) -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads(base64.b64decode(cast(str, tlog_entry(value)["canonicalizedBody"]))),
    )


def replace_tlog_body(value: dict[str, object], body: dict[str, object]) -> None:
    tlog_entry(value)["canonicalizedBody"] = base64.b64encode(canonical(body)).decode()


def test_acquires_exact_index_and_current_run_signature(tmp_path: Path) -> None:
    item = fixture()
    output = tmp_path / "authenticated-index"

    result, cosign = acquire(item, output)

    assert result["schema_version"] == 1
    assert result["kind"] == verifier.RECORD_KIND
    assert result["publication_allowed"] is False
    assert result["controller_manifest"] == {"sha256": item.plan.manifest_sha256}
    assert result["authenticated_workflow"] == {"sha256": item.workflow.record_sha256}
    assert result["cosign"] == {
        "maximum_major_version": 3,
        "minimum_version": "3.0.6",
        "version": "3.0.6",
    }
    image = cast(dict[str, object], result["image"])
    assert image["digest"] == item.digest
    assert image["reference"] == f"ghcr.io/{REPOSITORY}@{item.digest}"
    index = cast(dict[str, object], image["index"])
    assert index["descriptor_count"] == 4
    assert index["sha256"] == item.digest.removeprefix("sha256:")
    signature = cast(dict[str, object], result["signature_bundle"])
    assert signature["timestamp_count"] == 1
    assert signature["transparency_log_entry_count"] == 1
    assert (output / verifier.INDEX_NAME).read_bytes() == item.index
    assert (output / verifier.SIGNATURE_NAME).read_bytes() == bundle_bytes(item.signature)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / verifier.INDEX_NAME).stat().st_mode) == 0o600
    assert stat.S_IMODE((output / verifier.SIGNATURE_NAME).stat().st_mode) == 0o600
    assert cosign.calls[0] == ("version", None)
    assert cosign.calls[1] == (
        "download",
        f"ghcr.io/{REPOSITORY}@{item.digest}",
    )
    verify_call = cast(dict[str, object], cosign.calls[2][1])
    assert verify_call["raw"] == bundle_bytes(item.signature)
    assert verify_call["digest_hex"] == item.digest.removeprefix("sha256:")
    assert verify_call["certificate_identity"] == signer_identity()
    assert verify_call["workflow_ref"] == f"refs/tags/{TAG}"
    assert verify_call["workflow_sha"] == COMMIT
    assert verify_call["repository"] == REPOSITORY


def test_output_record_is_deterministic(tmp_path: Path) -> None:
    item = fixture()
    first, _ = acquire(item, tmp_path / "first")
    second, _ = acquire(item, tmp_path / "second")
    assert controller.canonical_json(first) == controller.canonical_json(second)


def test_skips_other_predicates_and_prior_attempt_signatures(tmp_path: Path) -> None:
    item = fixture()
    provenance = signature_bundle(
        item.digest,
        predicate_type="https://slsa.dev/provenance/v1",
    )
    prior = signature_bundle(
        item.digest,
        certificate=certificate_der(attempt=RUN_ATTEMPT - 1),
    )
    downloaded = bundle_bytes(provenance) + bundle_bytes(prior) + bundle_bytes(item.signature)

    result, cosign = acquire(item, tmp_path / "selected", downloaded=downloaded)

    assert (
        cast(dict[str, object], result["signature_bundle"])["sha256"]
        == hashlib.sha256(bundle_bytes(item.signature)).hexdigest()
    )
    assert cast(dict[str, object], cosign.calls[2][1])["raw"] == bundle_bytes(item.signature)


@pytest.mark.parametrize("count", [0, 2])
def test_requires_exactly_one_current_run_signature(tmp_path: Path, count: int) -> None:
    item = fixture()
    downloaded = (
        bundle_bytes(
            signature_bundle(
                item.digest,
                certificate=certificate_der(attempt=RUN_ATTEMPT - 1),
            )
        )
        if count == 0
        else bundle_bytes(item.signature) * 2
    )
    output = tmp_path / "rejected"

    with pytest.raises(verifier.OCIIndexError, match="exactly one"):
        acquire(item, output, downloaded=downloaded)

    assert not output.exists()


def test_rejects_different_subject_digest(tmp_path: Path) -> None:
    item = fixture()
    changed = signature_bundle("sha256:" + "f" * 64)

    with pytest.raises(verifier.OCIIndexError, match="different index digest"):
        acquire(item, tmp_path / "rejected", downloaded=bundle_bytes(changed))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("envelope-hash", "different DSSE envelope"),
        ("payload-hash", "different DSSE payload"),
        ("body-signature", "different signature"),
        ("body-certificate", "different certificate"),
        ("kind", "DSSE"),
        ("global-index", "canonical decimal"),
        ("tree-bounds", "tree bounds"),
        ("noncanonical-body", "canonical JSON"),
    ],
)
def test_rejects_transparency_log_substitution(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    item = fixture()
    changed = copy.deepcopy(item.signature)
    entry = tlog_entry(changed)
    if mutation == "kind":
        cast(dict[str, object], entry["kindVersion"])["kind"] = "hashedrekord"
    elif mutation == "global-index":
        entry["logIndex"] = "01"
    elif mutation == "tree-bounds":
        cast(dict[str, object], entry["inclusionProof"])["treeSize"] = "0"
    elif mutation == "noncanonical-body":
        raw_body = base64.b64decode(cast(str, entry["canonicalizedBody"]))
        entry["canonicalizedBody"] = base64.b64encode(raw_body + b"\n").decode()
    else:
        body = tlog_body(changed)
        spec = cast(dict[str, object], body["spec"])
        if mutation == "envelope-hash":
            cast(dict[str, object], spec["envelopeHash"])["value"] = "f" * 64
        elif mutation == "payload-hash":
            cast(dict[str, object], spec["payloadHash"])["value"] = "f" * 64
        elif mutation == "body-signature":
            cast(list[dict[str, object]], spec["signatures"])[0]["signature"] = base64.b64encode(
                b"x" * 64
            ).decode()
        else:
            cast(list[dict[str, object]], spec["signatures"])[0]["verifier"] = base64.b64encode(
                b"different certificate"
            ).decode()
        replace_tlog_body(changed, body)

    with pytest.raises(verifier.OCIIndexError, match=message):
        acquire(item, tmp_path / "rejected", downloaded=bundle_bytes(changed))


@pytest.mark.parametrize(
    "oid",
    [
        blob_signature.OID_ISSUER_V2,
        blob_signature.OID_BUILD_SIGNER_URI,
        blob_signature.OID_BUILD_SIGNER_DIGEST,
        blob_signature.OID_RUNNER_ENVIRONMENT,
        blob_signature.OID_SOURCE_REPOSITORY_URI,
        blob_signature.OID_SOURCE_REPOSITORY_DIGEST,
        blob_signature.OID_SOURCE_REPOSITORY_REF,
        blob_signature.OID_SOURCE_REPOSITORY_ID,
        blob_signature.OID_SOURCE_REPOSITORY_OWNER_URI,
        blob_signature.OID_SOURCE_REPOSITORY_OWNER_ID,
        blob_signature.OID_BUILD_CONFIG_URI,
        blob_signature.OID_BUILD_CONFIG_DIGEST,
        blob_signature.OID_BUILD_TRIGGER,
        blob_signature.OID_RUN_INVOCATION_URI,
        blob_signature.OID_SOURCE_REPOSITORY_VISIBILITY,
        blob_signature.OID_TOKEN_SUBJECT,
    ],
)
def test_rejects_each_current_run_certificate_substitution(
    tmp_path: Path,
    oid: ObjectIdentifier,
) -> None:
    item = fixture()
    changed = signature_bundle(
        item.digest,
        certificate=certificate_der(overrides={oid: "wrong"}),
    )

    with pytest.raises(verifier.OCIIndexError, match=r"exactly one|does not match"):
        acquire(item, tmp_path / "rejected", downloaded=bundle_bytes(changed))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"", "JSON Lines"),
        (b"{}\n\n", "bundle count"),
        (b"{}", "JSON Lines"),
        (b'{"x":1,"x":2}\n', "invalid"),
    ],
)
def test_rejects_malformed_cosign_download(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    item = fixture()
    with pytest.raises(verifier.OCIIndexError, match=message):
        acquire(item, tmp_path / "rejected", downloaded=raw)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ([], "JSON object"),
        ({"mediaType": verifier.OCI_INDEX_MEDIA_TYPE, "schemaVersion": 2}, "fields"),
        (
            {
                "manifests": [{}],
                "mediaType": "application/example",
                "schemaVersion": 2,
            },
            "schema or media type",
        ),
        (
            {
                "manifests": [],
                "mediaType": verifier.OCI_INDEX_MEDIA_TYPE,
                "schemaVersion": 2,
            },
            "descriptor count",
        ),
        (
            {
                "manifests": ["not an object"],
                "mediaType": verifier.OCI_INDEX_MEDIA_TYPE,
                "schemaVersion": 2,
            },
            "non-object",
        ),
    ],
)
def test_rejects_invalid_index_shape(value: object, message: str) -> None:
    with pytest.raises(verifier.OCIIndexError, match=message):
        verifier._validate_index(canonical(value))


def test_rejects_wrong_trusted_inputs_before_output(tmp_path: Path) -> None:
    item = fixture()
    with pytest.raises(verifier.OCIIndexError, match="trusted SHA-256"):
        verifier.acquire_oci_index(
            item.plan,
            item.workflow,
            expected_manifest_sha256="f" * 64,
            index_digest=item.digest,
            output_root=tmp_path / "wrong-manifest",
            registry=FakeRegistry(item.index),
            cosign=FakeCosign(bundle_bytes(item.signature)),
        )
    with pytest.raises(verifier.OCIIndexError, match="lowercase SHA-256"):
        verifier.acquire_oci_index(
            item.plan,
            item.workflow,
            expected_manifest_sha256=item.plan.manifest_sha256,
            index_digest="sha256:BAD",
            output_root=tmp_path / "wrong-digest",
            registry=FakeRegistry(item.index),
            cosign=FakeCosign(bundle_bytes(item.signature)),
        )
    assert not any(tmp_path.iterdir())


def test_rejects_registry_digest_disagreement(tmp_path: Path) -> None:
    item = fixture()

    class WrongRegistry:
        def fetch_index(self, repository: str, digest: str) -> Any:
            assert repository == REPOSITORY
            return verifier.FetchedIndex(
                raw=item.index + b"changed",
                manifest_url=f"https://ghcr.io/v2/{repository}/manifests/{digest}",
                token_url="https://ghcr.io/token",
            )

    with pytest.raises(verifier.OCIIndexError, match="different index digest"):
        acquire(item, tmp_path / "rejected", registry=WrongRegistry())


def test_rejects_bundle_replacement_during_cosign_verification(tmp_path: Path) -> None:
    item = fixture()

    def mutate(path: Path) -> None:
        path.write_bytes(b"replacement")
        path.chmod(0o600)

    output = tmp_path / "rejected"
    with pytest.raises(verifier.OCIIndexError, match="atomically retain"):
        acquire(
            item,
            output,
            cosign=FakeCosign(bundle_bytes(item.signature), mutation=mutate),
        )
    assert not output.exists()


def test_refuses_to_replace_existing_output_directory(tmp_path: Path) -> None:
    item = fixture()
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(verifier.OCIIndexError, match="private OCI acquisition output"):
        acquire(item, output)

    assert sentinel.read_text(encoding="utf-8") == "keep"


class FakeResponse:
    def __init__(
        self,
        raw: bytes,
        url: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.raw = raw
        self.url = url
        self.status = status
        self.headers = {} if headers is None else headers
        self.closed = False

    def geturl(self) -> str:
        return self.url

    def read(self, maximum: int) -> bytes:
        return self.raw[:maximum]

    def close(self) -> None:
        self.closed = True


class DuplicateHeaders(dict[str, str]):
    def get_all(self, name: str) -> list[str] | None:
        if name == "Docker-Content-Digest":
            return [self[name], "sha256:" + "f" * 64]
        return None


class FakeOpener:
    def __init__(self, responses: list[FakeResponse | BaseException]) -> None:
        self.responses = responses
        self.all_responses = [
            response for response in responses if isinstance(response, FakeResponse)
        ]
        self.requests: list[tuple[Any, float]] = []

    def open(self, request: Any, *, timeout: float) -> FakeResponse:
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def ghcr_fixture() -> tuple[Any, bytes, str, str]:
    raw = index_bytes()
    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    token_url = (
        "https://ghcr.io/token?"
        "service=ghcr.io&scope=repository%3Astampbot%2Fextra-codeowners%3Apull"
    )
    manifest_url = f"https://ghcr.io/v2/{REPOSITORY}/manifests/{digest}"
    opener = FakeOpener(
        [
            FakeResponse(
                b'{"token":"anonymous-token"}',
                token_url,
                headers={"Content-Type": "application/json"},
            ),
            FakeResponse(
                raw,
                manifest_url,
                headers={
                    "Content-Length": str(len(raw)),
                    "Content-Type": verifier.OCI_INDEX_MEDIA_TYPE,
                    "Docker-Content-Digest": digest,
                },
            ),
        ]
    )
    return opener, raw, digest, token_url


def test_ghcr_client_fetches_only_exact_https_digest_without_redirects() -> None:
    opener, raw, digest, token_url = ghcr_fixture()
    client = verifier.GHCRClient(timeout=12, opener=opener)

    result = client.fetch_index(REPOSITORY, digest)

    assert result.raw == raw
    assert result.token_url == token_url
    assert result.manifest_url == f"https://ghcr.io/v2/{REPOSITORY}/manifests/{digest}"
    assert len(opener.requests) == 2
    token_request, token_timeout = opener.requests[0]
    manifest_request, manifest_timeout = opener.requests[1]
    assert token_request.full_url == token_url
    assert token_request.get_header("Authorization") is None
    assert manifest_request.full_url == result.manifest_url
    assert manifest_request.get_header("Authorization") == "Bearer anonymous-token"
    assert token_timeout == manifest_timeout == 12
    assert all(response.closed for response in opener.all_responses)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("token-media", "wrong media type"),
        ("token-shape", "token response is invalid"),
        ("token-characters", "invalid characters"),
        ("token-url", "unexpected response"),
        ("manifest-media", "wrong media type"),
        ("manifest-encoding", "encoded bytes"),
        ("manifest-digest", "different digest"),
        ("manifest-length", "wrong byte length"),
        ("manifest-url", "unexpected response"),
    ],
)
def test_ghcr_client_rejects_response_substitution(
    mutation: str,
    message: str,
) -> None:
    opener, raw, digest, token_url = ghcr_fixture()
    token = cast(FakeResponse, opener.responses[0])
    manifest = cast(FakeResponse, opener.responses[1])
    if mutation == "token-media":
        token.headers["Content-Type"] = "text/plain"
    elif mutation == "token-shape":
        token.raw = b'{"access_token":"wrong-field"}'
    elif mutation == "token-characters":
        token.raw = b'{"token":"bad token"}'
    elif mutation == "token-url":
        token.url = "https://example.com/token"
    elif mutation == "manifest-media":
        manifest.headers["Content-Type"] = "application/example"
    elif mutation == "manifest-encoding":
        manifest.headers["Content-Encoding"] = "gzip"
    elif mutation == "manifest-digest":
        manifest.headers["Docker-Content-Digest"] = "sha256:" + "f" * 64
    elif mutation == "manifest-length":
        manifest.headers["Content-Length"] = str(len(raw) + 1)
    else:
        manifest.url = "https://example.com/index"

    with pytest.raises(verifier.OCIIndexError, match=message):
        verifier.GHCRClient(opener=opener).fetch_index(REPOSITORY, digest)

    assert token_url.startswith("https://ghcr.io/")


def test_ghcr_client_rejects_redirect_and_invalid_timeout() -> None:
    redirect = urllib.error.HTTPError(
        "https://ghcr.io/token",
        302,
        "Found",
        Message(),
        None,
    )
    with pytest.raises(verifier.OCIIndexError, match="untrusted redirect"):
        verifier.GHCRClient(opener=FakeOpener([redirect])).fetch_index(
            REPOSITORY,
            "sha256:" + "f" * 64,
        )
    for timeout in (0, -1, verifier.MAX_REGISTRY_TIMEOUT_SECONDS + 1, True):
        with pytest.raises(verifier.OCIIndexError, match="timeout"):
            verifier.GHCRClient(timeout=timeout)
    with pytest.raises(verifier.OCIIndexError, match="lowercase SHA-256"):
        verifier.GHCRClient(opener=FakeOpener([])).fetch_index(REPOSITORY, "sha256:BAD")


def test_ghcr_client_rejects_ambiguous_security_headers() -> None:
    opener, _raw, digest, _token_url = ghcr_fixture()
    manifest = cast(FakeResponse, opener.responses[1])
    manifest.headers = DuplicateHeaders(manifest.headers)

    with pytest.raises(verifier.OCIIndexError, match="ambiguous Docker-Content-Digest"):
        verifier.GHCRClient(opener=opener).fetch_index(REPOSITORY, digest)


def cosign_script(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "cosign"
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def cosign_home(tmp_path: Path) -> Path:
    path = tmp_path / "cosign-home"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_cosign_cli_downloads_and_verifies_with_exact_argv(tmp_path: Path) -> None:
    download_log = tmp_path / "download.json"
    verify_log = tmp_path / "verify.json"
    executable = cosign_script(
        tmp_path,
        "import json, os, pathlib, sys\n"
        "arguments = sys.argv[1:]\n"
        "record = {'argv': arguments, 'env': dict(os.environ)}\n"
        "if arguments[:2] == ['download', 'signature']:\n"
        f"    pathlib.Path({str(download_log)!r}).write_text(json.dumps(record))\n"
        "    print('downloaded bundle')\n"
        "else:\n"
        f"    pathlib.Path({str(verify_log)!r}).write_text(json.dumps(record))\n"
        "    print('Verified OK', file=sys.stderr)\n",
    )
    home = cosign_home(tmp_path)
    client = verifier.CosignCLI(
        executable=str(executable),
        home=home,
        environment={
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret",
            "DOCKER_CONFIG": "/untrusted",
            "GH_TOKEN": "secret",
            "GITHUB_TOKEN": "secret",
            "PATH": os.environ["PATH"],
            "SIGSTORE_NO_CACHE": "1",
        },
    )
    reference = "ghcr.io/stampbot/extra-codeowners@sha256:" + "f" * 64
    assert client.download_signatures(reference) == b"downloaded bundle\n"
    bundle = (tmp_path / "bundle.sigstore.json").absolute()
    client.verify_bundle(
        bundle,
        digest_hex="f" * 64,
        certificate_identity=signer_identity(),
        workflow_ref=f"refs/tags/{TAG}",
        workflow_sha=COMMIT,
        repository=REPOSITORY,
    )

    download = json.loads(download_log.read_text(encoding="utf-8"))
    assert download["argv"] == ["download", "signature", reference]
    environment = download["env"]
    assert environment["HOME"] == str(home)
    assert environment["XDG_CACHE_HOME"] == str(home / ".cache")
    for secret in (
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "DOCKER_CONFIG",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "SIGSTORE_NO_CACHE",
    ):
        assert secret not in environment
    verify = json.loads(verify_log.read_text(encoding="utf-8"))
    assert verify["argv"] == [
        "verify-blob-attestation",
        "--bundle",
        str(bundle),
        "--digest",
        "f" * 64,
        "--digestAlg",
        "sha256",
        "--type",
        verifier.COSIGN_SIGNATURE_PREDICATE_TYPE,
        "--certificate-identity",
        signer_identity(),
        "--certificate-oidc-issuer",
        blob_signature.OIDC_ISSUER,
        "--certificate-github-workflow-trigger",
        "push",
        "--certificate-github-workflow-sha",
        COMMIT,
        "--certificate-github-workflow-repository",
        REPOSITORY,
        "--certificate-github-workflow-ref",
        f"refs/tags/{TAG}",
        "--max-workers",
        "1",
    ]


def test_cosign_cli_rejects_unexpected_verification_stdout(tmp_path: Path) -> None:
    client = verifier.CosignCLI(
        executable=str(cosign_script(tmp_path, "print('unexpected')\n")),
        home=cosign_home(tmp_path),
    )
    with pytest.raises(verifier.OCIIndexError, match="unexpected standard output"):
        client.verify_bundle(
            (tmp_path / "bundle").absolute(),
            digest_hex="f" * 64,
            certificate_identity=signer_identity(),
            workflow_ref=f"refs/tags/{TAG}",
            workflow_sha=COMMIT,
            repository=REPOSITORY,
        )


def test_source_keeps_verifier_publication_inert_and_unwired() -> None:
    root = Path(__file__).parents[1]
    script_path = root / ".github" / "scripts" / "acquire_oci_index.py"
    source = script_path.read_text(encoding="utf-8")
    workflows = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((root / ".github" / "workflows").glob("*.yml"))
    )

    for forbidden in (
        "docker buildx imagetools create",
        "cosign sign",
        "gh release",
        "package: write",
        "packages: write",
    ):
        assert forbidden not in source
    assert '"publication_allowed": False' in source
    assert workflows.count(".github/scripts/acquire_oci_index.py") == 2
    assert "python -I -B .github/scripts/acquire_oci_index.py" not in workflows
    assert "--digestAlg" in source
    assert "--certificate-identity" in source
    assert "--certificate-github-workflow-ref" in source
    assert "--max-workers" in source


def test_documentation_matches_the_oci_acquisition_contract() -> None:
    root = Path(__file__).parents[1]
    reference = (root / "docs/reference/authenticated-oci-index.md").read_text(encoding="utf-8")
    how_to = (root / "docs/how-to/verify-container-release-evidence.md").read_text(encoding="utf-8")
    contract = (root / "docs/reference/container-evidence-release-contract.md").read_text(
        encoding="utf-8"
    )
    navigation = (root / "mkdocs.yml").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")

    for option in (
        "--manifest",
        "--manifest-sha256",
        "--authenticated-workflow-record",
        "--authenticated-workflow-record-sha256",
        "--index-digest",
        "--output-dir",
        "--cosign-home",
        "--registry-timeout-seconds",
        "--cosign-timeout-seconds",
    ):
        assert option in reference
    assert ".github/scripts/acquire_oci_index.py" in how_to
    assert '--index-digest "$OCI_INDEX_DIGEST"' in how_to
    assert "`publication_allowed` | Always `false`." in reference
    assert "doesn't establish where the trusted index digest came from" in contract
    assert "Authenticated OCI index: reference/authenticated-oci-index.md" in navigation
    assert ".github/scripts/acquire_oci_index.py" in dockerfile
    assert "!.github/scripts/acquire_oci_index.py" in dockerignore
