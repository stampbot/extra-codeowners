"""Adversarial tests for authenticated Sigstore blob verification."""

from __future__ import annotations

import base64
import copy
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable
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
acquisition: Any = load_script("acquire_github_release_assets")
workflow_verifier: Any = load_script("verify_release_workflow")
actions_provenance: Any = load_script("verify_actions_build_provenance")
verifier: Any = load_script("verify_blob_signature")

REPOSITORY = "stampbot/extra-codeowners"
REPOSITORY_ID = 1_299_090_885
OWNER_ID = 1_234_567
RELEASE_ID = 987_654_321
WORKFLOW_ID = 44_556_677
RUN_ID = 12_345_678
RUN_ATTEMPT = 2
TAG = "v0.1.0"
COMMIT = "a" * 40
WORKFLOW_PATH = ".github/workflows/release.yml"
WORKFLOW_SHA256 = "b" * 64
AUTHENTICATED_RELEASE_SHA256 = "c" * 64
ASSET_NAME = "extra-codeowners-0.1.0.tgz"
BUNDLE_NAME = f"{ASSET_NAME}.sigstore.json"
ASSET_BYTES = b"signed chart bytes"
INTEGRATED_TIME = 1_788_000_000


def signer_identity() -> str:
    return f"https://github.com/{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/{TAG}"


def run_invocation() -> str:
    return f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}"


def der_utf8(value: str) -> bytes:
    encoded = value.encode()
    if len(encoded) < 128:
        return b"\x0c" + bytes([len(encoded)]) + encoded
    return b"\x0c\x81" + bytes([len(encoded)]) + encoded


def rekor_canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def expected_extensions() -> dict[ObjectIdentifier, str]:
    owner = REPOSITORY.partition("/")[0]
    ref = f"refs/tags/{TAG}"
    return {
        verifier.OID_ISSUER_V2: verifier.OIDC_ISSUER,
        verifier.OID_BUILD_SIGNER_URI: signer_identity(),
        verifier.OID_BUILD_SIGNER_DIGEST: COMMIT,
        verifier.OID_RUNNER_ENVIRONMENT: "github-hosted",
        verifier.OID_SOURCE_REPOSITORY_URI: f"https://github.com/{REPOSITORY}",
        verifier.OID_SOURCE_REPOSITORY_DIGEST: COMMIT,
        verifier.OID_SOURCE_REPOSITORY_REF: ref,
        verifier.OID_SOURCE_REPOSITORY_ID: str(REPOSITORY_ID),
        verifier.OID_SOURCE_REPOSITORY_OWNER_URI: f"https://github.com/{owner}",
        verifier.OID_SOURCE_REPOSITORY_OWNER_ID: str(OWNER_ID),
        verifier.OID_BUILD_CONFIG_URI: signer_identity(),
        verifier.OID_BUILD_CONFIG_DIGEST: COMMIT,
        verifier.OID_BUILD_TRIGGER: "push",
        verifier.OID_RUN_INVOCATION_URI: run_invocation(),
        verifier.OID_SOURCE_REPOSITORY_VISIBILITY: "public",
        verifier.OID_TOKEN_SUBJECT: f"repo:{REPOSITORY}:ref:{ref}",
    }


def certificate_der(
    *,
    overrides: dict[ObjectIdentifier, str] | None = None,
    omitted: set[ObjectIdentifier] | None = None,
    malformed: dict[ObjectIdentifier, bytes] | None = None,
    san_names: list[x509.GeneralName] | None = None,
    include_environment: bool = False,
    ca: bool = False,
    digital_signature: bool = True,
    code_signing: bool = True,
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
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CODE_SIGNING]
                if code_signing
                else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(signer_identity())]
                if san_names is None
                else san_names
            ),
            critical=True,
        )
    )
    values = expected_extensions()
    values.update(overrides or {})
    for oid, value in values.items():
        if oid in (omitted or set()):
            continue
        encoded = (malformed or {}).get(oid, der_utf8(value))
        builder = builder.add_extension(x509.UnrecognizedExtension(oid, encoded), critical=False)
    if include_environment:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                verifier.OID_DEPLOYMENT_ENVIRONMENT,
                der_utf8("production"),
            ),
            critical=False,
        )
    certificate = builder.sign(key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.DER)


def bundle_value(
    *,
    certificate: bytes | None = None,
    asset_bytes: bytes = ASSET_BYTES,
    include_timestamp: bool = False,
) -> dict[str, object]:
    certificate = certificate_der() if certificate is None else certificate
    signature = base64.b64encode(b"s" * 64).decode()
    message_digest = hashlib.sha256(asset_bytes).digest()
    certificate_object = x509.load_der_x509_certificate(certificate)
    pem = certificate_object.public_bytes(serialization.Encoding.PEM)
    body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": message_digest.hex(),
                }
            },
            "signature": {
                "content": signature,
                "publicKey": {
                    "content": base64.b64encode(pem).decode(),
                },
            },
        },
    }
    material: dict[str, object] = {
        "certificate": {"rawBytes": base64.b64encode(certificate).decode()},
        "tlogEntries": [
            {
                "canonicalizedBody": base64.b64encode(rekor_canonical_json(body)).decode(),
                "inclusionPromise": {"signedEntryTimestamp": base64.b64encode(b"p" * 64).decode()},
                "inclusionProof": {
                    "checkpoint": {"envelope": "rekor.example\n1\nroot\n"},
                    "hashes": [],
                    "logIndex": "0",
                    "rootHash": base64.b64encode(b"r" * 32).decode(),
                    "treeSize": "1",
                },
                "integratedTime": str(INTEGRATED_TIME),
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
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
        "mediaType": verifier.SIGSTORE_BUNDLE_MEDIA_TYPE,
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(message_digest).decode(),
            },
            "signature": signature,
        },
        "verificationMaterial": material,
    }


def bundle_bytes(value: dict[str, object] | None = None) -> bytes:
    return cast(bytes, controller.canonical_json(bundle_value() if value is None else value))


def manifest_value(contents: dict[str, bytes]) -> dict[str, object]:
    return {
        "assets": [
            {
                "name": name,
                "path": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for name, content in contents.items()
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


def release_plan(contents: dict[str, bytes]) -> Any:
    manifest = manifest_value(contents)
    raw = controller.canonical_json(manifest)
    return controller.validate_manifest(manifest, hashlib.sha256(raw).hexdigest())


def workflow_record_value(plan: Any) -> dict[str, object]:
    return {
        "authenticated_release": {"sha256": AUTHENTICATED_RELEASE_SHA256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": workflow_verifier.RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
        },
        "schema_version": 1,
        "tag": {"name": TAG, "target_commit": COMMIT},
        "workflow": {
            "event": "push",
            "file": {
                "git_blob_sha1": "d" * 40,
                "sha256": WORKFLOW_SHA256,
                "size": 100,
            },
            "id": WORKFLOW_ID,
            "path": WORKFLOW_PATH,
            "ref": f"refs/tags/{TAG}",
            "run_attempt": RUN_ATTEMPT,
            "run_id": RUN_ID,
            "sha": COMMIT,
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        },
    }


def acquisition_record_value(plan: Any) -> dict[str, object]:
    return {
        "assets": [
            {
                "github_asset_id": index + 700,
                "name": asset.name,
                "path": asset.name,
                "sha256": asset.sha256,
                "size": asset.size,
            }
            for index, asset in enumerate(plan.assets)
        ],
        "authenticated_release": {
            "attestation_payload_sha256": "e" * 64,
            "sha256": AUTHENTICATED_RELEASE_SHA256,
        },
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": acquisition.RECORD_KIND,
        "publication_allowed": False,
        "release": {
            "id": RELEASE_ID,
            "immutable": True,
            "url": f"https://github.com/{REPOSITORY}/releases/tag/{TAG}",
        },
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
        },
        "schema_version": 1,
        "tag": {
            "attestation_subject_sha1": COMMIT,
            "name": TAG,
            "target_commit": COMMIT,
        },
    }


def write_record(path: Path, value: dict[str, object]) -> tuple[Path, str]:
    raw = controller.canonical_json(value)
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


@dataclasses.dataclass
class Fixture:
    plan: Any
    workflow: Any
    acquired: Any
    root: Path
    contents: dict[str, bytes]
    bundle: dict[str, object]


def make_fixture(
    tmp_path: Path,
    *,
    raw_bundle: dict[str, object] | None = None,
) -> Fixture:
    tmp_path.mkdir(parents=True, exist_ok=True)
    value = bundle_value() if raw_bundle is None else raw_bundle
    contents = {ASSET_NAME: ASSET_BYTES, BUNDLE_NAME: bundle_bytes(value)}
    plan = release_plan(contents)
    workflow_path, workflow_sha = write_record(
        tmp_path / "workflow.json",
        workflow_record_value(plan),
    )
    acquisition_path, acquisition_sha = write_record(
        tmp_path / "acquisition.json",
        acquisition_record_value(plan),
    )
    workflow = actions_provenance.load_authenticated_workflow(
        workflow_path,
        expected_sha256=workflow_sha,
        plan=plan,
    )
    acquired = actions_provenance.load_acquired_assets(
        acquisition_path,
        expected_sha256=acquisition_sha,
        plan=plan,
    )
    root = tmp_path / "assets"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    for asset in plan.assets:
        path = root / asset.name
        path.write_bytes(contents[asset.name])
        path.chmod(0o600)
    return Fixture(plan, workflow, acquired, root, contents, value)


class FakeCosign:
    def __init__(
        self,
        *,
        version: str = "3.0.6",
        mutation: Callable[[], None] | None = None,
    ) -> None:
        self.version = version
        self.mutation = mutation
        self.calls: list[dict[str, object]] = []

    def check_version(self) -> str:
        return self.version

    def verify_blob(self, blob: Path, **kwargs: object) -> None:
        self.calls.append({"blob": blob, **kwargs})
        if self.mutation is not None:
            self.mutation()


def verify(fixture: Fixture, client: FakeCosign | None = None) -> dict[str, object]:
    result = verifier.verify_blob_signature(
        fixture.plan,
        fixture.workflow,
        fixture.acquired,
        expected_manifest_sha256=fixture.plan.manifest_sha256,
        asset_root=fixture.root,
        asset_name=ASSET_NAME,
        client=FakeCosign() if client is None else client,
    )
    return cast(dict[str, object], result)


def selected_asset(fixture: Fixture) -> Any:
    return next(asset for asset in fixture.plan.assets if asset.name == ASSET_NAME)


def test_verifies_exact_blob_bundle_and_workflow_identity(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    client = FakeCosign()

    result = verify(fixture, client)

    material = cast(dict[str, object], fixture.bundle["verificationMaterial"])
    entry = cast(list[dict[str, object]], material["tlogEntries"])[0]
    body = base64.b64decode(cast(str, entry["canonicalizedBody"]))
    assert not body.endswith(b"\n")
    assert verifier._rekor_canonical_json(json.loads(body)) == body
    assert result["schema_version"] == 1
    assert result["kind"] == verifier.RECORD_KIND
    assert result["publication_allowed"] is False
    assert result["controller_manifest"] == {"sha256": fixture.plan.manifest_sha256}
    assert result["authenticated_workflow"] == {"sha256": fixture.workflow.record_sha256}
    assert result["acquired_assets"] == {"sha256": fixture.acquired.record_sha256}
    assert cast(dict[str, object], result["asset"])["name"] == ASSET_NAME
    signature = cast(dict[str, object], result["signature_bundle"])
    assert signature["name"] == BUNDLE_NAME
    assert signature["media_type"] == verifier.SIGSTORE_BUNDLE_MEDIA_TYPE
    assert signature["integrated_time"] == INTEGRATED_TIME
    assert signature["transparency_log_entry_count"] == 1
    assert signature["timestamp_count"] == 0
    assert result["cosign"] == {
        "maximum_major_version": 3,
        "minimum_version": "3.0.6",
        "version": "3.0.6",
    }
    assert client.calls == [
        {
            "blob": fixture.root / ASSET_NAME,
            "bundle": fixture.root / BUNDLE_NAME,
            "certificate_identity": signer_identity(),
            "workflow_ref": f"refs/tags/{TAG}",
            "workflow_sha": COMMIT,
            "repository": REPOSITORY,
        }
    ]


def test_output_is_deterministic(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert controller.canonical_json(verify(fixture)) == controller.canonical_json(verify(fixture))


def test_accepts_one_bounded_rfc3161_timestamp(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path, raw_bundle=bundle_value(include_timestamp=True))
    result = verify(fixture)
    assert cast(dict[str, object], result["signature_bundle"])["timestamp_count"] == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("mediaType", "application/example", "media type"),
        ("messageSignature", {}, "message signature"),
        ("verificationMaterial", {}, "verification material"),
    ],
)
def test_rejects_bundle_envelope_substitution(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    fixture = make_fixture(tmp_path)
    changed = copy.deepcopy(fixture.bundle)
    changed[field] = value
    with pytest.raises(verifier.BlobVerificationError, match=message):
        verifier.validate_bundle(
            bundle_bytes(changed),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("algorithm", "different blob bytes"),
        ("digest", "different blob bytes"),
        ("body-digest", "different blob bytes"),
        ("body-signature", "different signature"),
        ("body-certificate", "different certificate"),
    ],
)
def test_rejects_message_or_rekor_binding_substitution(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    fixture = make_fixture(tmp_path)
    changed = copy.deepcopy(fixture.bundle)
    message_signature = cast(dict[str, object], changed["messageSignature"])
    if mutation == "algorithm":
        cast(dict[str, object], message_signature["messageDigest"])["algorithm"] = "SHA3_256"
    elif mutation == "digest":
        cast(dict[str, object], message_signature["messageDigest"])["digest"] = base64.b64encode(
            b"x" * 32
        ).decode()
    else:
        material = cast(dict[str, object], changed["verificationMaterial"])
        entry = cast(list[dict[str, object]], material["tlogEntries"])[0]
        body_raw = base64.b64decode(cast(str, entry["canonicalizedBody"]))
        body = cast(dict[str, object], json.loads(body_raw))
        spec = cast(dict[str, object], body["spec"])
        if mutation == "body-digest":
            data = cast(dict[str, object], spec["data"])
            cast(dict[str, object], data["hash"])["value"] = "f" * 64
        elif mutation == "body-signature":
            cast(dict[str, object], spec["signature"])["content"] = base64.b64encode(
                b"x" * 64
            ).decode()
        else:
            signature = cast(dict[str, object], spec["signature"])
            cast(dict[str, object], signature["publicKey"])["content"] = base64.b64encode(
                b"different certificate"
            ).decode()
        entry["canonicalizedBody"] = base64.b64encode(rekor_canonical_json(body)).decode()
    with pytest.raises(verifier.BlobVerificationError, match=message):
        verifier.validate_bundle(
            bundle_bytes(changed),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


@pytest.mark.parametrize(
    "oid",
    [
        verifier.OID_ISSUER_V2,
        verifier.OID_BUILD_SIGNER_URI,
        verifier.OID_BUILD_SIGNER_DIGEST,
        verifier.OID_RUNNER_ENVIRONMENT,
        verifier.OID_SOURCE_REPOSITORY_URI,
        verifier.OID_SOURCE_REPOSITORY_DIGEST,
        verifier.OID_SOURCE_REPOSITORY_REF,
        verifier.OID_SOURCE_REPOSITORY_ID,
        verifier.OID_SOURCE_REPOSITORY_OWNER_URI,
        verifier.OID_SOURCE_REPOSITORY_OWNER_ID,
        verifier.OID_BUILD_CONFIG_URI,
        verifier.OID_BUILD_CONFIG_DIGEST,
        verifier.OID_BUILD_TRIGGER,
        verifier.OID_RUN_INVOCATION_URI,
        verifier.OID_SOURCE_REPOSITORY_VISIBILITY,
        verifier.OID_TOKEN_SUBJECT,
    ],
)
def test_rejects_each_fulcio_identity_substitution(tmp_path: Path, oid: ObjectIdentifier) -> None:
    fixture = make_fixture(
        tmp_path,
        raw_bundle=bundle_value(certificate=certificate_der(overrides={oid: "wrong"})),
    )
    with pytest.raises(verifier.BlobVerificationError, match="does not match"):
        verify(fixture)


def test_rejects_missing_or_malformed_fulcio_extension(tmp_path: Path) -> None:
    missing = make_fixture(
        tmp_path / "missing",
        raw_bundle=bundle_value(
            certificate=certificate_der(omitted={verifier.OID_RUN_INVOCATION_URI})
        ),
    )
    with pytest.raises(verifier.BlobVerificationError, match="missing extension"):
        verify(missing)

    malformed = make_fixture(
        tmp_path / "malformed",
        raw_bundle=bundle_value(
            certificate=certificate_der(malformed={verifier.OID_RUN_INVOCATION_URI: b"not DER"})
        ),
    )
    with pytest.raises(verifier.BlobVerificationError, match="DER UTF8String"):
        verify(malformed)


@pytest.mark.parametrize(
    ("certificate", "message"),
    [
        (
            certificate_der(
                san_names=[
                    x509.UniformResourceIdentifier(signer_identity()),
                    x509.DNSName("example.com"),
                ]
            ),
            "signer identity",
        ),
        (certificate_der(include_environment=True), "deployment environment"),
        (certificate_der(ca=True), "signing constraints"),
        (certificate_der(digital_signature=False), "signing constraints"),
        (certificate_der(code_signing=False), "signing constraints"),
    ],
)
def test_rejects_invalid_certificate_constraints(
    tmp_path: Path,
    certificate: bytes,
    message: str,
) -> None:
    fixture = make_fixture(
        tmp_path,
        raw_bundle=bundle_value(certificate=certificate),
    )
    with pytest.raises(verifier.BlobVerificationError, match=message):
        verify(fixture)


@pytest.mark.parametrize("integrated_time", [INTEGRATED_TIME - 601, INTEGRATED_TIME + 601])
def test_rejects_log_time_outside_certificate_validity(
    tmp_path: Path,
    integrated_time: int,
) -> None:
    fixture = make_fixture(tmp_path)
    changed = copy.deepcopy(fixture.bundle)
    material = cast(dict[str, object], changed["verificationMaterial"])
    cast(list[dict[str, object]], material["tlogEntries"])[0]["integratedTime"] = str(
        integrated_time
    )
    with pytest.raises(verifier.BlobVerificationError, match="validity interval"):
        verifier.validate_bundle(
            bundle_bytes(changed),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


def test_rejects_log_time_outside_datetime_range(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    changed = copy.deepcopy(fixture.bundle)
    material = cast(dict[str, object], changed["verificationMaterial"])
    cast(list[dict[str, object]], material["tlogEntries"])[0]["integratedTime"] = str(
        controller.MAX_ID
    )
    with pytest.raises(verifier.BlobVerificationError, match="time bound"):
        verifier.validate_bundle(
            bundle_bytes(changed),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("no-entry", "exactly one"),
        ("two-entries", "exactly one"),
        ("kind", "hashedrekord"),
        ("global-index", "canonical decimal"),
        ("tree-index", "tree bounds"),
        ("tree-size", "tree bounds"),
        ("too-many-hashes", "hash count"),
        ("bad-checkpoint", "checkpoint"),
        ("noncanonical-body", "canonical JSON"),
    ],
)
def test_rejects_invalid_transparency_log_structure(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    fixture = make_fixture(tmp_path)
    changed = copy.deepcopy(fixture.bundle)
    material = cast(dict[str, object], changed["verificationMaterial"])
    entries = cast(list[dict[str, object]], material["tlogEntries"])
    if mutation == "no-entry":
        entries.clear()
    elif mutation == "two-entries":
        entries.append(copy.deepcopy(entries[0]))
    elif mutation == "kind":
        cast(dict[str, object], entries[0]["kindVersion"])["kind"] = "intoto"
    elif mutation == "global-index":
        entries[0]["logIndex"] = "01"
    else:
        proof = cast(dict[str, object], entries[0]["inclusionProof"])
        if mutation == "tree-index":
            proof["logIndex"] = "1"
        elif mutation == "tree-size":
            proof["treeSize"] = "0"
        elif mutation == "too-many-hashes":
            proof["hashes"] = [
                base64.b64encode(b"h" * 32).decode()
                for _ in range(verifier.MAX_TLOG_PROOF_HASHES + 1)
            ]
        elif mutation == "bad-checkpoint":
            proof["checkpoint"] = {}
        else:
            body = base64.b64decode(cast(str, entries[0]["canonicalizedBody"]))
            entries[0]["canonicalizedBody"] = base64.b64encode(body + b"\n").decode()
    with pytest.raises(verifier.BlobVerificationError, match=message):
        verifier.validate_bundle(
            bundle_bytes(changed),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


@pytest.mark.parametrize(
    "field",
    [
        ("messageSignature", "signature"),
        ("verificationMaterial", "certificate", "rawBytes"),
        ("verificationMaterial", "tlogEntries", 0, "canonicalizedBody"),
        (
            "verificationMaterial",
            "tlogEntries",
            0,
            "inclusionPromise",
            "signedEntryTimestamp",
        ),
    ],
)
def test_rejects_malformed_base64(tmp_path: Path, field: tuple[object, ...]) -> None:
    fixture = make_fixture(tmp_path)
    changed_bundle = copy.deepcopy(fixture.bundle)
    changed: Any = changed_bundle
    for key in field[:-1]:
        changed = changed[key]
    changed[field[-1]] = "not-base64!"
    with pytest.raises(verifier.BlobVerificationError, match="base64"):
        verifier.validate_bundle(
            bundle_bytes(changed_bundle),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


def test_rejects_duplicate_json_keys_and_oversized_bundle(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    with pytest.raises(verifier.BlobVerificationError, match="strict bounded JSON"):
        verifier.validate_bundle(
            b'{"mediaType":"a","mediaType":"b"}',
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )
    with pytest.raises(verifier.BlobVerificationError, match="byte bound"):
        verifier.validate_bundle(
            b"x" * (verifier.MAX_BUNDLE_BYTES + 1),
            fixture.plan,
            fixture.workflow,
            selected_asset(fixture),
        )


def test_rejects_record_disagreement_and_wrong_trusted_manifest(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    with pytest.raises(verifier.BlobVerificationError, match="trusted SHA-256"):
        verifier.verify_blob_signature(
            fixture.plan,
            fixture.workflow,
            fixture.acquired,
            expected_manifest_sha256="f" * 64,
            asset_root=fixture.root,
            asset_name=ASSET_NAME,
            client=FakeCosign(),
        )
    changed_workflow = dataclasses.replace(fixture.workflow, owner_id=OWNER_ID + 1)
    with pytest.raises(verifier.BlobVerificationError, match="different repository owners"):
        verifier.verify_blob_signature(
            fixture.plan,
            changed_workflow,
            fixture.acquired,
            expected_manifest_sha256=fixture.plan.manifest_sha256,
            asset_root=fixture.root,
            asset_name=ASSET_NAME,
            client=FakeCosign(),
        )
    changed_release = dataclasses.replace(
        fixture.workflow,
        authenticated_release_sha256="f" * 64,
    )
    with pytest.raises(verifier.BlobVerificationError, match="different authenticated releases"):
        verifier.verify_blob_signature(
            fixture.plan,
            changed_release,
            fixture.acquired,
            expected_manifest_sha256=fixture.plan.manifest_sha256,
            asset_root=fixture.root,
            asset_name=ASSET_NAME,
            client=FakeCosign(),
        )


def test_rejects_missing_derived_bundle_in_manifest(tmp_path: Path) -> None:
    contents = {ASSET_NAME: ASSET_BYTES}
    plan = release_plan(contents)
    workflow_path, workflow_sha = write_record(
        tmp_path / "workflow.json",
        workflow_record_value(plan),
    )
    acquisition_path, acquisition_sha = write_record(
        tmp_path / "acquisition.json",
        acquisition_record_value(plan),
    )
    workflow = actions_provenance.load_authenticated_workflow(
        workflow_path,
        expected_sha256=workflow_sha,
        plan=plan,
    )
    acquired = actions_provenance.load_acquired_assets(
        acquisition_path,
        expected_sha256=acquisition_sha,
        plan=plan,
    )
    root = tmp_path / "assets"
    root.mkdir(mode=0o700)
    (root / ASSET_NAME).write_bytes(ASSET_BYTES)
    (root / ASSET_NAME).chmod(0o600)
    with pytest.raises(verifier.BlobVerificationError, match="derived Sigstore bundle"):
        verifier.verify_blob_signature(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256=plan.manifest_sha256,
            asset_root=root,
            asset_name=ASSET_NAME,
            client=FakeCosign(),
        )


@pytest.mark.parametrize("target", [ASSET_NAME, BUNDLE_NAME])
def test_rejects_local_file_mutation_during_cosign(tmp_path: Path, target: str) -> None:
    fixture = make_fixture(tmp_path)

    def mutate() -> None:
        (fixture.root / target).write_bytes(b"changed")

    with pytest.raises(actions_provenance.ProvenanceVerificationError, match="acquired asset"):
        verify(fixture, FakeCosign(mutation=mutate))


@pytest.mark.parametrize("target", [ASSET_NAME, BUNDLE_NAME])
def test_rejects_unsafe_local_file_mode(tmp_path: Path, target: str) -> None:
    fixture = make_fixture(tmp_path)
    (fixture.root / target).chmod(0o644)
    with pytest.raises(
        actions_provenance.ProvenanceVerificationError, match="unsafe local identity"
    ):
        verify(fixture)


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


def version_record(version: str = "v3.0.6") -> dict[str, object]:
    return {
        "buildDate": "2026-04-06T22:29:24Z",
        "compiler": "gc",
        "gitCommit": "f" * 40,
        "gitTreeState": "clean",
        "gitVersion": version,
        "goVersion": "go1.25.7",
        "platform": "linux/amd64",
    }


def test_cosign_cli_uses_exact_argv_and_minimized_environment(tmp_path: Path) -> None:
    log = tmp_path / "log.json"
    executable = cosign_script(
        tmp_path,
        "import json, os, pathlib, sys\n"
        f"log = pathlib.Path({str(log)!r})\n"
        "if sys.argv[1:] == ['version', '--json']:\n"
        f"    print(json.dumps({version_record()!r}, separators=(',', ':')))\n"
        "else:\n"
        "    log.write_text(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}))\n"
        "    print('Verified OK')\n",
    )
    home = cosign_home(tmp_path)
    client = verifier.CosignCLI(
        executable=str(executable),
        home=home,
        environment={
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret",
            "GH_TOKEN": "secret",
            "GITHUB_TOKEN": "secret",
            "HOME": "/untrusted",
            "PATH": os.environ["PATH"],
            "SIGSTORE_NO_CACHE": "1",
        },
    )
    assert client.check_version() == "3.0.6"
    blob = (tmp_path / "blob").absolute()
    bundle = (tmp_path / "bundle").absolute()
    client.verify_blob(
        blob,
        bundle=bundle,
        certificate_identity=signer_identity(),
        workflow_ref=f"refs/tags/{TAG}",
        workflow_sha=COMMIT,
        repository=REPOSITORY,
    )
    observed = json.loads(log.read_text())
    assert observed["argv"] == [
        "verify-blob",
        "--bundle",
        str(bundle),
        "--certificate-identity",
        signer_identity(),
        "--certificate-oidc-issuer",
        verifier.OIDC_ISSUER,
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
        str(blob),
    ]
    environment = observed["env"]
    assert environment["HOME"] == str(home)
    assert environment["XDG_CACHE_HOME"] == str(home / ".cache")
    assert "GH_TOKEN" not in environment
    assert "GITHUB_TOKEN" not in environment
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in environment
    assert "SIGSTORE_NO_CACHE" not in environment


@pytest.mark.parametrize("version", ["v2.6.2", "v3.0.3", "v4.0.0", "latest"])
def test_cosign_cli_rejects_unsupported_versions(tmp_path: Path, version: str) -> None:
    executable = cosign_script(
        tmp_path,
        f"import json\nprint(json.dumps({version_record(version)!r}, separators=(',', ':')))\n",
    )
    client = verifier.CosignCLI(
        executable=str(executable),
        home=cosign_home(tmp_path),
    )
    with pytest.raises(verifier.BlobVerificationError, match="Cosign"):
        client.check_version()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"gitTreeState": "dirty"}, "build identity"),
        ({"gitCommit": "short"}, "build identity"),
        ({"platform": "darwin/amd64"}, "build identity"),
        ({"compiler": "gccgo"}, "build identity"),
        ({"buildDate": "today"}, "build identity"),
    ],
)
def test_cosign_cli_rejects_untrusted_build_identity(
    tmp_path: Path,
    change: dict[str, object],
    message: str,
) -> None:
    record = version_record()
    record.update(change)
    executable = cosign_script(
        tmp_path,
        f"import json\nprint(json.dumps({record!r}, separators=(',', ':')))\n",
    )
    client = verifier.CosignCLI(
        executable=str(executable),
        home=cosign_home(tmp_path),
    )
    with pytest.raises(verifier.BlobVerificationError, match=message):
        client.check_version()


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("print('unexpected success')\n", "unexpected success"),
        ("import sys\nsys.exit(7)\n", "exit status 7"),
        ("print('x' * 2000)\n", "output exceeds"),
    ],
)
def test_cosign_cli_rejects_bad_command_results(
    tmp_path: Path,
    body: str,
    message: str,
) -> None:
    client = verifier.CosignCLI(
        executable=str(cosign_script(tmp_path, body)),
        home=cosign_home(tmp_path),
    )
    with pytest.raises(verifier.BlobVerificationError, match=message):
        client.verify_blob(
            (tmp_path / "blob").absolute(),
            bundle=(tmp_path / "bundle").absolute(),
            certificate_identity=signer_identity(),
            workflow_ref=f"refs/tags/{TAG}",
            workflow_sha=COMMIT,
            repository=REPOSITORY,
        )


def test_cosign_cli_enforces_timeout(tmp_path: Path) -> None:
    client = verifier.CosignCLI(
        executable=str(
            cosign_script(
                tmp_path,
                "import time\ntime.sleep(2)\n",
            )
        ),
        home=cosign_home(tmp_path),
        timeout=0.05,
    )
    with pytest.raises(verifier.BlobVerificationError, match="timed out"):
        client.verify_blob(
            (tmp_path / "blob").absolute(),
            bundle=(tmp_path / "bundle").absolute(),
            certificate_identity=signer_identity(),
            workflow_ref=f"refs/tags/{TAG}",
            workflow_sha=COMMIT,
            repository=REPOSITORY,
        )


@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_cosign_home_must_be_private(tmp_path: Path, mode: int) -> None:
    home = cosign_home(tmp_path)
    home.chmod(mode)
    with pytest.raises(verifier.BlobVerificationError, match="mode-0700"):
        verifier.CosignCLI(executable="/bin/true", home=home)


def test_main_help_and_import_are_inert() -> None:
    script = Path(__file__).parents[1] / ".github" / "scripts" / "verify_blob_signature.py"
    imported = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed script
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            (
                "import importlib.util,sys;"
                f"p={str(script)!r};"
                "s=importlib.util.spec_from_file_location('blob_verifier_import',p);"
                "m=importlib.util.module_from_spec(s);"
                "sys.modules[s.name]=m;"
                "s.loader.exec_module(m)"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert imported.returncode == 0, imported.stderr
    assert imported.stdout == ""
    assert imported.stderr == ""
    help_result = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed script
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0
    assert "--cosign-home" in help_result.stdout
    assert "--asset-name" in help_result.stdout


def test_verifier_remains_unwired_and_documented() -> None:
    root = Path(__file__).parents[1]
    script = ".github/scripts/verify_blob_signature.py"
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    occurrences = 0
    for workflow in workflows:
        source = workflow.read_text(encoding="utf-8")
        occurrences += source.count(script)
        assert f"python {script}" not in source
        assert f"python3 {script}" not in source
        assert f"mise exec -- python -I -B {script}" not in source
    assert occurrences == 2

    source = (root / script).read_text(encoding="utf-8")
    for forbidden in (
        "release create",
        "release edit",
        "release upload",
        "attestation sign",
        "api --method POST",
        "api --method PATCH",
        "api --method DELETE",
        "--insecure-ignore-sct",
        "--insecure-ignore-tlog",
    ):
        assert forbidden not in source
    assert '"publication_allowed": False' in source

    reference = (root / "docs/reference/authenticated-blob-signature.md").read_text(
        encoding="utf-8"
    )
    how_to = (root / "docs/how-to/verify-container-release-evidence.md").read_text(encoding="utf-8")
    contract = (root / "docs/reference/container-evidence-release-contract.md").read_text(
        encoding="utf-8"
    )
    navigation = (root / "mkdocs.yml").read_text(encoding="utf-8")
    for option in (
        "--manifest",
        "--manifest-sha256",
        "--authenticated-workflow-record",
        "--authenticated-workflow-record-sha256",
        "--acquisition-record",
        "--acquisition-record-sha256",
        "--asset-root",
        "--asset-name",
        "--cosign-home",
        "--cosign",
        "--timeout-seconds",
    ):
        assert option in reference
    assert ".github/scripts/verify_blob_signature.py" in how_to
    assert "mise exec -- python -I -B" in how_to
    assert "3.0.6" in reference
    assert "GHSA-whqx-f9j3-ch6m" in reference
    assert "`publication_allowed`" in reference
    assert "decide which release assets must be signed" in reference
    assert "No release workflow calls this command" in reference
    assert "Current blob-signature verifier" in contract
    assert "authenticated-blob-signature.md" in navigation
