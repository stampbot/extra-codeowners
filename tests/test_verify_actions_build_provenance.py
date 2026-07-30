"""Adversarial tests for GitHub Actions build-provenance verification."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


controller: Any = load_script("release_controller")
github_release: Any = load_script("verify_github_release")
acquisition: Any = load_script("acquire_github_release_assets")
workflow_verifier: Any = load_script("verify_release_workflow")
verifier: Any = load_script("verify_actions_build_provenance")

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
ASSET_CONTENT = {
    "extra-codeowners-0.1.0.tgz": b"chart",
    "extra_codeowners-0.1.0.tar.gz": b"source",
}


def manifest_value() -> dict[str, object]:
    return {
        "assets": [
            {
                "name": name,
                "path": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for name, content in ASSET_CONTENT.items()
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


def release_plan(value: dict[str, object] | None = None) -> Any:
    manifest = manifest_value() if value is None else value
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


def load_inputs(
    tmp_path: Path,
    plan: Any,
    *,
    workflow_value: dict[str, object] | None = None,
    acquisition_value: dict[str, object] | None = None,
) -> tuple[Any, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    workflow_path, workflow_sha = write_record(
        tmp_path / "workflow.json",
        workflow_record_value(plan) if workflow_value is None else workflow_value,
    )
    acquisition_path, acquisition_sha = write_record(
        tmp_path / "acquisition.json",
        acquisition_record_value(plan) if acquisition_value is None else acquisition_value,
    )
    return (
        verifier.load_authenticated_workflow(
            workflow_path,
            expected_sha256=workflow_sha,
            plan=plan,
        ),
        verifier.load_acquired_assets(
            acquisition_path,
            expected_sha256=acquisition_sha,
            plan=plan,
        ),
    )


def make_asset_root(tmp_path: Path, plan: Any) -> Path:
    root = tmp_path / "assets"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    for asset in plan.assets:
        path = root / asset.name
        path.write_bytes(ASSET_CONTENT[asset.name])
        path.chmod(0o600)
    return root


def signer_identity() -> str:
    return f"https://github.com/{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/{TAG}"


def run_invocation(attempt: int = RUN_ATTEMPT) -> str:
    return f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{attempt}"


def statement_value(asset_name: str) -> dict[str, object]:
    subjects = [
        {
            "digest": {"sha256": hashlib.sha256(content).hexdigest()},
            "name": name,
        }
        for name, content in ASSET_CONTENT.items()
    ]
    repository_url = f"https://github.com/{REPOSITORY}"
    return {
        "_type": github_release.STATEMENT_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": verifier.BUILD_TYPE,
                "externalParameters": {
                    "workflow": {
                        "path": WORKFLOW_PATH,
                        "ref": f"refs/tags/{TAG}",
                        "repository": repository_url,
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": "push",
                        "repository_id": str(REPOSITORY_ID),
                        "repository_owner_id": str(OWNER_ID),
                        "runner_environment": "github-hosted",
                    }
                },
                "resolvedDependencies": [
                    {
                        "digest": {"gitCommit": COMMIT},
                        "uri": f"git+{repository_url}@refs/tags/{TAG}",
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": signer_identity()},
                "metadata": {"invocationId": run_invocation()},
            },
        },
        "predicateType": verifier.PREDICATE_TYPE,
        "subject": subjects,
    }


def certificate_value() -> dict[str, object]:
    identity = signer_identity()
    repository_url = f"https://github.com/{REPOSITORY}"
    return {
        "buildConfigDigest": COMMIT,
        "buildConfigURI": identity,
        "buildSignerDigest": COMMIT,
        "buildSignerURI": identity,
        "buildTrigger": "push",
        "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
        "githubWorkflowName": "Release",
        "githubWorkflowRef": f"refs/tags/{TAG}",
        "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowSHA": COMMIT,
        "githubWorkflowTrigger": "push",
        "issuer": verifier.OIDC_ISSUER,
        "runInvocationURI": run_invocation(),
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryDigest": COMMIT,
        "sourceRepositoryIdentifier": str(REPOSITORY_ID),
        "sourceRepositoryOwnerIdentifier": str(OWNER_ID),
        "sourceRepositoryOwnerURI": "https://github.com/stampbot",
        "sourceRepositoryRef": f"refs/tags/{TAG}",
        "sourceRepositoryURI": repository_url,
        "sourceRepositoryVisibilityAtSigning": "public",
        "subjectAlternativeName": identity,
    }


def attestation_value(asset_name: str) -> dict[str, object]:
    statement = statement_value(asset_name)
    payload = controller.canonical_json(statement).rstrip(b"\n")
    return {
        "attestation": {
            "bundle": {
                "dsseEnvelope": {
                    "payload": base64.b64encode(payload).decode("ascii"),
                    "payloadType": github_release.DSSE_PAYLOAD_TYPE,
                    "signatures": [{"sig": "verified-by-gh"}],
                },
                "mediaType": github_release.SIGSTORE_BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {
                    "certificate": {"rawBytes": "certificate"},
                    "timestampVerificationData": {"rfc3161Timestamps": []},
                    "tlogEntries": [{"logIndex": "1"}],
                },
            },
            "bundle_url": "",
            "initiator": "",
        },
        "verificationResult": {
            "mediaType": github_release.VERIFICATION_RESULT_MEDIA_TYPE,
            "signature": {"certificate": certificate_value()},
            "statement": statement,
            "verifiedIdentity": {
                "issuer": {"issuer": "", "regexp": ".*"},
                "runnerEnvironment": "github-hosted",
                "subjectAlternativeName": {
                    "subjectAlternativeName": signer_identity(),
                },
            },
            "verifiedTimestamps": [
                {
                    "timestamp": "2026-07-02T16:29:15-05:00",
                    "type": "Tlog",
                    "uri": "https://rekor.sigstore.dev",
                }
            ],
        },
    }


def set_nested(target: dict[str, Any], path: tuple[str, ...], value: object) -> None:
    current = target
    for component in path[:-1]:
        current = cast(dict[str, Any], current[component])
    current[path[-1]] = value


def replace_statement(
    attestation: dict[str, object],
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    verification = cast(dict[str, Any], attestation["verificationResult"])
    statement = cast(dict[str, Any], copy.deepcopy(verification["statement"]))
    mutate(statement)
    payload = controller.canonical_json(statement).rstrip(b"\n")
    verification["statement"] = statement
    bundle = cast(dict[str, Any], cast(dict[str, Any], attestation["attestation"])["bundle"])
    envelope = cast(dict[str, Any], bundle["dsseEnvelope"])
    envelope["payload"] = base64.b64encode(payload).decode("ascii")


class FakeClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.events: list[tuple[object, ...]] = []
        self.version = "2.96.0"
        self.before_verify: Callable[[Path], None] | None = None

    def check_version(self) -> str:
        self.events.append(("version",))
        return self.version

    def verify_attestation(self, artifact: Path, **kwargs: object) -> object:
        self.events.append(("verify", artifact, kwargs))
        if self.before_verify is not None:
            self.before_verify(artifact)
        return copy.deepcopy(self.response)


def verify(
    tmp_path: Path,
    *,
    asset_name: str = "extra-codeowners-0.1.0.tgz",
    response: object | None = None,
) -> tuple[dict[str, object], FakeClient, Path, Any, Any, Any]:
    plan = release_plan()
    workflow, acquired = load_inputs(tmp_path / "records", plan)
    root = make_asset_root(tmp_path, plan)
    client = FakeClient(
        [attestation_value(asset_name)] if response is None else response,
    )
    result = verifier.verify_actions_build_provenance(
        plan,
        workflow,
        acquired,
        expected_manifest_sha256=plan.manifest_sha256,
        asset_root=root,
        asset_name=asset_name,
        client=client,
    )
    return cast(dict[str, object], result), client, root, plan, workflow, acquired


def test_verifies_exact_asset_provenance_and_emits_blocked_record(tmp_path: Path) -> None:
    asset_name = "extra-codeowners-0.1.0.tgz"
    result, client, root, plan, workflow, acquired = verify(tmp_path, asset_name=asset_name)
    asset = next(item for item in plan.assets if item.name == asset_name)
    payload = controller.canonical_json(statement_value(asset_name)).rstrip(b"\n")

    assert result == {
        "acquired_assets": {"sha256": acquired.record_sha256},
        "asset": {
            "github_asset_id": 700,
            "name": asset.name,
            "path": asset.name,
            "sha256": asset.sha256,
            "size": asset.size,
        },
        "attestation": {
            "bundle_media_type": github_release.SIGSTORE_BUNDLE_MEDIA_TYPE,
            "predicate_type": verifier.PREDICATE_TYPE,
            "statement_payload_sha256": hashlib.sha256(payload).hexdigest(),
            "subject_count": 2,
            "verification_media_type": github_release.VERIFICATION_RESULT_MEDIA_TYPE,
            "verified_timestamp_count": 1,
        },
        "authenticated_release": {"sha256": AUTHENTICATED_RELEASE_SHA256},
        "authenticated_workflow": {"sha256": workflow.record_sha256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": verifier.RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
        },
        "schema_version": 1,
        "tag": {"name": TAG, "target_commit": COMMIT},
        "workflow": {
            "file_sha256": WORKFLOW_SHA256,
            "id": WORKFLOW_ID,
            "path": WORKFLOW_PATH,
            "ref": f"refs/tags/{TAG}",
            "run_attempt": RUN_ATTEMPT,
            "run_id": RUN_ID,
            "sha": COMMIT,
            "signer_identity": signer_identity(),
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        },
    }
    assert controller.canonical_json(result).endswith(b"\n")
    assert client.events[0] == ("version",)
    event = client.events[1]
    assert event[0] == "verify"
    assert event[1] == root / asset_name
    assert event[2] == {
        "certificate_identity": signer_identity(),
        "limit": 30,
        "predicate_type": verifier.PREDICATE_TYPE,
        "repository": REPOSITORY,
        "signer_digest": COMMIT,
        "source_digest": COMMIT,
        "source_ref": f"refs/tags/{TAG}",
    }


def test_same_inputs_produce_same_record(tmp_path: Path) -> None:
    first = verify(tmp_path / "first")[0]
    second = verify(tmp_path / "second")[0]
    assert first == second
    assert controller.canonical_json(first) == controller.canonical_json(second)


@pytest.mark.parametrize(
    ("record_name", "path", "value", "message"),
    [
        ("workflow", ("publication_allowed",), True, "publication"),
        ("workflow", ("repository", "owner_id"), OWNER_ID + 1, "owner"),
        ("workflow", ("workflow", "run_attempt"), 0, "integer"),
        ("workflow", ("workflow", "ref"), "refs/heads/main", "identity"),
        ("workflow", ("workflow", "file", "sha256"), "invalid", "SHA-256"),
        ("acquisition", ("publication_allowed",), True, "publication"),
        ("acquisition", ("repository", "id"), REPOSITORY_ID + 1, "repository"),
        (
            "acquisition",
            ("authenticated_release", "sha256"),
            "f" * 64,
            "different authenticated releases",
        ),
        ("acquisition", ("assets", "0", "path"), "../asset", "inventory"),
        ("acquisition", ("assets", "0", "github_asset_id"), True, "integer"),
    ],
)
def test_rejects_input_record_drift(
    tmp_path: Path,
    record_name: str,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    plan = release_plan()
    workflow_value = workflow_record_value(plan)
    acquisition_value = acquisition_record_value(plan)
    target = workflow_value if record_name == "workflow" else acquisition_value
    current: Any = target
    for component in path[:-1]:
        current = current[int(component)] if component.isdecimal() else current[component]
    current[path[-1]] = value

    if "different authenticated releases" in message or (
        record_name == "workflow" and path == ("repository", "owner_id")
    ):
        workflow, acquired = load_inputs(
            tmp_path / "records",
            plan,
            workflow_value=workflow_value,
            acquisition_value=acquisition_value,
        )
        root = make_asset_root(tmp_path, plan)
        with pytest.raises(verifier.ProvenanceVerificationError, match=message):
            verifier.verify_actions_build_provenance(
                plan,
                workflow,
                acquired,
                expected_manifest_sha256=plan.manifest_sha256,
                asset_root=root,
                asset_name=plan.assets[0].name,
                client=FakeClient([attestation_value(plan.assets[0].name)]),
            )
    else:
        with pytest.raises(verifier.ProvenanceVerificationError, match=message):
            load_inputs(
                tmp_path / "records",
                plan,
                workflow_value=workflow_value,
                acquisition_value=acquisition_value,
            )


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (
            (
                "verificationResult",
                "verifiedIdentity",
                "subjectAlternativeName",
                "subjectAlternativeName",
            ),
            "https://github.com/stampbot/extra-codeowners/.github/workflows/release.yml.evil"
            "@refs/tags/v0.1.0",
            "verified identity",
        ),
        (
            ("verificationResult", "signature", "certificate", "subjectAlternativeName"),
            "https://github.com/stampbot/other/.github/workflows/release.yml@refs/tags/v0.1.0",
            "certificate",
        ),
        (
            ("verificationResult", "signature", "certificate", "issuer"),
            "https://issuer.example",
            "certificate",
        ),
        (
            ("verificationResult", "signature", "certificate", "githubWorkflowSHA"),
            "f" * 40,
            "certificate",
        ),
        (
            ("verificationResult", "signature", "certificate", "sourceRepositoryIdentifier"),
            str(REPOSITORY_ID + 1),
            "certificate",
        ),
        (
            ("verificationResult", "signature", "certificate", "runnerEnvironment"),
            "self-hosted",
            "certificate",
        ),
        (
            (
                "verificationResult",
                "signature",
                "certificate",
                "sourceRepositoryVisibilityAtSigning",
            ),
            "unknown",
            "visibility",
        ),
    ],
)
def test_rejects_verified_identity_and_certificate_drift(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    attestation = attestation_value("extra-codeowners-0.1.0.tgz")
    set_nested(cast(dict[str, Any], attestation), path, value)
    with pytest.raises(verifier.ProvenanceVerificationError, match=message):
        verify(tmp_path, response=[attestation])


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (
            ("predicate", "buildDefinition", "buildType"),
            "https://example.com/build",
            "build type",
        ),
        (
            ("predicate", "buildDefinition", "externalParameters", "workflow", "path"),
            ".github/workflows/other.yml",
            "different workflow",
        ),
        (
            (
                "predicate",
                "buildDefinition",
                "internalParameters",
                "github",
                "repository_owner_id",
            ),
            str(OWNER_ID + 1),
            "GitHub parameters",
        ),
        (
            (
                "predicate",
                "buildDefinition",
                "resolvedDependencies",
                "0",
                "digest",
                "gitCommit",
            ),
            "f" * 40,
            "resolved dependency",
        ),
        (
            ("predicate", "runDetails", "builder", "id"),
            "https://github.com/stampbot/other/.github/workflows/release.yml",
            "run details",
        ),
    ],
)
def test_rejects_slsa_statement_identity_drift(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    attestation = attestation_value("extra-codeowners-0.1.0.tgz")

    def mutate(statement: dict[str, Any]) -> None:
        current: Any = statement
        for component in path[:-1]:
            current = current[int(component)] if component.isdecimal() else current[component]
        current[path[-1]] = value

    replace_statement(attestation, mutate)
    with pytest.raises(verifier.ProvenanceVerificationError, match=message):
        verify(tmp_path, response=[attestation])


def test_selects_only_exact_authenticated_run_attempt(tmp_path: Path) -> None:
    asset_name = "extra-codeowners-0.1.0.tgz"
    old = attestation_value(asset_name)
    set_nested(
        cast(dict[str, Any], old),
        ("verificationResult", "signature", "certificate", "runInvocationURI"),
        run_invocation(1),
    )

    def old_statement(statement: dict[str, Any]) -> None:
        statement["predicate"]["runDetails"]["metadata"]["invocationId"] = run_invocation(1)

    replace_statement(old, old_statement)
    result = verify(
        tmp_path,
        asset_name=asset_name,
        response=[old, attestation_value(asset_name)],
    )[0]
    assert cast(dict[str, object], result["workflow"])["run_attempt"] == RUN_ATTEMPT


@pytest.mark.parametrize("responses", ["missing", "duplicate"])
def test_rejects_missing_or_ambiguous_run_attempt(
    tmp_path: Path,
    responses: str,
) -> None:
    asset_name = "extra-codeowners-0.1.0.tgz"
    current = attestation_value(asset_name)
    if responses == "duplicate":
        values = [current, copy.deepcopy(current)]
    else:
        old = current
        set_nested(
            cast(dict[str, Any], old),
            ("verificationResult", "signature", "certificate", "runInvocationURI"),
            run_invocation(1),
        )

        def old_statement(statement: dict[str, Any]) -> None:
            statement["predicate"]["runDetails"]["metadata"]["invocationId"] = run_invocation(1)

        replace_statement(old, old_statement)
        values = [old]
    with pytest.raises(verifier.ProvenanceVerificationError, match="run attempt exactly once"):
        verify(tmp_path, asset_name=asset_name, response=values)


def test_rejects_subject_tampering_and_payload_disagreement(tmp_path: Path) -> None:
    asset_name = "extra-codeowners-0.1.0.tgz"
    missing = attestation_value(asset_name)

    def remove_selected(statement: dict[str, Any]) -> None:
        statement["subject"] = [item for item in statement["subject"] if item["name"] != asset_name]

    replace_statement(missing, remove_selected)
    with pytest.raises(verifier.ProvenanceVerificationError, match="selected asset"):
        verify(tmp_path / "missing", asset_name=asset_name, response=[missing])

    disagreement = attestation_value(asset_name)
    verification = cast(dict[str, Any], disagreement["verificationResult"])
    verification["statement"] = statement_value(asset_name)
    cast(dict[str, Any], verification["statement"])["subject"] = []
    with pytest.raises(verifier.ProvenanceVerificationError, match="does not match"):
        verify(tmp_path / "disagreement", asset_name=asset_name, response=[disagreement])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("retained-metadata", "API metadata"),
        ("bundle-type", "bundle type"),
        ("payload-type", "payload type"),
        ("signatures", "signature count"),
        ("base64", "canonical base64"),
        ("timestamps", "no verified timestamp"),
        ("timestamp-uri", "invalid timestamp"),
    ],
)
def test_rejects_malformed_attestation_envelope(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    asset_name = "extra-codeowners-0.1.0.tgz"
    attestation = attestation_value(asset_name)
    value = cast(dict[str, Any], attestation)
    if mutation == "retained-metadata":
        set_nested(value, ("attestation", "initiator"), "user")
    elif mutation == "bundle-type":
        set_nested(value, ("attestation", "bundle", "mediaType"), "application/json")
    elif mutation == "payload-type":
        set_nested(
            value,
            ("attestation", "bundle", "dsseEnvelope", "payloadType"),
            "text/plain",
        )
    elif mutation == "signatures":
        set_nested(value, ("attestation", "bundle", "dsseEnvelope", "signatures"), [])
    elif mutation == "base64":
        set_nested(value, ("attestation", "bundle", "dsseEnvelope", "payload"), "!!!!")
    elif mutation == "timestamps":
        set_nested(value, ("verificationResult", "verifiedTimestamps"), [])
    elif mutation == "timestamp-uri":
        set_nested(
            value,
            ("verificationResult", "verifiedTimestamps"),
            [{"timestamp": "now", "type": "Tlog", "uri": "http://rekor.example"}],
        )
    with pytest.raises(verifier.ProvenanceVerificationError, match=message):
        verify(tmp_path, asset_name=asset_name, response=[attestation])


def test_rejects_duplicate_keys_and_invalid_result_counts(tmp_path: Path) -> None:
    asset_name = "extra-codeowners-0.1.0.tgz"
    duplicate = attestation_value(asset_name)
    payload = (
        b'{"_type":"https://in-toto.io/Statement/v1",'
        b'"_type":"https://in-toto.io/Statement/v1",'
        b'"predicate":{},"predicateType":"https://slsa.dev/provenance/v1","subject":[]}'
    )
    set_nested(
        cast(dict[str, Any], duplicate),
        ("attestation", "bundle", "dsseEnvelope", "payload"),
        base64.b64encode(payload).decode("ascii"),
    )
    with pytest.raises(verifier.ProvenanceVerificationError, match="strict bounded JSON"):
        verify(tmp_path / "duplicate", asset_name=asset_name, response=[duplicate])

    for label, response in (
        ("empty", []),
        (
            "oversized",
            [attestation_value(asset_name) for _ in range(verifier.ATTESTATION_LIMIT + 1)],
        ),
    ):
        with pytest.raises(verifier.ProvenanceVerificationError, match="result count"):
            verify(tmp_path / label, asset_name=asset_name, response=response)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("relative-root", "absolute"),
        ("root-mode", "mode-0700"),
        ("extra-entry", "unexpected"),
        ("file-mode", "unsafe local identity"),
        ("file-symlink", "unsafe local identity"),
        ("wrong-bytes", "wrong SHA-256"),
    ],
)
def test_rejects_unsafe_or_changed_asset_tree(
    tmp_path: Path,
    mutation: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = release_plan()
    workflow, acquired = load_inputs(tmp_path / "records", plan)
    root = make_asset_root(tmp_path, plan)
    asset = plan.assets[0]
    if mutation == "relative-root":
        monkeypatch.chdir(tmp_path)
        root = Path("assets")
    elif mutation == "root-mode":
        root.chmod(0o755)
    elif mutation == "extra-entry":
        extra = root / "extra"
        extra.write_bytes(b"x")
        extra.chmod(0o600)
    elif mutation == "file-mode":
        (root / asset.name).chmod(0o644)
    elif mutation == "file-symlink":
        path = root / asset.name
        path.unlink()
        path.symlink_to(root / plan.assets[1].name)
    elif mutation == "wrong-bytes":
        (root / asset.name).write_bytes(b"x" * asset.size)

    with pytest.raises(verifier.ProvenanceVerificationError, match=message):
        verifier.verify_actions_build_provenance(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256=plan.manifest_sha256,
            asset_root=root,
            asset_name=asset.name,
            client=FakeClient([attestation_value(asset.name)]),
        )


def test_rejects_asset_mutation_during_external_verification(tmp_path: Path) -> None:
    plan = release_plan()
    workflow, acquired = load_inputs(tmp_path / "records", plan)
    root = make_asset_root(tmp_path, plan)
    asset = plan.assets[0]
    client = FakeClient([attestation_value(asset.name)])

    def mutate(path: Path) -> None:
        path.write_bytes(ASSET_CONTENT[asset.name])
        path.chmod(0o600)

    client.before_verify = mutate
    with pytest.raises(verifier.ProvenanceVerificationError, match="changed"):
        verifier.verify_actions_build_provenance(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256=plan.manifest_sha256,
            asset_root=root,
            asset_name=asset.name,
            client=client,
        )


def test_rejects_untrusted_manifest_and_unselected_asset_before_cli(tmp_path: Path) -> None:
    plan = release_plan()
    workflow, acquired = load_inputs(tmp_path / "records", plan)
    root = make_asset_root(tmp_path, plan)
    client = FakeClient([attestation_value(plan.assets[0].name)])
    with pytest.raises(verifier.ProvenanceVerificationError, match="trusted SHA-256"):
        verifier.verify_actions_build_provenance(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256="f" * 64,
            asset_root=root,
            asset_name=plan.assets[0].name,
            client=client,
        )
    assert client.events == []

    with pytest.raises(verifier.ProvenanceVerificationError, match="not named exactly once"):
        verifier.verify_actions_build_provenance(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256=plan.manifest_sha256,
            asset_root=root,
            asset_name="not-an-asset",
            client=client,
        )
    assert client.events == []


def test_github_cli_uses_exact_identity_filters_not_prefix_workflow_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[str, ...]] = []

    def run_bounded(command: tuple[str, ...], **_kwargs: object) -> bytes:
        captured.append(command)
        return b"[]"

    monkeypatch.setattr(github_release, "_run_bounded", run_bounded)
    client = github_release.GitHubCLI(
        executable="/bin/true",
        environment={"PATH": os.environ["PATH"], "GH_TOKEN": "token"},
    )
    artifact = (tmp_path / "asset").resolve()
    assert (
        client.verify_attestation(
            artifact,
            repository=REPOSITORY,
            certificate_identity=signer_identity(),
            signer_digest=COMMIT,
            source_digest=COMMIT,
            source_ref=f"refs/tags/{TAG}",
            predicate_type=verifier.PREDICATE_TYPE,
            limit=30,
        )
        == []
    )

    command = captured[0]
    assert command[:4] == ("/bin/true", "attestation", "verify", str(artifact))
    assert "--cert-identity" in command
    assert "--cert-oidc-issuer" in command
    assert "--deny-self-hosted-runners" in command
    assert "--signer-workflow" not in command
    assert command[command.index("--cert-identity") + 1] == signer_identity()
    assert command[command.index("--limit") + 1] == "30"


def test_documented_isolated_python_invocation_loads_reviewed_siblings(
    tmp_path: Path,
) -> None:
    script = (
        Path(__file__).parents[1] / ".github" / "scripts" / "verify_actions_build_provenance.py"
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed script
        [sys.executable, "-I", "-B", str(script), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert "--authenticated-workflow-record-sha256" in result.stdout
    assert "--acquisition-record-sha256" in result.stdout
    assert "--asset-name" in result.stdout
    assert result.stderr == ""


def test_documentation_matches_provenance_verifier_and_nonclaims() -> None:
    root = Path(__file__).parents[1]
    reference = (root / "docs/reference/authenticated-actions-build-provenance.md").read_text(
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
        "--gh",
        "--timeout-seconds",
    ):
        assert option in reference
    assert ".github/scripts/verify_actions_build_provenance.py" in how_to
    assert "mise exec -- python -I -B" in how_to
    assert "Attestations: read" in reference
    assert "Contents: read" in reference
    assert "2.93.0" in reference
    assert "2.96.0" in reference
    assert "`publication_allowed`" in reference
    assert "does not decide which release assets" in reference
    assert "Cosign blob signature" in reference
    assert "No release workflow calls it" in reference
    assert "Current Actions build-provenance verifier" in contract
    assert "authenticated-actions-build-provenance.md" in navigation


def test_provenance_verifier_remains_unwired_and_publication_disabled() -> None:
    root = Path(__file__).parents[1]
    script = ".github/scripts/verify_actions_build_provenance.py"
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    assert workflows
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
    ):
        assert forbidden not in source
    assert '"publication_allowed": False' in source


def test_asset_tree_permissions_fixture_is_exact(tmp_path: Path) -> None:
    plan = release_plan()
    root = make_asset_root(tmp_path, plan)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert all(stat.S_IMODE((root / asset.name).stat().st_mode) == 0o600 for asset in plan.assets)
