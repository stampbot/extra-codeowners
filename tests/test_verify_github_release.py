"""Adversarial tests for authenticated immutable GitHub release verification."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
verifier: Any = load_script("verify_github_release")

REPOSITORY = "stampbot/extra-codeowners"
REPOSITORY_ID = 1_299_090_885
OWNER_ID = 1_234_567
RELEASE_ID = 987_654_321
TAG = "v0.1.0"
COMMIT = "a" * 40
WORKFLOW_SHA = "b" * 40


def manifest_value() -> dict[str, object]:
    return {
        "assets": [
            {
                "name": "evidence-predicate-amd64.json",
                "path": "release/evidence-predicate-amd64.json",
                "sha256": "1" * 64,
                "size": 123,
            },
            {
                "name": "extra-codeowners-0.1.0-linux-amd64-evidence.tar.gz",
                "path": "release/extra-codeowners-0.1.0-linux-amd64-evidence.tar.gz",
                "sha256": "2" * 64,
                "size": 456,
            },
        ],
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "run_id": 445_566,
        "schema_version": 1,
        "tag": TAG,
        "target_commit": COMMIT,
        "workflow_path": ".github/workflows/release.yml",
        "workflow_sha": WORKFLOW_SHA,
    }


def release_plan() -> Any:
    value = manifest_value()
    raw = controller.canonical_json(value)
    return controller.validate_manifest(value, hashlib.sha256(raw).hexdigest())


def repository_response() -> dict[str, object]:
    return {
        "full_name": REPOSITORY,
        "id": REPOSITORY_ID,
        "owner": {"id": OWNER_ID, "login": "stampbot"},
    }


def tag_response() -> dict[str, object]:
    return {
        "object": {"sha": COMMIT, "type": "commit"},
        "ref": f"refs/tags/{TAG}",
    }


def release_response(plan: Any, release_id: int = RELEASE_ID) -> dict[str, object]:
    api_url = f"https://api.github.com/repos/{REPOSITORY}/releases/{release_id}"
    return {
        "assets_url": f"{api_url}/assets",
        "body": plan.marker,
        "draft": False,
        "html_url": f"https://github.com/{REPOSITORY}/releases/tag/{TAG}",
        "id": release_id,
        "immutable": True,
        "name": TAG,
        "prerelease": False,
        "tag_name": TAG,
        "target_commitish": COMMIT,
        "url": api_url,
    }


def asset_responses(plan: Any) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, asset in enumerate(plan.assets, start=1):
        asset_id = 80_000 + index
        result.append(
            {
                "browser_download_url": (
                    f"https://github.com/{REPOSITORY}/releases/download/{TAG}/{asset.name}"
                ),
                "content_type": "application/octet-stream",
                "digest": f"sha256:{asset.sha256}",
                "id": asset_id,
                "label": None,
                "name": asset.name,
                "size": asset.size,
                "state": "uploaded",
                "url": (f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}"),
            }
        )
    return result


def statement_value(plan: Any) -> dict[str, object]:
    return {
        "_type": verifier.STATEMENT_TYPE,
        "predicate": {
            "databaseId": str(RELEASE_ID),
            "ownerId": str(OWNER_ID),
            "packageId": str(REPOSITORY_ID),
            "purl": f"pkg:github/{REPOSITORY}@{TAG}",
            "repository": REPOSITORY,
            "repositoryId": str(REPOSITORY_ID),
            "tag": TAG,
        },
        "predicateType": verifier.RELEASE_PREDICATE_TYPE,
        "subject": [
            {
                "digest": {"sha1": COMMIT},
                "uri": f"pkg:github/{REPOSITORY}@{TAG}",
            },
            *[{"digest": {"sha256": asset.sha256}, "name": asset.name} for asset in plan.assets],
        ],
    }


def attestation_response(
    plan: Any,
    *,
    statement: Mapping[str, object] | None = None,
    raw_payload: bytes | None = None,
) -> dict[str, object]:
    verified_statement = dict(statement or statement_value(plan))
    payload = (
        raw_payload
        or json.dumps(
            verified_statement,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    return {
        "attestation": {
            "bundle": {
                "dsseEnvelope": {
                    "payload": base64.b64encode(payload).decode(),
                    "payloadType": verifier.DSSE_PAYLOAD_TYPE,
                    "signatures": [{"sig": "synthetic-signature"}],
                },
                "mediaType": verifier.SIGSTORE_BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {},
            },
            "bundle_url": "",
            "initiator": "",
        },
        "verificationResult": {
            "mediaType": verifier.VERIFICATION_RESULT_MEDIA_TYPE,
            "signature": {"certificate": {"issuer": "GitHub"}},
            "statement": verified_statement,
            "verifiedIdentity": {"subjectAlternativeName": {"regexp": "release"}},
            "verifiedTimestamps": [{"type": "TimestampAuthority"}],
        },
    }


@dataclass
class Sequential:
    values: list[object]


class FakeClient:
    def __init__(self, plan: Any) -> None:
        repository = verifier._repository_endpoint(REPOSITORY)
        release = verifier._release_endpoint(plan)
        release_by_id = verifier._release_id_endpoint(plan, RELEASE_ID)
        assets = verifier._assets_endpoint(plan, RELEASE_ID)
        tag = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
        self.responses: dict[str, object | Sequential] = {
            repository: repository_response(),
            tag: tag_response(),
            release: release_response(plan),
            release_by_id: release_response(plan),
            assets: asset_responses(plan),
        }
        self.attestation: object = attestation_response(plan)
        self.events: list[tuple[str, ...]] = []
        self.version = "2.96.0"

    def check_version(self) -> str:
        self.events.append(("version",))
        return self.version

    def api(self, endpoint: str) -> object:
        self.events.append(("api", endpoint))
        response = self.responses[endpoint]
        if isinstance(response, Sequential):
            assert response.values
            value = response.values.pop(0)
        else:
            value = response
        return copy.deepcopy(value)

    def verify_release(self, repository: str, tag: str) -> object:
        self.events.append(("verify", repository, tag))
        return copy.deepcopy(self.attestation)


def verify(client: FakeClient, plan: Any) -> Mapping[str, object]:
    return cast(
        Mapping[str, object],
        verifier.verify_github_release(
            plan,
            expected_manifest_sha256=plan.manifest_sha256,
            client=client,
        ),
    )


def attestation_statement(client: FakeClient) -> dict[str, Any]:
    response = client.attestation
    assert isinstance(response, dict)
    envelope = response["attestation"]["bundle"]["dsseEnvelope"]
    payload = base64.b64decode(envelope["payload"], validate=True)
    return cast(dict[str, Any], json.loads(payload))


def replace_attestation_statement(
    client: FakeClient,
    plan: Any,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    statement = attestation_statement(client)
    mutate(statement)
    client.attestation = attestation_response(plan, statement=statement)


def test_authenticates_exact_immutable_release_and_emits_deterministic_record() -> None:
    plan = release_plan()
    first_client = FakeClient(plan)
    second_client = FakeClient(plan)

    first = verify(first_client, plan)
    second = verify(second_client, plan)

    assert first == second
    assert first == {
        "assets": [
            {"name": asset.name, "sha256": asset.sha256, "size": asset.size}
            for asset in plan.assets
        ],
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": verifier.RECORD_KIND,
        "release": {
            "attestation_payload_sha256": hashlib.sha256(
                json.dumps(
                    statement_value(plan),
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
            "attestation_predicate_type": verifier.RELEASE_PREDICATE_TYPE,
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
    assert controller.canonical_json(first) == controller.canonical_json(second)
    assert first_client.events[0] == ("version",)
    assert first_client.events.count(("api", verifier._repository_endpoint(REPOSITORY))) == 2
    assert first_client.events.count(("verify", REPOSITORY, TAG)) == 1


def test_rejects_untrusted_manifest_before_any_github_operation() -> None:
    plan = release_plan()
    client = FakeClient(plan)

    with pytest.raises(verifier.VerificationError, match="trusted SHA-256"):
        verifier.verify_github_release(
            plan,
            expected_manifest_sha256="f" * 64,
            client=client,
        )

    assert client.events == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("draft", True),
        ("immutable", False),
        ("prerelease", True),
        ("tag_name", "v0.1.1"),
        ("target_commitish", "c" * 40),
        ("body", "not-controller-owned"),
        ("html_url", "https://example.com/release"),
        ("url", "https://api.example.com/release"),
        ("assets_url", "https://api.example.com/assets"),
    ],
)
def test_rejects_release_identity_drift(field: str, value: object) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    response = release_response(plan)
    response[field] = value
    client.responses[verifier._release_endpoint(plan)] = response

    with pytest.raises(verifier.VerificationError, match="immutable manifest identity"):
        verify(client, plan)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("digest", "sha256:" + "f" * 64),
        ("size", 999),
        ("state", "new"),
        ("content_type", "text/plain"),
        ("label", "friendly"),
        ("browser_download_url", "https://example.com/asset"),
        ("url", "https://api.example.com/asset"),
    ],
)
def test_rejects_remote_asset_drift(field: str, value: object) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    assets = asset_responses(plan)
    assets[0][field] = value
    client.responses[verifier._assets_endpoint(plan, RELEASE_ID)] = assets

    with pytest.raises(verifier.VerificationError, match="does not match the manifest"):
        verify(client, plan)


def test_rejects_missing_duplicate_and_reused_asset_identity() -> None:
    plan = release_plan()

    missing = FakeClient(plan)
    missing.responses[verifier._assets_endpoint(plan, RELEASE_ID)] = asset_responses(plan)[:-1]
    with pytest.raises(verifier.VerificationError, match="wrong asset count"):
        verify(missing, plan)

    duplicate = FakeClient(plan)
    assets = asset_responses(plan)
    assets[1]["name"] = assets[0]["name"]
    duplicate.responses[verifier._assets_endpoint(plan, RELEASE_ID)] = assets
    with pytest.raises(verifier.VerificationError, match="unexpected or duplicate"):
        verify(duplicate, plan)

    reused_id = FakeClient(plan)
    assets = asset_responses(plan)
    assets[1]["id"] = assets[0]["id"]
    assets[1]["url"] = assets[0]["url"]
    reused_id.responses[verifier._assets_endpoint(plan, RELEASE_ID)] = assets
    with pytest.raises(verifier.VerificationError, match="repeats an asset ID"):
        verify(reused_id, plan)


def test_rejects_repository_and_tag_identity_drift() -> None:
    plan = release_plan()

    repository = FakeClient(plan)
    response = repository_response()
    response["id"] = REPOSITORY_ID + 1
    repository.responses[verifier._repository_endpoint(REPOSITORY)] = response
    with pytest.raises(verifier.VerificationError, match="repository identity"):
        verify(repository, plan)

    owner = FakeClient(plan)
    response = repository_response()
    response["owner"] = {"id": OWNER_ID, "login": "attacker"}
    owner.responses[verifier._repository_endpoint(REPOSITORY)] = response
    with pytest.raises(verifier.VerificationError, match="owner"):
        verify(owner, plan)

    tag = FakeClient(plan)
    tag.responses[f"repos/{REPOSITORY}/git/ref/tags/{TAG}"] = {
        "object": {"sha": "c" * 40, "type": "commit"},
        "ref": f"refs/tags/{TAG}",
    }
    with pytest.raises(verifier.VerificationError, match="does not resolve"):
        verify(tag, plan)


def test_accepts_one_direct_annotated_tag_and_rejects_nested_tag() -> None:
    plan = release_plan()
    client = FakeClient(plan)
    tag_object = "d" * 40
    ref_endpoint = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
    tag_endpoint = f"repos/{REPOSITORY}/git/tags/{tag_object}"
    client.responses[ref_endpoint] = {
        "object": {"sha": tag_object, "type": "tag"},
        "ref": f"refs/tags/{TAG}",
    }
    client.responses[tag_endpoint] = {
        "object": {"sha": COMMIT, "type": "commit"},
        "sha": tag_object,
        "tag": TAG,
    }

    def bind_attestation_to_tag_object(statement: dict[str, Any]) -> None:
        statement["subject"][0]["digest"]["sha1"] = tag_object

    replace_attestation_statement(client, plan, bind_attestation_to_tag_object)

    assert verify(client, plan)["tag"] == {
        "attestation_subject_sha1": tag_object,
        "name": TAG,
        "target_commit": COMMIT,
    }

    nested = FakeClient(plan)
    nested.responses[ref_endpoint] = client.responses[ref_endpoint]
    nested.responses[tag_endpoint] = {
        "object": {"sha": "e" * 40, "type": "tag"},
        "sha": tag_object,
        "tag": TAG,
    }
    with pytest.raises(verifier.VerificationError, match="does not point directly"):
        verify(nested, plan)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("repository", "attacker/repository", "predicate"),
        ("tag", "v0.1.1", "predicate"),
        ("purl", "pkg:github/attacker/repository@v0.1.0", "predicate"),
        ("databaseId", "999", "databaseId"),
        ("ownerId", "999", "ownerId"),
        ("packageId", "999", "packageId"),
        ("repositoryId", "999", "repositoryId"),
        ("databaseId", "01", "canonical positive ID"),
    ],
)
def test_rejects_release_attestation_predicate_drift(
    field: str,
    value: object,
    message: str,
) -> None:
    plan = release_plan()
    client = FakeClient(plan)

    def mutate(statement: dict[str, Any]) -> None:
        statement["predicate"][field] = value

    replace_attestation_statement(client, plan, mutate)
    with pytest.raises(verifier.VerificationError, match=message):
        verify(client, plan)


def test_rejects_attestation_subject_tampering() -> None:
    plan = release_plan()

    tag = FakeClient(plan)

    def wrong_tag(statement: dict[str, Any]) -> None:
        statement["subject"][0]["digest"]["sha1"] = "f" * 40

    replace_attestation_statement(tag, plan, wrong_tag)
    with pytest.raises(verifier.VerificationError, match="wrong tag reference"):
        verify(tag, plan)

    asset = FakeClient(plan)

    def wrong_asset(statement: dict[str, Any]) -> None:
        statement["subject"][1]["digest"]["sha256"] = "f" * 64

    replace_attestation_statement(asset, plan, wrong_asset)
    with pytest.raises(verifier.VerificationError, match="wrong digest"):
        verify(asset, plan)

    duplicate = FakeClient(plan)

    def duplicate_asset(statement: dict[str, Any]) -> None:
        statement["subject"][2]["name"] = statement["subject"][1]["name"]

    replace_attestation_statement(duplicate, plan, duplicate_asset)
    with pytest.raises(verifier.VerificationError, match="unexpected or duplicate"):
        verify(duplicate, plan)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("attestation", "initiator"), "user", "retained API metadata"),
        (
            ("attestation", "bundle_url"),
            "https://example.com/attestation/1",
            "retained API metadata",
        ),
        (
            ("attestation", "bundle", "mediaType"),
            "application/example",
            "unsupported Sigstore bundle",
        ),
        (
            ("attestation", "bundle", "dsseEnvelope", "payloadType"),
            "application/example",
            "DSSE payload type",
        ),
    ],
)
def test_rejects_attestation_envelope_drift(
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    response = cast(dict[str, Any], copy.deepcopy(client.attestation))
    target = response
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    client.attestation = response

    with pytest.raises(verifier.VerificationError, match=message):
        verify(client, plan)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mediaType", "application/example"),
        ("statement", {"different": "statement"}),
        ("signature", {}),
        ("verifiedIdentity", {}),
        ("verifiedTimestamps", []),
        ("verifiedTimestamps", ["not-an-object"]),
    ],
)
def test_rejects_verification_result_drift(field: str, value: object) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    response = cast(dict[str, Any], copy.deepcopy(client.attestation))
    response["verificationResult"][field] = value
    client.attestation = response

    with pytest.raises(verifier.VerificationError, match="does not match its bundle"):
        verify(client, plan)


def test_rejects_malformed_duplicate_and_oversized_attestation_payloads() -> None:
    plan = release_plan()

    malformed = FakeClient(plan)
    response = cast(dict[str, Any], copy.deepcopy(malformed.attestation))
    response["attestation"]["bundle"]["dsseEnvelope"]["payload"] = "not/base64***"
    malformed.attestation = response
    with pytest.raises(verifier.VerificationError, match="canonical base64"):
        verify(malformed, plan)

    duplicate = FakeClient(plan)
    duplicate.attestation = attestation_response(
        plan,
        raw_payload=b'{"_type":"x","_type":"y"}',
    )
    with pytest.raises(verifier.VerificationError, match="repeats object key"):
        verify(duplicate, plan)

    oversized = FakeClient(plan)
    oversized.attestation = attestation_response(
        plan,
        raw_payload=b"{" + b" " * verifier.MAX_ATTESTATION_PAYLOAD_BYTES + b"}",
    )
    with pytest.raises(verifier.VerificationError, match="outside its byte bound"):
        verify(oversized, plan)


def test_rechecks_repository_release_tag_and_assets_after_attestation() -> None:
    plan = release_plan()
    client = FakeClient(plan)
    repository_endpoint = verifier._repository_endpoint(REPOSITORY)
    changed_repository = repository_response()
    changed_repository["id"] = REPOSITORY_ID + 1
    client.responses[repository_endpoint] = Sequential([repository_response(), changed_repository])

    with pytest.raises(verifier.VerificationError, match="repository identity"):
        verify(client, plan)

    assets = FakeClient(plan)
    asset_endpoint = verifier._assets_endpoint(plan, RELEASE_ID)
    changed_assets = asset_responses(plan)
    changed_assets[0]["digest"] = "sha256:" + "f" * 64
    assets.responses[asset_endpoint] = Sequential([asset_responses(plan), changed_assets])
    with pytest.raises(verifier.VerificationError, match="does not match the manifest"):
        verify(assets, plan)

    tag = FakeClient(plan)
    tag_object = "d" * 40
    tag_endpoint = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
    annotated_endpoint = f"repos/{REPOSITORY}/git/tags/{tag_object}"
    tag.responses[tag_endpoint] = Sequential(
        [
            tag_response(),
            {
                "object": {"sha": tag_object, "type": "tag"},
                "ref": f"refs/tags/{TAG}",
            },
        ]
    )
    tag.responses[annotated_endpoint] = {
        "object": {"sha": COMMIT, "type": "commit"},
        "sha": tag_object,
        "tag": TAG,
    }
    with pytest.raises(verifier.VerificationError, match="tag changed"):
        verify(tag, plan)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"key":1,"key":2}',
        b'{"value":1.5}',
        b'{"value":NaN}',
        b"",
        b"\xff",
    ],
)
def test_strict_json_rejects_ambiguous_inputs(raw: bytes) -> None:
    with pytest.raises(verifier.VerificationError):
        verifier.strict_json(raw, "fixture")


def write_executable(path: Path, source: str) -> Path:
    path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_documented_isolated_python_invocation_loads_only_reviewed_sibling(
    tmp_path: Path,
) -> None:
    script = Path(__file__).parents[1] / ".github" / "scripts" / "verify_github_release.py"
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
    assert "--manifest-sha256" in result.stdout
    assert result.stderr == ""


def test_github_cli_removes_tokens_from_version_probe_and_sanitizes_authenticated_env(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "capture.json"
    executable = write_executable(
        tmp_path / "fake-gh",
        f"""
import json
import os
import sys
from pathlib import Path

record = {{
    "argv": sys.argv[1:],
    "gh_token": "GH_TOKEN" in os.environ,
    "github_token": "GITHUB_TOKEN" in os.environ,
    "oidc": "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in os.environ,
    "unrelated": "UNRELATED_SECRET" in os.environ,
    "xdg_cache_home": os.environ.get("XDG_CACHE_HOME"),
}}
Path({str(capture)!r}).write_text(json.dumps(record), encoding="utf-8")
if sys.argv[1:] == ["version"]:
    sys.stdout.write("gh version 2.96.0 (2026-07-02)\\n")
else:
    sys.stdout.write("{{}}")
""",
    )
    client = verifier.GitHubCLI(
        executable=str(executable),
        timeout=5,
        environment={
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-secret",
            "GH_TOKEN": "github-secret",
            "GITHUB_TOKEN": "github-secret",
            "HOME": str(tmp_path),
            "PATH": os.environ["PATH"],
            "UNRELATED_SECRET": "other-secret",
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
        },
    )

    assert client.check_version() == "2.96.0"
    version_record = json.loads(capture.read_text(encoding="utf-8"))
    assert version_record == {
        "argv": ["version"],
        "gh_token": False,
        "github_token": False,
        "oidc": False,
        "unrelated": False,
        "xdg_cache_home": str(tmp_path / "cache"),
    }

    assert client.api("repos/stampbot/extra-codeowners") == {}
    api_record = json.loads(capture.read_text(encoding="utf-8"))
    assert api_record["gh_token"] is True
    assert api_record["github_token"] is False
    assert api_record["oidc"] is False
    assert api_record["unrelated"] is False
    assert api_record["xdg_cache_home"] == str(tmp_path / "cache")
    assert api_record["argv"] == [
        "api",
        "--hostname",
        "github.com",
        "--method",
        "GET",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {verifier.API_VERSION}",
        "repos/stampbot/extra-codeowners",
    ]

    assert client.verify_release(REPOSITORY, TAG) == {}
    release_record = json.loads(capture.read_text(encoding="utf-8"))
    assert release_record["argv"] == [
        "release",
        "verify",
        TAG,
        "--repo",
        REPOSITORY,
        "--format",
        "json",
    ]
    assert release_record["xdg_cache_home"] == str(tmp_path / "cache")


def test_rejects_vulnerable_github_cli_before_authentication(tmp_path: Path) -> None:
    marker = tmp_path / "authenticated-command-ran"
    executable = write_executable(
        tmp_path / "old-gh",
        f"""
import sys
from pathlib import Path

if sys.argv[1:] == ["version"]:
    sys.stdout.write("gh version 2.92.0 (2026-04-28)\\n")
else:
    Path({str(marker)!r}).touch()
    sys.stdout.write("{{}}")
""",
    )
    plan = release_plan()
    client = verifier.GitHubCLI(
        executable=str(executable),
        timeout=5,
        environment={
            "GH_TOKEN": "must-not-reach-old-client",
            "HOME": str(tmp_path),
            "PATH": os.environ["PATH"],
        },
    )

    with pytest.raises(verifier.VerificationError, match=r"2\.93\.0 or newer"):
        verifier.verify_github_release(
            plan,
            expected_manifest_sha256=plan.manifest_sha256,
            client=client,
        )

    assert not marker.exists()


def test_cli_failure_never_echoes_token_or_untrusted_diagnostics(tmp_path: Path) -> None:
    secret = "github-token-must-not-appear"
    executable = write_executable(
        tmp_path / "failing-gh",
        """
import os
import sys

sys.stderr.write(os.environ.get("GH_TOKEN", "") + "\\nattacker-controlled-error")
raise SystemExit(7)
""",
    )
    client = verifier.GitHubCLI(
        executable=str(executable),
        timeout=5,
        environment={
            "GH_TOKEN": secret,
            "HOME": str(tmp_path),
            "PATH": os.environ["PATH"],
        },
    )

    with pytest.raises(verifier.VerificationError) as error:
        client.api("repos/stampbot/extra-codeowners")

    message = str(error.value)
    assert secret not in message
    assert "attacker-controlled-error" not in message
    assert "exit status 7" in message


def test_cli_rejects_conflicting_token_variables_before_execution(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    executable = write_executable(
        tmp_path / "fake-gh",
        f"""
from pathlib import Path
Path({str(marker)!r}).touch()
print("{{}}")
""",
    )
    client = verifier.GitHubCLI(
        executable=str(executable),
        timeout=5,
        environment={
            "GH_TOKEN": "first-token",
            "GITHUB_TOKEN": "second-token",
            "HOME": str(tmp_path),
            "PATH": os.environ["PATH"],
        },
    )

    with pytest.raises(verifier.VerificationError, match="disagree"):
        client.api("repos/stampbot/extra-codeowners")

    assert not marker.exists()


def test_bounded_runner_rejects_output_bombs_and_timeouts(tmp_path: Path) -> None:
    output_bomb = write_executable(
        tmp_path / "output-bomb",
        """
import sys
sys.stdout.write("x" * 1024)
""",
    )
    with pytest.raises(verifier.VerificationError, match="output exceeds"):
        verifier._run_bounded(
            (str(output_bomb),),
            environment={"PATH": os.environ["PATH"]},
            timeout=5,
            maximum_stdout=32,
        )

    timeout = write_executable(
        tmp_path / "timeout",
        """
import time
time.sleep(60)
""",
    )
    with pytest.raises(verifier.VerificationError, match="timed out"):
        verifier._run_bounded(
            (str(timeout),),
            environment={"PATH": os.environ["PATH"]},
            timeout=0.05,
            maximum_stdout=32,
        )


def test_verifier_remains_read_only_and_unwired_from_workflows() -> None:
    path = ".github/scripts/verify_github_release.py"
    workflows = sorted((Path(__file__).parents[1] / ".github" / "workflows").glob("*.yml"))
    assert workflows
    occurrences = 0
    for workflow in workflows:
        source = workflow.read_text(encoding="utf-8")
        occurrences += source.count(path)
        assert f"python {path}" not in source
        assert f"python3 {path}" not in source
        assert f"mise exec -- python -I -B {path}" not in source
    assert occurrences == 2  # CI and release strict type-check scopes only.


def test_documentation_matches_the_verifier_command_and_nonclaims() -> None:
    root = Path(__file__).parents[1]
    how_to = (root / "docs/how-to/verify-container-release-evidence.md").read_text(encoding="utf-8")
    reference = (root / "docs/reference/authenticated-github-release-record.md").read_text(
        encoding="utf-8"
    )
    contract = (root / "docs/reference/container-evidence-release-contract.md").read_text(
        encoding="utf-8"
    )
    navigation = (root / "mkdocs.yml").read_text(encoding="utf-8")

    for option in (
        "--manifest",
        "--manifest-sha256",
        "--gh",
        "--timeout-seconds",
    ):
        assert option in reference
    assert ".github/scripts/verify_github_release.py" in how_to
    assert "mise exec -- python -I -B" in how_to
    assert 'XDG_CACHE_HOME="$AUTH_CACHE"' in how_to
    assert "unset GH_TOKEN GITHUB_TOKEN" in how_to
    assert "Contents: read" in how_to
    assert "Attestations: read" in how_to
    assert "2.93.0 or newer" in reference
    assert "2.96.0" in reference
    assert "release v0.2" in reference
    assert "`attestation_subject_sha1`" in reference
    assert "- download a release asset" in reference
    assert "does not download assets" in contract
    assert "No workflow" in reference
    assert (
        "Authenticated GitHub release record: "
        "reference/authenticated-github-release-record.md" in navigation
    )
