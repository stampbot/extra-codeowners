"""Keep published documentation examples aligned with executable policy models."""

import argparse
import tomllib
from pathlib import Path
from threading import Thread

from examples.tutorial.relay_probe import ProbeHandler, ProbeServer, _signature, send
from extra_codeowners.models import OrganizationPolicy, RepositoryPolicy
from extra_codeowners.policy import compile_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_EXAMPLES = ROOT / "examples" / "policy"
FIRST_CHECK_TUTORIAL = ROOT / "docs" / "tutorials" / "development-installation.md"
CLOUDFLARED_VERSION = "2026.7.2"
CLOUDFLARED_CONFIG = ROOT / "mise.tutorial.toml"
CLOUDFLARED_ASSETS = {
    "linux-x64": (
        "cloudflared-linux-amd64",
        "sha256:ec905ea7b7e327ff8abdde8cb64697a2152de74dbcdbf6aec9db8364eb3886cd",
    ),
    "linux-arm64": (
        "cloudflared-linux-arm64",
        "sha256:405df476437e027fc6d18729a5a77155c0a33a6082aeee60a799a688f3052e66",
    ),
    "macos-x64": (
        "cloudflared-darwin-amd64.tgz",
        "sha256:4ee0d3b48a990a2f9b5faec5838f73ec1f400aa8e0a4864be576adfafec406cb",
    ),
    "macos-arm64": (
        "cloudflared-darwin-arm64.tgz",
        "sha256:2086e51c61d6565781d84117a5007d0c826d03ffdc74acb91c08c167f9f8cd7c",
    ),
}


def test_published_policy_pair_compiles_and_preserves_its_guardrails() -> None:
    organization = OrganizationPolicy.from_toml(
        (POLICY_EXAMPLES / "organization.toml").read_text(encoding="utf-8")
    )
    repository = RepositoryPolicy.from_toml(
        (POLICY_EXAMPLES / "repository.toml").read_text(encoding="utf-8")
    )

    compiled = compile_policy(organization, repository)

    assert repository.enabled
    assert compiled.is_non_delegable("infrastructure/production/main.tf")
    assert compiled.is_non_delegable(".github/extra-codeowners.toml")
    assert compiled.delegation_decisions(
        "uv.lock",
        frozenset({"@example-org/platform"}),
        frozenset({"automation-approved"}),
    )[0].eligible
    assert not compiled.delegation_decisions(
        "docs/guide.md",
        frozenset({"@example-org/platform"}),
        frozenset({"automation-approved", "needs-security-review"}),
    )[0].eligible


def test_published_diagrams_do_not_need_a_browser_side_renderer() -> None:
    markdown_files = [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]

    for path in markdown_files:
        assert "```mermaid" not in path.read_text(encoding="utf-8"), path


def test_first_check_tutorial_uses_the_checksum_pinned_tunnel_config() -> None:
    tutorial = FIRST_CHECK_TUTORIAL.read_text(encoding="utf-8")
    config = tomllib.loads(CLOUDFLARED_CONFIG.read_text(encoding="utf-8"))
    assert config["tool_alias"]["tutorial-cloudflared"] == ("github:cloudflare/cloudflared")
    cloudflared = config["tools"]["tutorial-cloudflared"]

    assert cloudflared["version"] == CLOUDFLARED_VERSION
    assert {
        platform: (options["asset_pattern"], options["checksum"])
        for platform, options in cloudflared["platforms"].items()
    } == CLOUDFLARED_ASSETS
    assert "mise exec -E tutorial --" in tutorial
    assert CLOUDFLARED_VERSION in tutorial
    assert "smee-client" not in tutorial


def test_relay_probe_accepts_exact_hmac_and_rejects_another_secret(
    tmp_path: Path,
) -> None:
    expected_secret = b"expected tutorial secret"
    payload_file = tmp_path / "payload.json"
    payload_file.write_bytes(b'{"z":1, "a":2}\n')

    def exercise(sender_secret: bytes) -> tuple[int, bool]:
        secret_file = tmp_path / f"secret-{len(sender_secret)}"
        secret_file.write_bytes(sender_secret)
        server = ProbeServer(("127.0.0.1", 0), ProbeHandler)
        server.expected_body = payload_file.read_bytes()
        server.expected_signature = _signature(
            expected_secret,
            server.expected_body,
        )
        thread = Thread(target=server.handle_request)
        thread.start()
        try:
            result = send(
                argparse.Namespace(
                    secret_file=secret_file,
                    payload_file=payload_file,
                    url=f"http://127.0.0.1:{server.server_port}/probe",
                    timeout=1,
                )
            )
            thread.join(timeout=1)
        finally:
            server.server_close()
        assert not thread.is_alive()
        return result, server.succeeded

    assert exercise(expected_secret) == (0, True)
    assert exercise(b"different tutorial secret") == (1, False)
