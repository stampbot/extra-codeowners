"""Exercise the scanner action's shell commands without a Docker daemon."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/scan-image/action.yml"
BASH = shutil.which("bash")
PIN = re.compile(r"anchore/grype:v\d+\.\d+\.\d+@sha256:[a-f0-9]{64}")


def _script(name: str) -> str:
    step = ACTION.read_text().split(f"    - name: {name}\n", 1)[1].split("\n    - name:", 1)[0]
    script = step.split("      run: ", 1)[1].rstrip()
    if script.startswith("|\n"):
        return "\n".join(line[8:] for line in script[2:].splitlines())
    return script


@pytest.fixture
def scan_env(tmp_path: Path) -> dict[str, str]:
    docker = tmp_path / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['DOCKER_LOG'], 'a') as log:\n"
        "    log.write(json.dumps(args) + '\\n')\n"
        "if args[:2] == ['image', 'inspect']:\n"
        "    print('sha256:' + 'a' * 64)\n"
        "elif args[:2] == ['image', 'save']:\n"
        "    pathlib.Path(args[3]).touch()\n"
        "elif args[0] == 'run':\n"
        "    print('{\"matches\": []}')\n"
        "sys.exit(int(os.environ.get('DOCKER_EXIT', '0')))\n"
    )
    docker.chmod(0o755)
    return {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "DOCKER_LOG": str(tmp_path / "docker.jsonl"),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_WORKSPACE": str(ROOT),
        "SCAN_IMAGE": "example:local",
        "REPORT_FILE": str(tmp_path / "report.json"),
        "GRYPE_IMAGE": PIN.findall(ACTION.read_text())[0],
    }


def _run(name: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    if BASH is None:
        pytest.skip("bash is unavailable")
    return subprocess.run(  # noqa: S603
        [BASH, "-euo", "pipefail", "-c", _script(name)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_scan_uses_an_archive_and_one_database_without_socket_access(
    scan_env: dict[str, str],
) -> None:
    result = _run("Prepare scanner inputs", scan_env)
    assert result.returncode == 0, result.stderr
    directory = Path(scan_env["GITHUB_OUTPUT"]).read_text().strip().removeprefix("directory=")
    scan_env["SCAN_DIRECTORY"] = directory
    for name in ("Inventory all vulnerabilities", "Reject fixable high-severity vulnerabilities"):
        result = _run(name, scan_env)
        assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in Path(scan_env["DOCKER_LOG"]).read_text().splitlines()]
    assert calls[1] == ["image", "save", "--output", f"{directory}/image.tar", "sha256:" + "a" * 64]
    inventory, gate = calls[2:]
    for call in (inventory, gate):
        assert "docker-archive:/image.tar" in call
        assert f"type=bind,src={directory}/image.tar,dst=/image.tar,readonly" in call
        assert f"type=bind,src={directory}/db,dst=/cache" in call
        assert "GRYPE_DB_CACHE_DIR=/cache" in call
        assert scan_env["GRYPE_IMAGE"] in call
        assert "--read-only" in call
        assert "--cap-drop=ALL" in call
        assert "--security-opt=no-new-privileges" in call
        assert "docker.sock" not in " ".join(call)
    assert "/work/.github/grype-inventory.yaml" in inventory
    assert "--vex" not in inventory
    assert "--only-fixed" not in inventory
    assert "GRYPE_DB_AUTO_UPDATE=false" not in inventory
    assert "GRYPE_DB_AUTO_UPDATE=false" in gate
    assert "/work/.grype.yaml" in gate
    assert "/work/security/vex/openssl-3.5.7.openvex.json" in gate
    assert gate[gate.index("--fail-on") + 1] == "high"
    assert "--only-fixed" in gate
    assert json.loads(Path(scan_env["REPORT_FILE"]).read_text()) == {"matches": []}
    assert _run("Remove scanner inputs and database", scan_env).returncode == 0
    assert not Path(directory).exists()


@pytest.mark.parametrize(
    "step",
    [
        "Prepare scanner inputs",
        "Inventory all vulnerabilities",
        "Reject fixable high-severity vulnerabilities",
    ],
)
@pytest.mark.parametrize("exit_code", [1, 2])
def test_docker_and_scanner_failures_fail_the_step(
    scan_env: dict[str, str], step: str, exit_code: int
) -> None:
    scan_env.update(DOCKER_EXIT=str(exit_code), SCAN_DIRECTORY=scan_env["RUNNER_TEMP"])
    assert _run(step, scan_env).returncode == exit_code


def test_every_build_uses_the_scanner_and_retains_raw_findings_before_the_gate() -> None:
    source = ACTION.read_text()
    assert len(set(PIN.findall(source))) == 1
    assert source.index("Retain the unfiltered report") < source.index("Reject fixable")
    assert "if-no-files-found: error" in source
    assert "retention-days: 14" in source
    assert "always() && steps.prepare.outputs.directory != ''" in source
    assert "continue-on-error" not in source
    for name in ("ci", "cold-container", "release"):
        workflow = (ROOT / f".github/workflows/{name}.yml").read_text()
        assert "uses: ./.github/actions/scan-image" in workflow
        assert "anchore/scan-action" not in workflow
    for action in re.findall(r"uses: (\S+)", source):
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)


def test_renovate_tracks_build_and_rescan_images() -> None:
    config = json.loads((ROOT / "renovate.json").read_text())
    manager = next(
        item for item in config["customManagers"] if item.get("depNameTemplate") == "anchore/grype"
    )
    for filename in (
        ".github/actions/scan-image/action.yml",
        ".github/workflows/rescan-release.yml",
    ):
        assert any(re.search(pattern[1:-1], filename) for pattern in manager["managerFilePatterns"])
        assert PIN.search((ROOT / filename).read_text())


@pytest.mark.live
def test_real_scanner_on_an_explicitly_selected_local_image(tmp_path: Path) -> None:
    image = os.environ.get("LOCAL_SCAN_IMAGE")
    if not image:
        pytest.skip("set LOCAL_SCAN_IMAGE to a locally loaded image")
    env = {
        **os.environ,
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_WORKSPACE": str(ROOT),
        "SCAN_IMAGE": image,
        "REPORT_FILE": str(tmp_path / "report.json"),
        "GRYPE_IMAGE": PIN.findall(ACTION.read_text())[0],
    }
    if BASH is None:
        pytest.skip("bash is unavailable")
    try:
        for name in (
            "Prepare scanner inputs",
            "Inventory all vulnerabilities",
            "Reject fixable high-severity vulnerabilities",
        ):
            result = subprocess.run(  # noqa: S603
                [BASH, "-euo", "pipefail", "-c", _script(name)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            if name == "Prepare scanner inputs":
                env["SCAN_DIRECTORY"] = (
                    Path(env["GITHUB_OUTPUT"]).read_text().strip().removeprefix("directory=")
                )
            assert result.returncode == 0, result.stderr + result.stdout
        report = json.loads(Path(env["REPORT_FILE"]).read_text())
        assert report["descriptor"]["name"] == "grype"
        assert "matches" in report
        assert report["source"]["type"] == "image"
    finally:
        if env.get("SCAN_DIRECTORY"):
            assert _run("Remove scanner inputs and database", env).returncode == 0
