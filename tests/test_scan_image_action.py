"""Exercise the scanner's actual download program without Docker or network."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


def _steps() -> list[dict[str, Any]]:
    action = yaml.safe_load((ROOT / ".github/actions/scan-image/action.yml").read_text())
    return cast(list[dict[str, Any]], action["runs"]["steps"])


@pytest.mark.skipif(BASH is None, reason="Bash is required")
@pytest.mark.parametrize(
    ("failures", "failure_code", "attempts", "exit_code"),
    [(0, 1, 1, 0), (2, 1, 3, 0), (3, 1, 3, 1), (1, 130, 1, 130), (1, 143, 1, 143)],
)
def test_database_download_retries_are_bounded_and_fail_closed(
    tmp_path: Path, failures: int, failure_code: int, attempts: int, exit_code: int
) -> None:
    steps = _steps()
    download = next(s for s in steps if s["name"] == "Download vulnerability database")
    programs = tmp_path / "bin"
    programs.mkdir()
    docker = programs / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "log = pathlib.Path(os.environ['FAKE_DOCKER_LOG'])\n"
        "previous = log.read_text().splitlines() if log.exists() else []\n"
        "with log.open('a') as target:\n"
        "    target.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "assert sys.argv[-2:] == ['db', 'update']\n"
        "failed = len(previous) < int(os.environ['FAKE_FAILURES'])\n"
        "sys.exit(int(os.environ['FAKE_FAILURE_CODE']) if failed else 0)\n"
    )
    docker.chmod(0o755)
    sleep = programs / "sleep"
    sleep.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "with pathlib.Path(os.environ['FAKE_SLEEP_LOG']).open('a') as target:\n"
        "    target.write(sys.argv[1] + '\\n')\n"
    )
    sleep.chmod(0o755)
    log = tmp_path / "docker.jsonl"
    delays = tmp_path / "sleep.txt"
    environment = {
        **os.environ,
        "PATH": str(programs) + os.pathsep + os.environ["PATH"],
        "FAKE_DOCKER_LOG": str(log),
        "FAKE_SLEEP_LOG": str(delays),
        "FAKE_FAILURES": str(failures),
        "FAKE_FAILURE_CODE": str(failure_code),
        "SCAN_DIRECTORY": str(tmp_path),
        "GRYPE_IMAGE": download["env"]["GRYPE_IMAGE"],
    }
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - Execute tracked Bash with fake Docker and sleep.
        [BASH, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", download["run"]],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == exit_code, result.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(calls) == attempts
    for call in calls:
        assert "GRYPE_DB_UPDATE_AVAILABLE_TIMEOUT=30s" in call
        assert "GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT=120s" in call
        assert call[-3:] == [environment["GRYPE_IMAGE"], "db", "update"]
        assert "--read-only" in call and "--cap-drop=ALL" in call
        assert all("docker.sock" not in value for value in call)
    assert (delays.read_text().splitlines() if delays.exists() else []) == ["5", "10"][
        : attempts - 1
    ]
    assert "continue-on-error" not in download and "if" not in download
    names = [step["name"] for step in steps]
    assert names.index("Download vulnerability database") < names.index(
        "Inventory all vulnerabilities"
    )


def test_both_scans_reuse_the_download_without_retrying_the_vulnerability_gate() -> None:
    steps = _steps()
    selected = {step["name"]: step for step in steps}
    download = selected["Download vulnerability database"]
    inventory = selected["Inventory all vulnerabilities"]
    gate = selected["Reject fixable high-severity vulnerabilities"]
    assert (
        download["env"]["GRYPE_IMAGE"]
        == inventory["env"]["GRYPE_IMAGE"]
        == gate["env"]["GRYPE_IMAGE"]
    )
    for step in (inventory, gate):
        assert "GRYPE_DB_AUTO_UPDATE=false" in step["run"]
        assert "type=bind,src=${SCAN_DIRECTORY}/db,dst=/cache" in step["run"]
        assert "continue-on-error" not in step and "if" not in step
    assert "--only-fixed --fail-on high" in gate["run"]
    assert "--vex /work/security/vex/runtime.openvex.json" in gate["run"]
    assert "for attempt" not in gate["run"]
