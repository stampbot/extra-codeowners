"""Keep routine builders quiet without restoring insecure daemon defaults."""

from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(("workflow", "expected_builders"), [("ci.yml", 1), ("release.yml", 3)])
def test_buildkit_debug_is_disabled_with_explicit_daemon_flags(
    workflow: str, expected_builders: int
) -> None:
    document = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    builders = [
        step
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("docker/setup-buildx-action@")
    ]

    assert len(builders) == expected_builders
    for builder in builders:
        # Omitting this input restores the action's insecure-entitlement defaults.
        assert builder["with"]["buildkitd-flags"] == "--debug=false"
