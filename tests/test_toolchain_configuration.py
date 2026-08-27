"""Regression tests for the reviewed build and release toolchain."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

import extra_codeowners
from tools import evaluation_beta_bootstrap as beta_bootstrap
from tools import readthedocs_bootstrap

ROOT = Path(__file__).resolve().parents[1]
TEST_INSTALLED_BETA_VERSION = "9.8.7.dev1+test"
OPENSSL_VEX = ROOT / "security" / "vex" / "openssl-3.5.6.openvex.json"
OPENSSL_VEX_VERSION = "3.5.6-1~deb13u2"
OPENSSL_VEX_IMPACT_STATEMENTS = {
    "CVE-2026-14456": "The service does not configure or use OpenSSL QUIC server listeners.",
    "CVE-2026-14457": (
        "The service does not enable RFC 7250 raw public keys or a key-only TLS endpoint."
    ),
    "CVE-2026-18798": "The service does not configure or use OpenSSL QUIC server listeners.",
    "CVE-2026-54874": "The service does not use UDP or DTLS.",
    "CVE-2026-63072": "The service does not process CMS messages or call OpenSSL CMS decryption.",
    "CVE-2026-63075": "The service does not configure or use OpenSSL QUIC connections.",
    "CVE-2026-63076": "The service does not configure or use an OpenSSL CMP client or server.",
}
SETUP_UV = re.compile(
    r"^(?P<indent>\s*)uses: astral-sh/setup-uv@(?P<sha>[0-9a-f]{40})(?:\s+#.*)?$",
    flags=re.MULTILINE,
)
SETUP_BUILDX = re.compile(
    r"^(?P<indent>\s*)uses: docker/setup-buildx-action@(?P<sha>[0-9a-f]{40})(?:\s+#.*)?$",
    flags=re.MULTILINE,
)


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _mise_uv_version() -> str:
    return cast(str, _load_toml(ROOT / "mise.toml")["tools"]["uv"])


def _workflow_action_steps(workflow: str, action: re.Pattern[str]) -> list[str]:
    steps: list[str] = []
    for match in action.finditer(workflow):
        action_indent = len(match.group("indent"))
        next_step = re.search(
            rf"^{' ' * (action_indent - 2)}- ",
            workflow[match.end() :],
            flags=re.MULTILINE,
        )
        end = match.end() + next_step.start() if next_step is not None else len(workflow)
        steps.append(workflow[match.start() : end])
    return steps


def _workflow_job(workflow: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"workflow is missing the {name!r} job"
    return match.group(0)


def _workflow_step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    _, separator, tail = job.partition(marker)
    assert separator, f"workflow job is missing the {name!r} step"
    next_step = re.search(r"(?m)^      - (?:name|uses):", tail)
    return tail[: next_step.start()] if next_step is not None else tail


def _openssl_vex_products() -> set[str]:
    products: set[str] = set()
    for architecture in ("amd64", "arm64"):
        for package, upstream in (
            ("libssl3t64", "&upstream=openssl"),
            ("openssl", ""),
            ("openssl-provider-legacy", "&upstream=openssl"),
        ):
            products.add(
                f"pkg:deb/debian/{package}@{OPENSSL_VEX_VERSION}"
                f"?arch={architecture}&distro=debian-13{upstream}"
            )
    return products


def _assert_native_matrix(job: str) -> None:
    assert "runs-on: ${{ matrix.runner }}" in job
    assert job.count("- architecture: amd64") == 1
    assert job.count("- architecture: arm64") == 1
    assert job.count("machine: x86_64") == 1
    assert job.count("machine: aarch64") == 1
    assert job.count("platform: linux/amd64") == 1
    assert job.count("platform: linux/arm64") == 1
    assert job.count("runner: ubuntu-24.04\n") == 1
    assert job.count("runner: ubuntu-24.04-arm") == 1
    assert 'test "$(uname -m)" = "${EXPECTED_MACHINE}"' in job
    assert "setup-qemu-action" not in job


def test_project_uses_dynamic_vcs_version_and_a_locked_build_group() -> None:
    project = _load_toml(ROOT / "pyproject.toml")
    lock = _load_toml(ROOT / "uv.lock")

    metadata = cast(dict[str, Any], project["project"])
    assert "version" not in metadata
    assert metadata["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"]["source"] == "vcs"
    assert project["build-system"]["build-backend"] == "hatchling.build"

    build_requires = cast(list[str], project["build-system"]["requires"])
    build_group = cast(list[str], project["dependency-groups"]["build"])
    assert set(build_group) == set(build_requires)
    assert all("==" in requirement for requirement in build_group)

    root_package = next(
        package
        for package in cast(list[dict[str, Any]], lock["package"])
        if package["name"] == "extra-codeowners"
    )
    locked_build = {
        item["name"]: item["specifier"]
        for item in root_package["metadata"]["requires-dev"]["build"]
    }
    expected_build = {
        requirement.split("==", 1)[0]: f"=={requirement.split('==', 1)[1]}"
        for requirement in build_group
    }
    assert locked_build == expected_build


def test_project_owned_uv_version_drives_local_container_and_action_setup() -> None:
    project = _load_toml(ROOT / "pyproject.toml")
    reviewed_version = _mise_uv_version()
    assert project["tool"]["uv"]["required-version"] == f"=={reviewed_version}"

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    uv_image = re.search(
        r"^FROM ghcr\.io/astral-sh/uv:(?P<version>\d+\.\d+\.\d+)"
        r"@sha256:[0-9a-f]{64} AS uv$",
        dockerfile,
        flags=re.MULTILINE,
    )
    assert uv_image is not None
    assert uv_image.group("version") == reviewed_version

    found_steps = 0
    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        workflow = path.read_text(encoding="utf-8")
        steps = _workflow_action_steps(workflow, SETUP_UV)
        assert workflow.count("uses: astral-sh/setup-uv@") == len(steps), (
            f"{path}: setup-uv must be pinned to a full commit"
        )
        for step in steps:
            assert re.search(r"(?m)^\s+version:", step) is None, (
                f"{path}: setup-uv must read tool.uv.required-version"
            )
        found_steps += len(steps)
    assert found_steps > 0


def test_debian_container_uses_only_locked_binary_dependencies() -> None:
    project = _load_toml(ROOT / "pyproject.toml")
    lock = _load_toml(ROOT / "uv.lock")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    python_base = re.search(
        r"^FROM (?P<image>python:\d+\.\d+\.\d+-slim-trixie"
        r"@sha256:[0-9a-f]{64}) AS python-base$",
        dockerfile,
        flags=re.MULTILINE,
    )
    assert python_base is not None
    assert dockerfile.count("FROM python-base AS builder") == 1
    assert dockerfile.count("FROM python-base AS runtime") == 1
    assert len(re.findall(r"^FROM ", dockerfile, flags=re.MULTILINE)) == 4
    assert "apt-get" not in dockerfile
    assert "apk add" not in dockerfile
    assert "native-wheelhouse" not in dockerfile

    sync_commands = re.findall(
        r"(?ms)^\s*uv sync \\\n(?P<arguments>.*?)(?=\n\n|\Z)",
        dockerfile,
    )
    assert len(sync_commands) == 2
    runtime_sync, build_sync = sync_commands
    for command in sync_commands:
        assert "--frozen" in command
        assert "--no-install-project" in command
        assert "--no-build" in command
    assert "--no-dev" in runtime_sync
    assert "--only-group build" in build_sync
    assert "uv build \\\n      --python /opt/build-venv/bin/python" in dockerfile
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" in dockerfile
    assert "uv pip install" in dockerfile
    assert "--offline" in dockerfile
    assert "--no-index" in dockerfile
    assert "--no-deps" in dockerfile
    assert (
        'ENTRYPOINT ["/opt/venv/bin/python", "-I", "-B", "-u", "-m", "extra_codeowners"]'
        in dockerfile
    )

    dependencies = cast(list[str], project["project"]["dependencies"])
    assert any(requirement.startswith("psycopg[binary]") for requirement in dependencies)
    packages = {package["name"] for package in cast(list[dict[str, Any]], lock["package"])}
    assert "psycopg-binary" in packages
    assert "psycopg-c" not in packages


def test_grype_policy_has_one_scoped_python_line_exception() -> None:
    policy = cast(
        dict[str, Any],
        yaml.safe_load((ROOT / ".grype.yaml").read_text(encoding="utf-8")),
    )

    assert set(policy) == {"ignore"}
    rules = cast(list[dict[str, Any]], policy["ignore"])
    assert len(rules) == 1
    assert rules[0]["vulnerability"] == "CVE-2026-15308"
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_base = re.search(
        r"(?m)^FROM python:(?P<version>\d+\.\d+\.\d+)-slim-trixie@sha256:[0-9a-f]{64} "
        r"AS python-base$",
        dockerfile,
    )
    assert python_base is not None
    assert rules[0]["package"] == {
        "name": "python",
        "version": python_base.group("version"),
        "type": "binary",
    }
    assert "CPython 3.14" in rules[0]["reason"]
    assert "Python 3.15" in rules[0]["reason"]


def test_openssl_vex_is_exact_and_evidence_backed() -> None:
    document = cast(dict[str, Any], json.loads(OPENSSL_VEX.read_text(encoding="utf-8")))

    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", cast(str, document["@id"]))
    assert document["author"] == "Extra CODEOWNERS maintainers"
    assert document["role"] == "VEX document producer"
    assert document["tooling"] == "Vexcalibur"
    assert document["version"] == 1

    statements = cast(list[dict[str, Any]], document["statements"])
    assert len(statements) == len(OPENSSL_VEX_IMPACT_STATEMENTS)
    assert {
        cast(dict[str, str], statement["vulnerability"])["name"] for statement in statements
    } == set(OPENSSL_VEX_IMPACT_STATEMENTS)
    for statement in statements:
        vulnerability = cast(dict[str, str], statement["vulnerability"])["name"]
        impact_statement = OPENSSL_VEX_IMPACT_STATEMENTS[vulnerability]
        assert statement["status"] == "not_affected"
        assert statement["impact_statement"] == impact_statement
        assert statement["status_notes"] == (
            f"Analysis detail: {impact_statement}\n"
            "Source: Debian Security Tracker "
            f"(https://security-tracker.debian.org/tracker/{vulnerability})\n"
            "Original Vexcalibur analysis state: not_affected"
        )
        products = cast(list[dict[str, Any]], statement["products"])
        assert {cast(str, product["@id"]) for product in products} == _openssl_vex_products()
        assert all(product["identifiers"] == {"purl": product["@id"]} for product in products)


def test_openssl_vex_claims_match_the_service_protocol_contract() -> None:
    application_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "extra_codeowners").glob("*.py"))
    )
    forbidden_capabilities = re.compile(
        r"\b(?:quic|dtls|cms|cmp|ossl_cmp|cms_decrypt|raw public)\b",
        flags=re.IGNORECASE,
    )
    assert forbidden_capabilities.search(application_source) is None
    assert re.search(r"(?m)^\s*(?:from|import)\s+ssl\b", application_source) is None
    assert "socket.socket" not in application_source
    assert "SOCK_DGRAM" not in application_source

    serve = (
        (ROOT / "extra_codeowners" / "cli.py")
        .read_text(encoding="utf-8")
        .split("@cli.command()\ndef serve", 1)[1]
        .split("\n\n@cli.command", 1)[0]
    )
    assert "ssl_" not in serve
    assert "http2=" not in application_source
    assert "http3" not in application_source

    deployment = (ROOT / "charts" / "extra-codeowners" / "templates" / "deployment.yaml").read_text(
        encoding="utf-8"
    )
    service = (ROOT / "charts" / "extra-codeowners" / "templates" / "service.yaml").read_text(
        encoding="utf-8"
    )
    assert "protocol: UDP" not in deployment
    assert "protocol: UDP" not in service
    assert "protocol: TCP" in deployment
    assert "protocol: TCP" in service

    lock = _load_toml(ROOT / "uv.lock")
    package_names = {package["name"] for package in cast(list[dict[str, Any]], lock["package"])}
    assert "aioquic" not in package_names


def test_dependency_audit_uses_locked_mode_without_frozen_mode() -> None:
    workflow = (ROOT / ".github" / "workflows" / "dependency-audit.yml").read_text(encoding="utf-8")
    assert "UV_FROZEN" not in workflow
    assert "--locked" in workflow
    assert "--no-cache" in workflow
    assert "--no-python-downloads" in workflow
    assert "--preview-features audit-command" in workflow


def test_ci_checks_lockfile_freshness_outside_frozen_mode() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    lock_check = workflow.split("      - name: Verify lockfile is current\n", 1)[1].split(
        "\n      - name:", 1
    )[0]

    assert 'UV_FROZEN: "false"' in lock_check
    assert "run: uv lock --check" in lock_check


def test_helm_chart_retains_hardening_without_image_specific_loader_paths() -> None:
    values = cast(
        dict[str, Any],
        yaml.safe_load((ROOT / "charts" / "extra-codeowners" / "values.yaml").read_text()),
    )
    startup = cast(dict[str, Any], cast(dict[str, Any], values["probes"])["startup"])
    assert startup == {
        "enabled": True,
        "path": "/health/live",
        "initialDelaySeconds": 0,
        "periodSeconds": 5,
        "timeoutSeconds": 3,
        "failureThreshold": 60,
    }

    image = cast(dict[str, Any], values["image"])
    assert image["repository"] == "ghcr.io/stampbot/extra-codeowners"
    assert image["tag"] == ""
    assert values["deploymentAnnotations"] == {}
    assert values["extraManifests"] == []
    assert values["monitoring"] == {
        "serviceMonitor": {
            "enabled": False,
            "labels": {},
            "interval": "30s",
            "scrapeTimeout": "10s",
            "sampleLimit": None,
        },
        "prometheusRule": {
            "enabled": False,
            "labels": {"severity": "warning"},
            "interactiveQueueStalledSeconds": 60,
            "reconciliationStalledSeconds": 900,
        },
        "dashboard": {
            "enabled": False,
            "labels": {"grafana_dashboard": "1"},
            "annotations": {"grafana_folder": "Extra CODEOWNERS"},
        },
    }
    assert values["highAvailability"] == {
        "enabled": False,
        "replicas": 2,
        "minAvailable": 1,
    }

    schema = json.loads((ROOT / "charts" / "extra-codeowners" / "values.schema.json").read_text())
    assert "deploymentAnnotations" in schema["required"]
    assert schema["properties"]["deploymentAnnotations"] == {"$ref": "#/definitions/stringMap"}
    assert "highAvailability" in schema["required"]
    assert schema["properties"]["highAvailability"]["properties"]["replicas"]["minimum"] == 2
    assert schema["properties"]["highAvailability"]["properties"]["minAvailable"] == {
        "type": "integer",
        "minimum": 1,
    }

    probes = schema["properties"]["probes"]
    assert "startup" in probes["required"]
    assert probes["properties"]["startup"] == {"$ref": "#/definitions/probe"}

    migrations = cast(dict[str, Any], values["migrations"])
    assert migrations["asHelmHook"] is True
    migration_schema = schema["properties"]["migrations"]
    assert "asHelmHook" in migration_schema["required"]
    assert migration_schema["properties"]["asHelmHook"] == {"type": "boolean"}

    extra_manifests_schema = schema["properties"]["extraManifests"]
    assert "extraManifests" in schema["required"]
    assert extra_manifests_schema["items"]["required"] == ["apiVersion", "kind", "metadata"]
    assert extra_manifests_schema["items"]["properties"]["metadata"]["required"] == ["name"]

    monitoring_schema = schema["properties"]["monitoring"]
    assert "monitoring" in schema["required"]
    assert monitoring_schema["required"] == ["serviceMonitor", "prometheusRule", "dashboard"]
    assert monitoring_schema["properties"]["serviceMonitor"]["required"] == [
        "enabled",
        "labels",
        "interval",
        "scrapeTimeout",
    ]
    assert monitoring_schema["properties"]["serviceMonitor"]["properties"]["sampleLimit"] == {
        "type": ["integer", "null"],
        "minimum": 0,
        "maximum": 100000,
    }

    deployment = (
        ROOT / "charts" / "extra-codeowners" / "templates" / "deployment.yaml"
    ).read_text()
    assert "{{- if .Values.probes.startup.enabled }}" in deployment
    assert "EXTRA_CODEOWNERS_REQUIRE_POSTGRESQL" in deployment
    assert 'ternary "true" "false" .Values.highAvailability.enabled' in deployment
    assert ".Values.highAvailability.enabled" in deployment
    assert "requiredDuringSchedulingIgnoredDuringExecution" in deployment
    assert "topology.kubernetes.io/zone" in deployment
    helpers = (ROOT / "charts" / "extra-codeowners" / "templates" / "_helpers.tpl").read_text()
    assert "replicaCount greater than 1 requires highAvailability.enabled" in helpers
    assert "autoscaling.maxReplicas greater than 1 requires highAvailability.enabled" in helpers
    assert "highAvailability.minAvailable must be lower" in helpers
    assert "EXTRA_CODEOWNERS_REQUIRE_POSTGRESQL" in helpers
    for field in (
        "path",
        "initialDelaySeconds",
        "periodSeconds",
        "timeoutSeconds",
        "failureThreshold",
    ):
        assert f".Values.probes.startup.{field}" in deployment

    migration_template = (
        ROOT / "charts" / "extra-codeowners" / "templates" / "migration-job.yaml"
    ).read_text()
    assert "{{- if .Values.migrations.asHelmHook }}" in migration_template
    assert '"argocd.argoproj.io/hook": Sync' in migration_template
    assert '"argocd.argoproj.io/hook-delete-policy": BeforeHookCreation,HookSucceeded' in (
        migration_template
    )

    for template in (deployment, migration_template):
        assert "- name: PATH" in template
        assert "- name: LD_PRELOAD" in template
        assert "- name: LD_AUDIT" in template
        assert "- name: SSLKEYLOGFILE" in template
        for obsolete_override in (
            "LD_LIBRARY_PATH",
            "GCONV_PATH",
            "LOCPATH",
            "OPENSSL_CONF",
            "OPENSSL_MODULES",
            "OPENSSL_ENGINES",
        ):
            assert f"- name: {obsolete_override}" not in template

    helpers = (ROOT / "charts" / "extra-codeowners" / "templates" / "_helpers.tpl").read_text()
    assert helpers.count('hasPrefix "PG" .name') == 2
    assert helpers.count("must not set ambient libpq variable") == 2
    assert 'eq $name "argocd.argoproj.io/hook"' in helpers
    assert 'eq $name "argocd.argoproj.io/hook-delete-policy"' in helpers
    assert 'define "extra-codeowners.validateExtraManifest"' in helpers
    assert 'include "extra-codeowners.validateExtraManifest" .' in helpers
    assert "extraManifests must not contain Secret objects" in helpers

    extra_manifests_template = (
        ROOT / "charts" / "extra-codeowners" / "templates" / "extra-manifests.yaml"
    ).read_text()
    assert "{{ toYaml . }}" in extra_manifests_template
    assert "tpl" not in extra_manifests_template

    service_monitor = (
        ROOT / "charts" / "extra-codeowners" / "templates" / "servicemonitor.yaml"
    ).read_text()
    assert ".Values.monitoring.serviceMonitor.enabled" in service_monitor
    assert "path: /metrics" in service_monitor
    assert "port: http" in service_monitor
    assert "if ne .Values.monitoring.serviceMonitor.sampleLimit nil" in service_monitor
    prometheus_rule = (
        ROOT / "charts" / "extra-codeowners" / "templates" / "prometheusrule.yaml"
    ).read_text()
    assert ".Values.monitoring.prometheusRule.enabled" in prometheus_rule
    assert "ExtraCodeownersInteractiveQueueStalled" in prometheus_rule
    dashboard = (ROOT / "charts" / "extra-codeowners" / "templates" / "dashboard.yaml").read_text()
    assert ".Values.monitoring.dashboard.enabled" in dashboard
    assert ".Values.monitoring.dashboard.labels" in dashboard
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "-skip ServiceMonitor,PrometheusRule" in ci


def test_chart_release_placeholders_and_public_image_are_automatic() -> None:
    chart = yaml.safe_load((ROOT / "charts" / "extra-codeowners" / "Chart.yaml").read_text())
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    readme = (ROOT / "charts" / "extra-codeowners" / "README.md").read_text(encoding="utf-8")

    assert chart["version"] == "0.0.0-dev"
    assert chart["appVersion"] == "0.0.0-dev"
    assert "helm package charts/extra-codeowners \\" in release
    assert '--version "${VERSION}" \\' in release
    assert '--app-version "${VERSION}" \\' in release
    assert 'chart="dist/extra-codeowners-${VERSION}.tgz"' in release
    assert "sed -i" not in release
    assert (
        "| `image.repository` | string | `ghcr.io/stampbot/extra-codeowners` "
        "| Public image published with each Extra CODEOWNERS release. |"
    ) in readme


def test_pinned_uv_exposes_the_scheduled_audit_interface_without_network() -> None:
    uv = shutil.which("uv")
    assert uv is not None, "the pinned uv executable must be available to the test suite"
    result = subprocess.run(  # noqa: S603
        [uv, "--preview-features", "audit-command", "audit", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "Audit the project's dependencies" in result.stdout
    assert "--locked" in result.stdout
    assert "--python-version" in result.stdout


def _committed_minimal_beta_bootstrap(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, str]]:
    checkout = tmp_path / "minimal-source"
    tools = checkout / "tools"
    tools.mkdir(parents=True)
    package = checkout / "extra_codeowners"
    package.mkdir()
    shutil.copy2(ROOT / "tools" / "evaluation_beta_bootstrap.py", tools)
    shutil.copy2(ROOT / "pyproject.toml", checkout)
    (checkout / "pyproject.toml").chmod(0o644)
    (tools / "__init__.py").write_text('"""Test tools package."""\n', encoding="utf-8")
    (package / "__init__.py").write_text(
        "from pathlib import Path\n"
        "import os\n\n"
        "Path(os.environ['CHECKOUT_PACKAGE_MARKER']).write_text('checkout', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (tools / "evaluation_beta.py").write_text(
        "from pathlib import Path\n"
        "import os\n"
        "import extra_codeowners\n\n"
        "def main() -> int:\n"
        "    Path(os.environ['CHECKOUT_MARKER']).write_text('checkout', encoding='utf-8')\n"
        "    return 0\n",
        encoding="utf-8",
    )
    for directory in (checkout, tools, package):
        directory.chmod(0o755)
    for path in checkout.rglob("*.py"):
        path.chmod(0o644)

    git_environment = os.environ.copy()
    git_environment.update(
        {
            "GIT_AUTHOR_EMAIL": "tests@example.invalid",
            "GIT_AUTHOR_NAME": "Extra CODEOWNERS tests",
            "GIT_COMMITTER_EMAIL": "tests@example.invalid",
            "GIT_COMMITTER_NAME": "Extra CODEOWNERS tests",
        }
    )
    for arguments in (
        ("init", "--quiet"),
        ("add", "."),
        ("commit", "--quiet", "-m", "test source"),
    ):
        result = subprocess.run(  # noqa: S603 - fixed Git binary and test arguments.
            ["/usr/bin/git", *arguments],
            cwd=checkout,
            env=git_environment,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    revision = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    assert revision.returncode == 0, revision.stderr
    config_path = tmp_path / "minimal-preflight.toml"
    config_path.write_text(
        f"source_checkout = {json.dumps(str(checkout))}\n"
        f"source_revision = {json.dumps(revision.stdout.strip())}\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    fake_environment = tmp_path / "minimal-venv"
    site_packages = (
        fake_environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site_packages.mkdir(parents=True)
    distribution = site_packages / f"extra_codeowners-{TEST_INSTALLED_BETA_VERSION}.dist-info"
    distribution.mkdir()
    (distribution / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: extra-codeowners\nVersion: {TEST_INSTALLED_BETA_VERSION}\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "CHECKOUT_MARKER": str(tmp_path / "checkout.executed"),
            "CHECKOUT_PACKAGE_MARKER": str(tmp_path / "checkout-package.executed"),
            "EXTRA_CODEOWNERS_BETA_CONFIG_FILE": str(config_path),
            "PYTHONDONTWRITEBYTECODE": "1",
            "VIRTUAL_ENV": str(fake_environment),
        }
    )
    return checkout, site_packages, environment


def _run_minimal_beta_bootstrap(
    checkout: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "preflight",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("index_operation", "expected_error"),
    [
        (None, "tracked source content does not exactly match HEAD"),
        ("add", "source index does not exactly match HEAD"),
        ("--assume-unchanged", "unsafe index flags"),
        ("--skip-worktree", "unsafe index flags"),
    ],
)
def test_evaluation_beta_bootstrap_rejects_tracked_code_before_import(
    tmp_path: Path,
    index_operation: str | None,
    expected_error: str,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    evaluator = checkout / "tools" / "evaluation_beta.py"
    hostile_marker = tmp_path / "tracked.executed"
    if index_operation in {"--assume-unchanged", "--skip-worktree"}:
        result = subprocess.run(  # noqa: S603 - fixed Git binary and test arguments.
            ["/usr/bin/git", "update-index", index_operation, "tools/evaluation_beta.py"],
            cwd=checkout,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
    evaluator.write_text(
        evaluator.read_text(encoding="utf-8")
        + f"\nPath({str(hostile_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    if index_operation == "add":
        result = subprocess.run(
            ["/usr/bin/git", "add", "tools/evaluation_beta.py"],
            cwd=checkout,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert expected_error in result.stderr
    assert not hostile_marker.exists()
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_prefers_reviewed_checkout_to_external_tools(
    tmp_path: Path,
) -> None:
    checkout, site_packages, environment = _committed_minimal_beta_bootstrap(tmp_path)
    external_marker = tmp_path / "external.executed"
    external_package_marker = tmp_path / "external-package.executed"
    external_tools = site_packages / "tools"
    external_tools.mkdir()
    (external_tools / "__init__.py").write_text('"""Hostile external tools."""\n', encoding="utf-8")
    (external_tools / "evaluation_beta.py").write_text(
        "from pathlib import Path\n\n"
        "def main() -> int:\n"
        f"    Path({str(external_marker)!r}).write_text('executed', encoding='utf-8')\n"
        "    return 0\n",
        encoding="utf-8",
    )
    external_package = site_packages / "extra_codeowners"
    external_package.mkdir()
    (external_package / "__init__.py").write_text(
        "from pathlib import Path\n\n"
        f"Path({str(external_package_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 0, result.stderr
    assert Path(environment["CHECKOUT_MARKER"]).read_text(encoding="utf-8") == "checkout"
    assert Path(environment["CHECKOUT_PACKAGE_MARKER"]).read_text(encoding="utf-8") == "checkout"
    assert not external_marker.exists()
    assert not external_package_marker.exists()


def test_evaluation_beta_bootstrap_ignores_hostile_stat_cache_configuration(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    evaluator = checkout / "tools" / "evaluation_beta.py"
    for key, value in (("core.checkStat", "minimal"), ("core.trustctime", "false")):
        result = subprocess.run(  # noqa: S603 - fixed Git binary and bounded test arguments.
            ["/usr/bin/git", "config", "--local", key, value],
            cwd=checkout,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
    initial = evaluator.stat()
    os.utime(
        evaluator,
        ns=(initial.st_atime_ns, initial.st_mtime_ns - 2_000_000_000),
    )
    refresh = subprocess.run(
        ["/usr/bin/git", "update-index", "--really-refresh"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    assert refresh.returncode == 0, refresh.stderr

    before = evaluator.stat()
    source = evaluator.read_bytes()
    assert b"'checkout'" in source
    evaluator.write_bytes(source.replace(b"'checkout'", b"'attacked'", 1))
    os.utime(evaluator, ns=(before.st_atime_ns, before.st_mtime_ns))

    status = subprocess.run(
        ["/usr/bin/git", "status", "--porcelain", "--untracked-files=no"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    assert status.returncode == 0, status.stderr
    assert status.stdout == ""

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert "tracked source content does not exactly match HEAD" in result.stderr
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_rejects_replacement_refs_before_import(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    git_environment = os.environ.copy()
    git_environment.update(
        {
            "GIT_AUTHOR_EMAIL": "tests@example.invalid",
            "GIT_AUTHOR_NAME": "Extra CODEOWNERS tests",
            "GIT_COMMITTER_EMAIL": "tests@example.invalid",
            "GIT_COMMITTER_NAME": "Extra CODEOWNERS tests",
        }
    )
    tree = subprocess.run(
        ["/usr/bin/git", "write-tree"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    assert tree.returncode == 0, tree.stderr
    replacement = subprocess.run(  # noqa: S603 - fixed Git and locally generated tree.
        ["/usr/bin/git", "commit-tree", tree.stdout.strip(), "-m", "replacement"],
        cwd=checkout,
        env=git_environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert replacement.returncode == 0, replacement.stderr
    replace = subprocess.run(  # noqa: S603 - fixed Git and locally generated commit.
        ["/usr/bin/git", "replace", "HEAD", replacement.stdout.strip()],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    assert replace.returncode == 0, replace.stderr

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert "replacement refs" in result.stderr
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_binds_head_to_config_before_import(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    config_path = Path(environment["EXTRA_CODEOWNERS_BETA_CONFIG_FILE"])
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        re.sub(r'(?m)^source_revision = "[0-9a-f]+"$', f'source_revision = "{"0" * 40}"', config),
        encoding="utf-8",
    )

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert "HEAD does not match configured source_revision" in result.stderr
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_normalizes_the_configured_revision(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    config_path = Path(environment["EXTRA_CODEOWNERS_BETA_CONFIG_FILE"])
    config = config_path.read_text(encoding="utf-8")
    revision = re.search(r'(?m)^source_revision = "([0-9a-f]+)"$', config)
    assert revision is not None
    config_path.write_text(
        config.replace(
            revision.group(0),
            f'source_revision = "  {revision.group(1).upper()}  "',
        ),
        encoding="utf-8",
    )

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 0, result.stderr
    assert Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_requires_an_explicit_checkout(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    config_path = Path(environment["EXTRA_CODEOWNERS_BETA_CONFIG_FILE"])
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        re.sub(r"(?m)^source_checkout = .+\n", "", config),
        encoding="utf-8",
    )

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert "must pin source_revision and source_checkout" in result.stderr
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_requires_an_external_trust_anchor(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    external_config = Path(environment["EXTRA_CODEOWNERS_BETA_CONFIG_FILE"])
    checkout_config = checkout / "preflight.toml"
    shutil.copy2(external_config, checkout_config)
    checkout_config.chmod(0o600)
    environment["EXTRA_CODEOWNERS_BETA_CONFIG_FILE"] = str(checkout_config)

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert "configuration must be outside the source checkout" in result.stderr
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


def test_evaluation_beta_bootstrap_rejects_a_tree_as_the_pinned_revision(
    tmp_path: Path,
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)
    tree = subprocess.run(
        ["/usr/bin/git", "write-tree"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    assert tree.returncode == 0, tree.stderr
    tree_id = tree.stdout.strip()
    (checkout / ".git" / "HEAD").write_text(f"{tree_id}\n", encoding="ascii")
    config_path = Path(environment["EXTRA_CODEOWNERS_BETA_CONFIG_FILE"])
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        re.sub(r'(?m)^source_revision = "[0-9a-f]+"$', f'source_revision = "{tree_id}"', config),
        encoding="utf-8",
    )

    result = _run_minimal_beta_bootstrap(checkout, environment)

    assert result.returncode == 2
    assert "source revision is not a commit object" in result.stderr
    assert not Path(environment["CHECKOUT_MARKER"]).exists()


@pytest.mark.parametrize("path", [b".", b"..", b"dir/../outside.py", b"dir/./inside.py"])
def test_evaluation_beta_bootstrap_rejects_dot_path_components(path: bytes) -> None:
    with pytest.raises(beta_bootstrap.BootstrapError, match="unsafe tracked path"):
        beta_bootstrap._safe_tracked_path(path)


def test_evaluation_beta_bootstrap_rejects_ignored_imports_before_execution(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "source"
    ignored_bytecode = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(
        Path(extra_codeowners.__file__).resolve().parent,
        checkout / "extra_codeowners",
        ignore=ignored_bytecode,
    )
    shutil.copytree(ROOT / "tools", checkout / "tools", ignore=ignored_bytecode)
    shutil.copy2(ROOT / "pyproject.toml", checkout)
    (checkout / ".gitignore").write_text(
        "__pycache__/\n*.pyc\nhttpx.py\nsitecustomize.py\nsubprocess.py\n",
        encoding="utf-8",
    )
    git_environment = os.environ.copy()
    git_environment.update(
        {
            "GIT_AUTHOR_EMAIL": "tests@example.invalid",
            "GIT_AUTHOR_NAME": "Extra CODEOWNERS tests",
            "GIT_COMMITTER_EMAIL": "tests@example.invalid",
            "GIT_COMMITTER_NAME": "Extra CODEOWNERS tests",
        }
    )
    for arguments in (
        ("init", "--quiet"),
        ("add", "."),
        ("commit", "--quiet", "-m", "test source"),
    ):
        result = subprocess.run(  # noqa: S603 - fixed Git binary and test arguments.
            ["/usr/bin/git", *arguments],
            cwd=checkout,
            env=git_environment,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
    for directory in (checkout, *checkout.rglob("*")):
        if directory.is_dir():
            directory.chmod(0o755)
    for path in checkout.rglob("*"):
        if path.is_file():
            path.chmod(0o755 if os.access(path, os.X_OK) else 0o644)

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(checkout)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["VIRTUAL_ENV"] = sys.prefix
    markers = [tmp_path / f"{name}.executed" for name in ("httpx", "sitecustomize", "subprocess")]
    hostile_source = (
        "from pathlib import Path\nPath({marker!r}).write_text('executed', encoding='utf-8')\n"
    )
    for name, marker in zip(("httpx", "sitecustomize", "subprocess"), markers, strict=True):
        (checkout / f"{name}.py").write_text(
            hostile_source.format(marker=str(marker)),
            encoding="utf-8",
        )

    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "--version",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "untracked or ignored content" in result.stderr
    assert all(not marker.exists() for marker in markers)

    for name in ("httpx", "sitecustomize", "subprocess"):
        (checkout / f"{name}.py").unlink()
    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "--version",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == extra_codeowners.__version__
    assert list(checkout.rglob("*.pyc")) == []
    assert list(checkout.rglob("__pycache__")) == []

    direct_result = subprocess.run(
        [sys.executable, "-B", "-m", "tools.evaluation_beta", "--help"],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert direct_result.returncode != 0
    assert "evaluation_beta_bootstrap.py preflight" in direct_result.stderr

    fake_environment = tmp_path / "fake-venv"
    fake_site_packages = (
        fake_environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    fake_site_packages.parent.mkdir(parents=True)
    fake_site_packages.symlink_to(checkout, target_is_directory=True)
    environment["VIRTUAL_ENV"] = str(fake_environment)
    linked_environment_result = subprocess.run(  # noqa: S603 - fixed test interpreter.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "--version",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert linked_environment_result.returncode == 2
    assert "site-packages must be outside" in linked_environment_result.stderr


@pytest.mark.parametrize("arguments", [("--help",), ("preflight", "--help"), ("--version",)])
def test_evaluation_beta_bootstrap_information_does_not_import_project_code(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    checkout, _, environment = _committed_minimal_beta_bootstrap(tmp_path)

    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            *arguments,
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    if arguments == ("--version",):
        assert result.stdout == f"{TEST_INSTALLED_BETA_VERSION}\n"
    assert not Path(environment["CHECKOUT_MARKER"]).exists()
    assert not Path(environment["CHECKOUT_PACKAGE_MARKER"]).exists()


def test_evaluation_beta_bootstrap_version_does_not_import_installed_project_code(
    tmp_path: Path,
) -> None:
    checkout, site_packages, environment = _committed_minimal_beta_bootstrap(tmp_path)
    imported_marker = tmp_path / "installed-package.executed"
    installed_package = site_packages / "extra_codeowners"
    installed_package.mkdir()
    (installed_package / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(imported_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "--version",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{TEST_INSTALLED_BETA_VERSION}\n"
    assert not imported_marker.exists()
    assert not Path(environment["CHECKOUT_PACKAGE_MARKER"]).exists()


@pytest.mark.parametrize("metadata_count", [0, 2])
def test_evaluation_beta_bootstrap_version_requires_one_installed_distribution(
    tmp_path: Path,
    metadata_count: int,
) -> None:
    checkout, site_packages, environment = _committed_minimal_beta_bootstrap(tmp_path)
    distribution = next(site_packages.glob("extra_codeowners-*.dist-info"))
    if metadata_count == 0:
        shutil.rmtree(distribution)
    else:
        duplicate = site_packages / "extra_codeowners-9.8.8.dist-info"
        duplicate.mkdir()
        (duplicate / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: extra-codeowners\nVersion: 9.8.8\n",
            encoding="utf-8",
        )

    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "--version",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "must contain exactly one Extra CODEOWNERS distribution" in result.stderr
    assert not Path(environment["CHECKOUT_PACKAGE_MARKER"]).exists()


@pytest.mark.parametrize(
    "metadata_text",
    [
        "Metadata-Version: 2.4\nName: extra-codeowners\nVersion: ../../untrusted\n",
        "Metadata-Version: 2.4\nName: extra-codeowners\nVersion: 9.8.7\nVersion: 9.8.8\n",
    ],
)
def test_evaluation_beta_bootstrap_version_rejects_invalid_distribution_metadata(
    tmp_path: Path,
    metadata_text: str,
) -> None:
    checkout, site_packages, environment = _committed_minimal_beta_bootstrap(tmp_path)
    metadata = next(site_packages.glob("extra_codeowners-*.dist-info")) / "METADATA"
    metadata.write_text(metadata_text, encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - fixed test interpreter and script.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(checkout / "tools" / "evaluation_beta_bootstrap.py"),
            "--version",
        ],
        cwd=checkout,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "installed Extra CODEOWNERS distribution metadata is invalid" in result.stderr
    assert not Path(environment["CHECKOUT_PACKAGE_MARKER"]).exists()


def test_evaluation_beta_entrypoints_use_the_isolated_bootstrap() -> None:
    mise = (ROOT / "mise.toml").read_text(encoding="utf-8")
    how_to = (ROOT / "docs" / "how-to" / "preflight-evaluation-beta.md").read_text(encoding="utf-8")
    reference = (ROOT / "docs" / "reference" / "evaluation-beta-preflight.md").read_text(
        encoding="utf-8"
    )

    command = "uv run --no-sync python -I -S -B tools/evaluation_beta_bootstrap.py preflight"
    assert command in mise
    assert command in re.sub(r"\\\n\s*", "", how_to)
    assert "python -I -S -B tools/evaluation_beta_bootstrap.py preflight" in reference
    assert "export PYTHONDONTWRITEBYTECODE=1" in how_to


def test_standalone_python_tools_are_in_every_type_check_entrypoint() -> None:
    required = {
        "tools/evaluation_beta.py",
        "tools/evaluation_beta_bootstrap.py",
        "tools/release_inventory.py",
    }
    sources = {
        "mise": (ROOT / "mise.toml").read_text(encoding="utf-8"),
        "CI": (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"),
    }
    for source_name, source in sources.items():
        for path in required:
            assert path in source, f"{source_name} does not type-check {path}"


def test_renovate_owns_ordinary_docker_uv_and_build_backend_updates() -> None:
    config = cast(
        dict[str, Any],
        json.loads((ROOT / "renovate.json").read_text(encoding="utf-8")),
    )
    managers = cast(list[dict[str, Any]], config["customManagers"])
    uv_managers = [
        manager
        for manager in managers
        if manager.get("description") == "Keep the project-owned uv version current"
    ]
    assert len(uv_managers) == 1
    uv_manager = uv_managers[0]
    assert uv_manager["managerFilePatterns"] == ["/^pyproject\\.toml$/"]
    assert uv_manager["depNameTemplate"] == "astral-sh/uv"
    assert uv_manager["datasourceTemplate"] == "github-releases"

    rules = cast(list[dict[str, Any]], config["packageRules"])
    uv_rules = [rule for rule in rules if rule.get("groupName") == "uv toolchain"]
    assert len(uv_rules) == 1
    assert set(cast(list[str], uv_rules[0]["matchPackageNames"])) == {
        "astral-sh/uv",
        "ghcr.io/astral-sh/uv",
    }
    backend_rules = [rule for rule in rules if rule.get("groupName") == "Python build backend"]
    assert len(backend_rules) == 1
    assert set(cast(list[str], backend_rules[0]["matchPackageNames"])) == {
        "hatch-vcs",
        "hatchling",
    }
    assert any(
        rule.get("matchManagers") == ["github-actions"] and rule.get("enabled") is False
        for rule in rules
    )
    assert any(rule.get("matchUpdateTypes") == ["digest"] and "schedule" in rule for rule in rules)

    raw_config = (ROOT / "renovate.json").read_text(encoding="utf-8")
    assert "requirements-build" not in raw_config
    assert "native-wheelhouse" not in raw_config

    dependabot = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert any(update["package-ecosystem"] == "github-actions" for update in dependabot["updates"])


def test_renovate_updates_the_pinned_docker_build_runtime_as_one_unit() -> None:
    config = cast(
        dict[str, Any],
        json.loads((ROOT / "renovate.json").read_text(encoding="utf-8")),
    )
    managers = cast(list[dict[str, Any]], config["customManagers"])

    buildx = [
        manager
        for manager in managers
        if manager.get("description") == "Update the pinned Buildx runtime"
    ]
    assert len(buildx) == 1
    assert buildx[0]["depNameTemplate"] == "docker/buildx"
    assert buildx[0]["datasourceTemplate"] == "github-releases"
    assert buildx[0]["versioningTemplate"] == "semver"

    images = [
        manager
        for manager in managers
        if manager.get("description") == "Update digest-pinned Docker build runtime images"
    ]
    assert len(images) == 1
    assert images[0]["datasourceTemplate"] == "docker"
    matchers = "\n".join(cast(list[str], images[0]["matchStrings"]))
    assert "moby/buildkit" in matchers
    assert "docker/buildkit-syft-scanner" in matchers

    rules = cast(list[dict[str, Any]], config["packageRules"])
    runtime_rules = [rule for rule in rules if rule.get("groupName") == "Docker build runtime"]
    assert len(runtime_rules) == 1
    assert set(cast(list[str], runtime_rules[0]["matchPackageNames"])) == {
        "docker/buildkit-syft-scanner",
        "docker/buildx",
        "moby/buildkit",
    }

    assert not any(
        manager.get("description") == "Update the local Markdown linter" for manager in managers
    )


def test_renovate_mise_manager_exclusively_owns_local_tool_versions() -> None:
    config = cast(
        dict[str, Any],
        json.loads((ROOT / "renovate.json").read_text(encoding="utf-8")),
    )
    managers = cast(list[dict[str, Any]], config["customManagers"])
    rules = cast(list[dict[str, Any]], config["packageRules"])

    for manager in managers:
        patterns = cast(list[str], manager["managerFilePatterns"])
        assert all("mise" not in pattern for pattern in patterns), manager["description"]
    assert not any(
        rule.get("matchManagers") == ["mise"] and rule.get("enabled") is False for rule in rules
    )

    local_tools = cast(dict[str, str], _load_toml(ROOT / "mise.toml")["tools"])
    assert set(local_tools) == {
        "actionlint",
        "aqua:cli/cli",
        "aqua:sigstore/cosign",
        "helm",
        "jq",
        "aqua:yannh/kubeconform",
        "node",
        "shellcheck",
        "uv",
        "npm:markdownlint-cli2",
    }

    mise = _load_toml(ROOT / "mise.toml")
    settings = cast(dict[str, Any], mise["settings"])
    assert settings["idiomatic_version_file_enable_tools"] == ["python"]
    assert re.fullmatch(r"3\.\d+", (ROOT / ".python-version").read_text().strip())


def test_readthedocs_bootstraps_the_project_owned_uv_version() -> None:
    config = cast(
        dict[str, Any],
        yaml.safe_load((ROOT / ".readthedocs.yaml").read_text(encoding="utf-8")),
    )
    build = cast(dict[str, Any], config["build"])
    jobs = cast(dict[str, list[str]], build["jobs"])
    install = jobs["install"]

    assert len(install) == 2
    bootstrap, sync = install
    assert bootstrap == "python tools/readthedocs_bootstrap.py"
    assert 'UV_PROJECT_ENVIRONMENT="$READTHEDOCS_VIRTUALENV_PATH"' in sync
    assert "uv sync --frozen --only-group docs" in sync
    assert "python" not in config

    required = cast(str, _load_toml(ROOT / "pyproject.toml")["tool"]["uv"]["required-version"])
    assert readthedocs_bootstrap.required_uv_requirement() == f"uv{required}"
    command = readthedocs_bootstrap.install_command()
    assert command[-1] == f"uv{required}"
    assert "--no-deps" in command
    assert "--only-binary=:all:" in command


def test_readthedocs_bootstrap_rejects_a_nonexact_uv_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.uv]\nrequired-version = ">=0.11"\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="must be one exact semantic version"):
        readthedocs_bootstrap.install_command(pyproject)


def test_renovate_owns_every_duplicated_ci_tool_pin() -> None:
    config = cast(
        dict[str, Any],
        json.loads((ROOT / "renovate.json").read_text(encoding="utf-8")),
    )
    managers = cast(list[dict[str, Any]], config["customManagers"])
    rules = cast(list[dict[str, Any]], config["packageRules"])
    expected: dict[str, tuple[str, str, str, set[str]]] = {
        "Keep the Helm 3 runtime current": (
            "helm/helm",
            "github-releases",
            "Helm toolchain",
            {"helm/helm"},
        ),
        "Keep the Cosign runtime current": (
            "sigstore/cosign",
            "github-releases",
            "Cosign toolchain",
            {"sigstore/cosign"},
        ),
        "Keep the Actionlint runtime current": (
            "rhysd/actionlint",
            "github-releases",
            "Actionlint toolchain",
            {"rhysd/actionlint"},
        ),
        "Keep the ShellCheck runtime current": (
            "koalaman/shellcheck",
            "docker",
            "ShellCheck toolchain",
            {"koalaman/shellcheck"},
        ),
        "Update the kubeconform validation image": (
            "ghcr.io/yannh/kubeconform",
            "docker",
            "kubeconform toolchain",
            {"ghcr.io/yannh/kubeconform", "yannh/kubeconform"},
        ),
    }

    for description, (package, datasource, group_name, group_packages) in expected.items():
        matches = [manager for manager in managers if manager.get("description") == description]
        assert len(matches) == 1
        assert matches[0]["depNameTemplate"] == package
        assert matches[0]["datasourceTemplate"] == datasource
        assert matches[0]["versioningTemplate"] == "semver"
        groups = [rule for rule in rules if rule.get("groupName") == group_name]
        assert len(groups) == 1
        assert set(cast(list[str], groups[0]["matchPackageNames"])) == group_packages

    helm_rule = next(rule for rule in rules if rule.get("groupName") == "Helm toolchain")
    assert helm_rule["allowedVersions"] == "<4.0.0"


def test_local_and_ci_validation_tool_versions_match() -> None:
    tools = cast(dict[str, str], _load_toml(ROOT / "mise.toml")["tools"])
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    workflow_security = (ROOT / ".github" / "workflows" / "workflow-security.yml").read_text(
        encoding="utf-8"
    )

    assert f"version: v{tools['helm']} # helm runtime" in ci
    assert release.count(f"version: v{tools['helm']} # helm runtime") == 3
    assert f"cosign-release: v{tools['aqua:sigstore/cosign']}" in release
    assert f"version: {tools['actionlint']} # actionlint runtime" in workflow_security
    assert f"koalaman/shellcheck:v{tools['shellcheck']}@sha256:" in ci
    assert f"ghcr.io/yannh/kubeconform:v{tools['aqua:yannh/kubeconform']}@sha256:" in ci


def test_container_builds_pin_one_consistent_buildx_and_buildkit_runtime() -> None:
    expected_step_counts = {
        "ci.yml": 1,
        "cold-container.yml": 1,
        "release.yml": 3,
    }
    runtime_pins: set[tuple[str, str, str]] = set()

    for workflow_name, expected_count in expected_step_counts.items():
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        steps = _workflow_action_steps(workflow, SETUP_BUILDX)
        assert len(steps) == expected_count
        assert workflow.count("uses: docker/setup-buildx-action@") == len(steps)
        for step in steps:
            buildx = re.search(
                r"(?m)^          version: v(?P<version>\d+\.\d+\.\d+) # buildx runtime$",
                step,
            )
            buildkit = re.search(
                r"(?m)^            image=moby/buildkit:v(?P<version>\d+\.\d+\.\d+)"
                r"@(?P<digest>sha256:[0-9a-f]{64})$",
                step,
            )
            assert buildx is not None
            assert buildkit is not None
            assert "buildkitd-flags: --debug" in step
            if workflow_name == "release.yml":
                assert "cache-binary: false" in step
            runtime_pins.add(
                (buildx.group("version"), buildkit.group("version"), buildkit.group("digest"))
            )

    assert len(runtime_pins) == 1


def test_documentation_lint_uses_one_pinned_bundled_action() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    docs = _workflow_job(workflow, "docs")

    assert re.search(
        r"(?m)^        uses: DavidAnson/markdownlint-cli2-action@[0-9a-f]{40}"
        r" # v\d+\.\d+\.\d+$",
        docs,
    )
    assert "uses: actions/setup-node@" not in docs
    assert "npx " not in docs
    local_version = cast(str, _load_toml(ROOT / "mise.toml")["tools"]["npm:markdownlint-cli2"])
    assert re.fullmatch(r"\d+\.\d+\.\d+", local_version)


def test_ci_builds_and_scans_both_architectures_natively() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    container = _workflow_job(workflow, "container")
    _assert_native_matrix(container)

    assert container.count("uses: docker/build-push-action@") == 1
    assert "load: true" in container
    assert "push: false" in container
    assert "platforms: ${{ matrix.platform }}" in container
    assert "cache-from: type=gha,scope=container-${{ matrix.architecture }}" in container
    assert (
        "cache-to: type=gha,mode=max,scope=container-${{ matrix.architecture }},"
        "ignore-error=true,timeout=5m"
    ) in container
    assert ".github/scripts/smoke-container.sh" in container
    assert container.count("uses: anchore/scan-action@") == 2
    assert container.count("by-cve: true") == 2
    assert container.count("config: .grype.yaml") == 2
    assert "fail-build: false" in container
    assert "only-fixed: false" in container
    assert "fail-build: true" in container
    assert "only-fixed: true" in container
    inventory = _workflow_step(container, "Inventory high-severity vulnerabilities")
    blocking = _workflow_step(container, "Reject fixable high-severity vulnerabilities")
    assert "vex:" not in inventory
    assert "vex: security/vex/openssl-3.5.6.openvex.json" in blocking

    required = _workflow_job(workflow, "required")
    assert "- container" in required


def test_scheduled_cold_build_proves_caches_are_optional() -> None:
    workflow = (ROOT / ".github" / "workflows" / "cold-container.yml").read_text(encoding="utf-8")
    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow

    container = _workflow_job(workflow, "container")
    _assert_native_matrix(container)
    assert container.count("uses: docker/build-push-action@") == 1
    assert "no-cache: true" in container
    assert "cache-from:" not in container
    assert "cache-to:" not in container
    assert "push: false" in container
    assert ".github/scripts/smoke-container.sh" in container


def test_successful_main_ci_automatically_plans_one_release() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    plan = _workflow_job(release, "plan")
    caller = _workflow_job(ci, "release")

    assert re.search(r"(?ms)^  push:\n    branches:\n      - main$", ci)
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in ci
    assert "queue: ${{ github.event_name == 'pull_request' && 'single' || 'max' }}" in ci
    assert "workflow_call:" in release
    assert "workflow_run:" not in release
    assert "workflow_dispatch:" not in release
    assert "needs: required" in caller
    assert "github.event_name == 'push'" in caller
    assert "github.ref == 'refs/heads/main'" in caller
    assert "uses: ./.github/workflows/release.yml" in caller
    assert "SOURCE_REVISION: ${{ github.sha }}" in plan
    assert "git merge-base --is-ancestor" in plan
    assert "origin/main" in plan
    assert "python .github/scripts/release_plan.py" in plan
    assert "release-please" not in release.lower()


def test_release_builds_native_digests_then_publishes_the_exact_manifest() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    image = _workflow_job(release, "image")
    publish = _workflow_job(release, "publish")
    _assert_native_matrix(image)

    assert re.search(r"(?m)^    needs: plan$", image)
    assert (
        "outputs: type=image,name=${{ env.IMAGE }},oci-artifact=true,push-by-digest=true" in image
    )
    assert "provenance: mode=max" in image
    assert re.search(
        r"generator=docker/buildkit-syft-scanner:\d+\.\d+\.\d+"
        r"@sha256:[0-9a-f]{64}",
        image,
    )
    assert "${IMAGE}@${DIGEST}" in image
    assert image.count("image: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}") == 2
    assert image.count("by-cve: true") == 2
    assert image.count("config: .grype.yaml") == 2
    assert "only-fixed: false" in image
    assert "only-fixed: true" in image
    inventory = _workflow_step(image, "Inventory high-severity vulnerabilities")
    blocking = _workflow_step(image, "Reject fixable high-severity vulnerabilities")
    assert "vex:" not in inventory
    assert "vex: security/vex/openssl-3.5.6.openvex.json" in blocking
    assert "digest-${{ matrix.architecture }}.txt" in image
    assert "Collect raw native filesystem inventory" in image
    assert "python -I -S -B tools/release_inventory.py" in image
    assert 'docker export "${CONTAINER_NAME}"' in image
    assert '"${IMAGE}@${platform_digest}"' in image
    assert "distribution-inventory-${{ matrix.architecture }}.json" in image

    assert "release-image-amd64-" in publish
    assert "release-image-arm64-" in publish
    assert "docker buildx imagetools create" in publish
    assert '"${IMAGE}@${amd64_build_index}"' in publish
    assert '"${IMAGE}@${arm64_build_index}"' in publish
    assert 'amd64) expected_digest="${amd64_digest}"' in publish
    assert 'arm64) expected_digest="${arm64_digest}"' in publish
    assert "linux/amd64\\nlinux/arm64" in publish
    assert "docker buildx imagetools inspect" in publish
    assert "subject-digest: ${{ steps.image.outputs.digest }}" in publish
    assert 'cosign sign --yes "${IMAGE}@${DIGEST}"' in publish
    assert "subject-path: release/python/*" in publish
    assert "subject-path: release/chart/*.tgz" in publish
    assert "subject-path: release/image/*/distribution-inventory-*.json" in publish
    assert "-name 'distribution-inventory-*.json'" in publish


def test_release_retries_are_idempotent_and_keep_versions_in_one_place() -> None:
    project = _load_toml(ROOT / "pyproject.toml")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    mise = (ROOT / "mise.toml").read_text(encoding="utf-8")

    assert "workflow_call:" in release
    assert "workflow_dispatch:" not in release
    assert "gh api --include" in release
    assert '"repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}"' in release
    assert 'if [[ "${status}" == 404 ]]' in release
    assert "already_released=true" in release
    assert "needs.plan.outputs.already_released != 'true'" in release
    assert 'git show-ref --verify --quiet "refs/tags/${TAG}"' in release
    assert 'git cat-file -t "refs/tags/${TAG}"' in release
    assert "Publish or verify multiarch image" in release
    assert "Publish or verify Helm chart" in release
    assert "version" not in project["project"]
    assert "release:prepare" not in mise
    assert "prepare_prerelease.py" not in mise

    planner = ".github/scripts/release_plan.py"
    assert planner in mise
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert planner in ci
