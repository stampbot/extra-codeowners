"""Keep compact discovery evidence reusable when PR pages exceed their budget."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from prometheus_client import Counter as PrometheusCounter
from prometheus_client import Gauge

from extra_codeowners.github import GitHubClient, _request_operation
from extra_codeowners.metrics import (
    GITHUB_DISCOVERY_CACHE_BYTES,
    GITHUB_DISCOVERY_CACHE_ENTRIES,
    GITHUB_DISCOVERY_CACHE_LOOKUPS,
)


def metric_value(
    metric: PrometheusCounter | Gauge, sample_name: str, labels: dict[str, str]
) -> float:
    for family in metric.collect():
        for sample in family.samples:
            if sample.name == sample_name and sample.labels == labels:
                return float(sample.value)
    return 0


@pytest.mark.asyncio
async def test_large_pages_cannot_evict_small_checks_or_branch_refs(private_key: str) -> None:
    statuses: Counter[tuple[str, int]] = Counter()

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "test",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        operation = _request_operation("GET", path)
        if request.headers.get("if-none-match") == '"entity"':
            statuses[operation, 304] += 1
            return httpx.Response(304)
        statuses[operation, 200] += 1
        body: Any
        if operation == "pull.list":
            # A live PR-list page was about 45 kB. One thousand such pages
            # exceed the page budget without exceeding the per-entry limit.
            body = [{"number": 1, "body": "x" * 45_000}]
        elif operation == "check.list":
            body = {"total_count": 0, "check_runs": []}
        else:
            assert operation == "repository.ref"
            body = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "b" * 40}}
        return httpx.Response(200, json=body, headers={"etag": '"entity"'})

    hits_before = metric_value(
        GITHUB_DISCOVERY_CACHE_LOOKUPS,
        "extra_codeowners_github_discovery_cache_lookups_total",
        {"cache": "compact", "result": "hit"},
    )
    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        for _cycle in range(2):
            for number in range(1000):
                repository = f"example/project-{number}"
                assert len(await client.list_open_pulls(17, repository)) == 1
                assert await client.get_branch_head(17, repository, "main") == "b" * 40
                for head in ("a" * 40, "c" * 40):
                    assert not await client.has_reconciliation_check(
                        17, repository, head, "Extra CODEOWNERS / approval"
                    )
        assert statuses["pull.list", 200] == 2000
        assert statuses["check.list", 200] == 2000
        assert statuses["check.list", 304] == 2000
        assert statuses["repository.ref", 200] == 1000
        assert statuses["repository.ref", 304] == 1000
        assert client._compact_discovery_cache.entry_count == 3000
        assert (
            client._discovery_cache.bytes_used + client._compact_discovery_cache.bytes_used
            <= 32 * 1024 * 1024
        )
        for name, cache in (
            ("pages", client._discovery_cache),
            ("compact", client._compact_discovery_cache),
        ):
            assert (
                metric_value(
                    GITHUB_DISCOVERY_CACHE_BYTES,
                    "extra_codeowners_github_discovery_cache_bytes",
                    {"cache": name},
                )
                == cache.bytes_used
            )
            assert (
                metric_value(
                    GITHUB_DISCOVERY_CACHE_ENTRIES,
                    "extra_codeowners_github_discovery_cache_entries",
                    {"cache": name},
                )
                == cache.entry_count
            )
        assert (
            metric_value(
                GITHUB_DISCOVERY_CACHE_LOOKUPS,
                "extra_codeowners_github_discovery_cache_lookups_total",
                {"cache": "compact", "result": "hit"},
            )
            - hits_before
            == 3000
        )
    finally:
        await client.close()


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/repos/example/project", "repository.get"),
        ("/repos/example/project/pulls", "pull.list"),
        ("/repos/example/project/pulls/1", "pull.get"),
        ("/repos/example/project/git/ref/heads/main", "repository.ref"),
    ],
)
def test_discovery_operations_have_fixed_metric_labels(path: str, expected: str) -> None:
    assert _request_operation("GET", path) == expected
