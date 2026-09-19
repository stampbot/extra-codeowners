import pytest

from extra_codeowners.discovery_cache import CacheEntry, DiscoveryCache

KEY = (17, "/installation/repositories", "page=1&per_page=100")


class Clock:
    value = 0.0

    def __call__(self) -> float:
        return self.value


def entry(body: bytes = b"body", etag: str = '"one"', links: tuple[str, ...] = ()) -> CacheEntry:
    return CacheEntry(body, etag, links)


def test_lru_refresh_and_entry_limit() -> None:
    clock = Clock()
    cache = DiscoveryCache(max_entries=2, clock=clock)
    second = (17, "/x", "")
    third = (17, "/y", "")
    cache.put(KEY, entry())
    cache.put(second, entry(b"two"))
    assert cache.get(KEY) == entry()
    cache.put(third, entry(b"three"))
    assert cache.get(second) is None
    assert cache.entry_count == 2


def test_byte_limit_evicts_oldest_and_replacement_accounts() -> None:
    clock = Clock()
    cache = DiscoveryCache(max_bytes=60, max_entry_bytes=100, clock=clock)
    cache.put(KEY, entry(b"123456"))
    old_bytes = cache.bytes_used
    cache.put(KEY, entry(b"x"))
    assert cache.bytes_used < old_bytes
    other = (17, "/other", "")
    cache.put(other, entry(b"123456"))
    assert cache.get(KEY) is None
    assert cache.bytes_used > 0


def test_idle_ttl_expires_without_retaining_entry() -> None:
    clock = Clock()
    cache = DiscoveryCache(idle_ttl_seconds=10, clock=clock)
    cache.put(KEY, entry())
    clock.value = 9
    assert cache.get(KEY) is not None
    clock.value = 19
    assert cache.get(KEY) is None
    assert cache.bytes_used == 0


@pytest.mark.parametrize("etag", ["*", "W/*", "bare", '"bad\nvalue"', '"é"', '"' + "x" * 512 + '"'])
def test_invalid_etag_is_rejected(etag: str) -> None:
    cache = DiscoveryCache()
    with pytest.raises(ValueError):
        cache.put(KEY, entry(etag=etag))
    assert cache.get(KEY) is None


def test_rejected_replacement_removes_old_entry() -> None:
    cache = DiscoveryCache()
    cache.put(KEY, entry())
    with pytest.raises(ValueError):
        cache.put(KEY, entry(etag="not-quoted"))
    assert cache.get(KEY) is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_bytes": True},
        {"max_entries": 1.5},
        {"idle_ttl_seconds": float("nan")},
        {"idle_ttl_seconds": float("inf")},
    ],
)
def test_constructor_rejects_invalid_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        DiscoveryCache(**kwargs)  # type: ignore[arg-type]


def test_huge_key_and_links_are_rejected() -> None:
    cache = DiscoveryCache()
    with pytest.raises(ValueError):
        cache.put((17, "/" + "x" * 5000, ""), entry())
    with pytest.raises(ValueError):
        cache.put(KEY, entry(links=("x" * 20000,)))
    with pytest.raises(ValueError):
        cache.put(KEY, entry(links=("ok", "bad\x00")))


def test_oversized_replacement_removes_old_entry() -> None:
    cache = DiscoveryCache(max_entry_bytes=60)
    cache.put(KEY, entry(b"ok"))
    with pytest.raises(ValueError):
        cache.put(KEY, entry(b"too large"))
    assert cache.get(KEY) is None
    assert cache.bytes_used == 0


def test_remove_updates_accounting_and_is_idempotent() -> None:
    cache = DiscoveryCache()
    cache.put(KEY, entry())
    assert cache.bytes_used > 0
    cache.remove(KEY)
    cache.remove(KEY)
    assert cache.entry_count == 0
    assert cache.bytes_used == 0
