"""Local encoding saves storage without changing admission or revalidation."""

import hashlib
import zlib
from unittest.mock import patch

import pytest

from extra_codeowners.discovery_cache import CacheEntry, DiscoveryCache

KEY = (17, "/installation/repositories", "page=1")
BODY = b'{"description":"a repeated description"}' * 100
ENTRY = CacheEntry(BODY, 'W/"one"', ("https://api.example.test/page/2",))


def test_encoding_round_trip_preserves_entity_and_accounts_retained_bytes() -> None:
    cache = DiscoveryCache(compress=True)
    cache.put(KEY, ENTRY)
    assert cache.get(KEY) == ENTRY
    assert cache._entries[KEY].compressed
    assert cache.bytes_used == cache._entry_size(
        KEY, CacheEntry(zlib.compress(BODY, level=1), ENTRY.etag, ENTRY.links)
    )
    cache.put(KEY, CacheEntry(b"tiny", '"two"'))
    assert not cache._entries[KEY].compressed
    assert cache.bytes_used == cache._entry_size(KEY, CacheEntry(b"tiny", '"two"'))
    cache.remove(KEY)
    assert cache.bytes_used == 0
    assert cache.entry_count == 0


def test_encoded_entries_avoid_byte_evictions_without_expanding_budget() -> None:
    raw = DiscoveryCache(max_bytes=8000)
    encoded = DiscoveryCache(max_bytes=8000, compress=True)
    keys = [(17, f"/repos/example/project-{index}/pulls", "") for index in range(20)]
    for key in keys:
        raw.put(key, ENTRY)
        encoded.put(key, ENTRY)
    assert raw.entry_count < len(keys)
    assert encoded.entry_count == len(keys)
    assert encoded.bytes_used <= 8000
    assert all(encoded.get(key) == ENTRY for key in keys)


@pytest.mark.parametrize("body", [b"", b"tiny", hashlib.shake_256(b"fixture").digest(1000)])
def test_nonbeneficial_encoding_keeps_original_body(body: bytes) -> None:
    cache = DiscoveryCache(compress=True)
    entry = CacheEntry(body, '"one"')
    cache.put(KEY, entry)
    assert not cache._entries[KEY].compressed
    assert cache.get(KEY) == entry
    assert cache.bytes_used == cache._entry_size(KEY, entry)


@pytest.mark.parametrize("byte_bounds", [(1000, 8000), (8000, 1000)])
def test_compressible_raw_entry_still_has_to_fit_admission_bound(
    byte_bounds: tuple[int, int],
) -> None:
    events: list[str] = []
    cache = DiscoveryCache(
        compress=True,
        observer=events.append,
        max_bytes=byte_bounds[0],
        max_entry_bytes=byte_bounds[1],
    )
    with pytest.raises(ValueError, match="size bound"):
        cache.put(KEY, ENTRY)
    assert cache.bytes_used == 0
    assert cache.entry_count == 0
    assert events == ["rejected_size"]


def test_encoding_failure_falls_back_to_original_storage() -> None:
    cache = DiscoveryCache(compress=True)
    with patch("extra_codeowners.discovery_cache.zlib.compress", side_effect=zlib.error("codec")):
        cache.put(KEY, ENTRY)
    assert not cache._entries[KEY].compressed
    assert cache.get(KEY) == ENTRY
    assert cache.bytes_used == cache._entry_size(KEY, ENTRY)


@pytest.mark.parametrize(
    "encoded",
    [
        b"not a zlib stream",
        zlib.compress(BODY)[:-1],
        zlib.compress(BODY) + b"trailing data",
        zlib.compress(BODY) + zlib.compress(BODY),
        zlib.compress(b"x" * 100_000),
    ],
)
def test_invalid_or_expanding_encoding_is_removed_and_becomes_a_miss(encoded: bytes) -> None:
    # Verifies XCO-001: corrupt local state cannot supply authorization evidence.
    events: list[str] = []
    cache = DiscoveryCache(compress=True, max_entry_bytes=8000, observer=events.append)
    cache.put(KEY, ENTRY)
    stored = cache._entries[KEY]
    stored.entry = CacheEntry(encoded, ENTRY.etag, ENTRY.links)
    assert cache.lookup(KEY) == (None, "absent")
    assert cache.bytes_used == 0
    assert cache.entry_count == 0
    assert events == ["stored", "rejected_encoding"]


def test_encoded_entries_keep_installation_isolation_lru_and_count_limits() -> None:
    cache = DiscoveryCache(compress=True, max_entries=2)
    other_installation = (18, KEY[1], KEY[2])
    third = (17, "/other", "")
    cache.put(KEY, ENTRY)
    assert cache.get(other_installation) is None
    cache.put(other_installation, CacheEntry(BODY, '"other"'))
    assert cache.get(KEY) == ENTRY
    cache.put(third, ENTRY)
    assert cache.get(other_installation) is None
    assert cache.entry_count == 2
    cache.remove(KEY)
    cache.remove(third)
    assert cache.bytes_used == 0


def test_encoded_entries_keep_idle_expiration() -> None:
    now = 0.0
    cache = DiscoveryCache(compress=True, idle_ttl_seconds=10, clock=lambda: now)
    cache.put(KEY, ENTRY)
    now = 10.0
    assert cache.lookup(KEY) == (None, "expired")
    assert cache.bytes_used == 0


def test_encoded_entries_still_evict_at_accounted_byte_limit() -> None:
    events: list[str] = []
    cache = DiscoveryCache(compress=True, max_bytes=8000, observer=events.append)
    for index in range(200):
        cache.put((17, f"/repos/example/project-{index}/pulls", ""), ENTRY)
    assert cache.bytes_used <= 8000
    assert cache.entry_count < 200
    assert "evicted_bytes" in events
