"""A bounded, disposable cache for authenticated discovery responses."""

from __future__ import annotations

import math
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

DEFAULT_MAX_BYTES: Final = 32 * 1024 * 1024
DEFAULT_MAX_ENTRY_BYTES: Final = 1024 * 1024
DEFAULT_MAX_ENTRIES: Final = 4096
DEFAULT_IDLE_TTL_SECONDS: Final = 3600.0
MAX_KEY_BYTES: Final = 4096
MAX_LINKS: Final = 128
MAX_LINK_BYTES: Final = 16 * 1024
MAX_ETAG_BYTES: Final = 512
_ETAG_RE = re.compile(r'^(?:W/)?"[^"\x00-\x1f\x7f]*"$')


@dataclass(frozen=True, slots=True)
class CacheEntry:
    """One validated discovery representation and its pagination links."""

    body: bytes
    etag: str
    links: tuple[str, ...] = ()


@dataclass(slots=True)
class _StoredEntry:
    entry: CacheEntry
    last_used: float
    size: int


class DiscoveryCache:
    """Keep a small in-memory LRU of response bodies for one client instance.

    The caller must send a conditional authenticated request on every reuse and
    discard the cached representation when validation fails. This cache carries
    no authority and is safe to drop when a replica or client is replaced.
    """

    def __init__(
        self,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        idle_ttl_seconds: float = DEFAULT_IDLE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (max_bytes, max_entry_bytes, max_entries)
        ):
            raise ValueError("cache bounds must be positive")
        if (
            isinstance(idle_ttl_seconds, bool)
            or not isinstance(idle_ttl_seconds, (int, float))
            or not math.isfinite(idle_ttl_seconds)
            or idle_ttl_seconds <= 0
        ):
            raise ValueError("idle_ttl_seconds must be positive")
        self.max_bytes = max_bytes
        self.max_entry_bytes = max_entry_bytes
        self.max_entries = max_entries
        self.idle_ttl_seconds = idle_ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[tuple[int, str, str], _StoredEntry] = OrderedDict()
        self._bytes = 0

    @property
    def bytes_used(self) -> int:
        """Return the accounted bytes currently held by the cache."""

        return self._bytes

    @property
    def entry_count(self) -> int:
        """Return the number of cached representations."""

        return len(self._entries)

    def get(self, key: tuple[int, str, str]) -> CacheEntry | None:
        """Return a live entry, refreshing its idle lifetime and LRU position."""

        key = self._validate_key(key)
        stored = self._entries.get(key)
        if stored is None:
            return None
        now = self._clock()
        if now - stored.last_used >= self.idle_ttl_seconds:
            self._remove_validated(key)
            return None
        stored.last_used = now
        self._entries.move_to_end(key)
        return stored.entry

    def put(self, key: tuple[int, str, str], entry: CacheEntry) -> None:
        """Store an entry, evicting oldest entries until all bounds hold."""

        key = self._validate_key(key)
        self._remove_validated(key)
        if not isinstance(entry, CacheEntry):
            raise TypeError("entry must be a CacheEntry")
        self._validate_entry(entry)
        size = self._entry_size(key, entry)
        if size > self.max_entry_bytes or size > self.max_bytes:
            raise ValueError("cache entry exceeds its configured size bound")
        now = self._clock()
        self._entries[key] = _StoredEntry(entry, now, size)
        self._bytes += size
        while len(self._entries) > self.max_entries or self._bytes > self.max_bytes:
            _, evicted = self._entries.popitem(last=False)
            self._bytes -= evicted.size

    def remove(self, key: tuple[int, str, str]) -> None:
        """Discard one entry if it exists."""

        self._remove_validated(self._validate_key(key))

    def _remove_validated(self, key: tuple[int, str, str]) -> None:
        stored = self._entries.pop(key, None)
        if stored is not None:
            self._bytes -= stored.size

    @staticmethod
    def _validate_key(key: tuple[int, str, str]) -> tuple[int, str, str]:
        if not isinstance(key, tuple) or len(key) != 3:
            raise ValueError("cache key must be (installation_id, path, query)")
        installation_id, path, query = key
        if (
            isinstance(installation_id, bool)
            or not isinstance(installation_id, int)
            or installation_id <= 0
        ):
            raise ValueError("installation_id must be a positive integer")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("path must be an absolute request path")
        if not isinstance(query, str):
            raise ValueError("query must be a canonical string")
        try:
            key_bytes = path.encode("utf-8") + query.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("cache key must be valid UTF-8") from error
        if len(key_bytes) > MAX_KEY_BYTES:
            raise ValueError("cache key is too large")
        return key

    @staticmethod
    def _validate_entry(entry: CacheEntry) -> None:
        if not isinstance(entry.body, bytes):
            raise TypeError("cache body must be bytes")
        if not isinstance(entry.etag, str):
            raise TypeError("ETag must be a string")
        try:
            etag_bytes = entry.etag.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("ETag must contain printable ASCII only") from error
        if len(etag_bytes) > MAX_ETAG_BYTES or not _ETAG_RE.fullmatch(entry.etag):
            raise ValueError("ETag must be one bounded quoted or weak quoted tag")
        if not isinstance(entry.links, tuple) or len(entry.links) > MAX_LINKS:
            raise ValueError("pagination links exceed their bound")
        total_link_bytes = 0
        for link in entry.links:
            if not isinstance(link, str):
                raise TypeError("pagination links must be strings")
            try:
                link_bytes = link.encode("ascii")
            except UnicodeEncodeError as error:
                raise ValueError("pagination links must contain ASCII only") from error
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in link):
                raise ValueError("pagination links must not contain control characters")
            total_link_bytes += len(link_bytes)
        if total_link_bytes > MAX_LINK_BYTES:
            raise ValueError("pagination links exceed their byte bound")

    @staticmethod
    def _entry_size(key: tuple[int, str, str], entry: CacheEntry) -> int:
        key_bytes = (
            len(str(key[0]).encode("ascii"))
            + len(key[1].encode("utf-8"))
            + len(key[2].encode("utf-8"))
        )
        return (
            key_bytes
            + len(entry.body)
            + len(entry.etag.encode("ascii"))
            + sum(len(link.encode("ascii")) for link in entry.links)
        )
