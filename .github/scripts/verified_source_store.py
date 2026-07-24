#!/usr/bin/env python3
"""Validate a bounded, content-addressed verified-source store without writing it.

Successful verification is a point-in-time observation of bytes read through
retained file descriptors. It does not make a writable store immutable. Before
using any object, a consumer must bind the plan to its own trusted digest and
either verify the object as part of that read or copy the store behind a trusted
read-only boundary.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NamedTuple, NoReturn, NotRequired, TypedDict, cast

SCHEMA_VERSION = 1
PLAN_MEDIA_TYPE = "application/vnd.stampbot.container-source-plan.v1+json"
STORE_MEDIA_TYPE = "application/vnd.stampbot.verified-source-store.v1+json"
RESULT_KIND = "extra-codeowners/source-store-verification"
SUPPORTED_PLAN_KINDS = frozenset({"alpine-distfiles", "direct"})
SUPPORTED_EVIDENCE_SCHEMA_VERSION = 7

PLAN_FILENAME = "SOURCE-PLAN.json"
STORE_FILENAME = "SOURCE-STORE.json"
OBJECTS_DIRECTORY = "objects"
OBJECT_ALGORITHM = "sha256"
OBJECT_DIRECTORY = f"{OBJECTS_DIRECTORY}/{OBJECT_ALGORITHM}"

MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_STORE_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024
MAX_OBJECT_BYTES = 128 * 1024 * 1024
MAX_TOTAL_OBJECT_BYTES = 1024 * 1024 * 1024
MAX_REQUESTS = 512
MAX_OBJECTS = 512
MAX_ATTEMPTS = 4
MAX_REDIRECTS = 5
MAX_ALLOWED_HOSTS = 32
MAX_CONSUMERS_PER_REQUEST = 512
MAX_TOTAL_CONSUMER_REFERENCES = 2_048
MAX_TOKEN_BYTES = 512
MAX_URL_BYTES = 16 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 1_000_000
MAX_RETRY_DELAY_SECONDS = 60
MAX_INVENTORY_DIAGNOSTICS = 8
READ_CHUNK_BYTES = 1024 * 1024

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
_LOWER_SHA512 = re.compile(r"[0-9a-f]{128}")
_LOWER_COMMIT = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@#+-]*")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_RETRYABLE_HTTP_STATUSES = frozenset({408, 429, *range(500, 600)})
_ATTEMPT_OUTCOMES = frozenset({"retryable_transport", "retryable_http", "success"})


class SourceStoreError(RuntimeError):
    """The source-store contract or filesystem does not verify."""


class DigestDescriptor(TypedDict):
    algorithm: str
    digest: str
    size: int


class SourcePlanRequest(TypedDict):
    id: str
    url: str
    allowed_hosts: list[str]
    algorithm: str
    digest: str
    expected_size: int | None
    max_bytes: int
    consumers: list[str]


class AlpineRecipeBinding(TypedDict):
    request_id: str
    object_sha256: str
    size: int


class SourcePlan(TypedDict):
    schema_version: int
    media_type: str
    kind: str
    evidence_schema_version: int
    source_revision: str
    policy_sha256: str
    uv_lock_sha256: str
    requests: list[SourcePlanRequest]
    parent_plan: NotRequired[DigestDescriptor]
    parent_manifest: NotRequired[DigestDescriptor]
    recipes: NotRequired[list[AlpineRecipeBinding]]


class FetchAttempt(TypedDict):
    number: int
    outcome: str
    http_status: int | None
    redirect_origins: list[str]
    received_size: int | None
    sha256: str | None
    retry_delay_seconds: int | None


class StoreRequest(TypedDict):
    id: str
    request_origin: str
    algorithm: str
    digest: str
    expected_size: int | None
    max_bytes: int
    object_sha256: str
    size: int
    path: str
    redirect_origins: list[str]
    attempts: list[FetchAttempt]


class StoreObject(TypedDict):
    algorithm: str
    digest: str
    size: int
    path: str


class SourceStore(TypedDict):
    schema_version: int
    media_type: str
    kind: str
    plan_sha256: str
    plan_size: int
    objects: list[StoreObject]
    results: list[StoreRequest]


class VerificationResult(TypedDict):
    schema_version: int
    kind: str
    plan: DigestDescriptor
    manifest: DigestDescriptor
    request_count: int
    object_count: int
    total_object_bytes: int


class VerifiedSourceRead(NamedTuple):
    """Verified bytes, the exact plan URL, and credential-safe redirect origins."""

    content: bytes
    request_url: str
    redirect_origins: tuple[str, ...]

    @property
    def redirect_chain(self) -> tuple[str, ...]:
        """Return the exact request URL followed by safe redirect origins.

        This compatibility view never returns a redirected path or query. New
        consumers should use ``request_url`` and ``redirect_origins`` directly.
        """

        return (self.request_url, *self.redirect_origins[1:])


class FileIdentity(NamedTuple):
    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int


class DirectoryIdentity(NamedTuple):
    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int


class RetainedFile(NamedTuple):
    descriptor: int
    identity: FileIdentity
    name: str
    source: str
    parent_descriptor: int


def canonical_json(value: object) -> bytes:
    """Return the single accepted JSON encoding, including its final line feed."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SourceStoreError("value cannot be encoded as canonical JSON") from exc
    return encoded + b"\n"


def _reject_constant(value: str) -> NoReturn:
    raise SourceStoreError(f"JSON contains a non-finite number: {value}")


def _reject_float(_value: str) -> NoReturn:
    raise SourceStoreError("JSON contains a floating-point number")


def _parse_integer(value: str) -> int:
    if len(value.removeprefix("-")) > 20:
        raise SourceStoreError("JSON integer exceeds its lexical bound")
    return int(value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceStoreError("JSON repeats an object key")
        result[key] = value
    return result


def strict_json_bytes(raw: bytes, source: str, *, maximum: int) -> object:
    """Parse one bounded canonical JSON value without lossy normalization."""

    if not 1 <= len(raw) <= maximum:
        raise SourceStoreError(f"{source} is outside its byte bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceStoreError(f"{source} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_parse_integer,
        )
    except SourceStoreError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SourceStoreError(f"{source} is not valid bounded JSON") from exc

    count = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_JSON_ITEMS:
            raise SourceStoreError(f"{source} has too many JSON values")
        if depth > MAX_JSON_DEPTH:
            raise SourceStoreError(f"{source} exceeds the JSON depth limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            raise SourceStoreError(f"{source} contains a floating-point number")

    if canonical_json(value) != raw:
        raise SourceStoreError(f"{source} is not canonical JSON")
    return value


def _exact_mapping(value: object, fields: frozenset[str], source: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SourceStoreError(f"{source} must contain exactly {sorted(fields)}")
    return cast(dict[str, Any], value)


def _bounded_integer(
    value: object,
    source: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise SourceStoreError(f"{source} is outside its integer bound")
    return value


def _nullable_size(value: object, source: str, *, maximum: int) -> int | None:
    if value is None:
        return None
    return _bounded_integer(value, source, minimum=1, maximum=maximum)


def _bounded_ascii(value: object, source: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise SourceStoreError(f"{source} must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SourceStoreError(f"{source} must contain only ASCII") from exc
    if not 1 <= len(encoded) <= maximum:
        raise SourceStoreError(f"{source} is outside its string bound")
    return value


def _request_id(value: object, source: str) -> str:
    identifier = _bounded_ascii(value, source, maximum=MAX_TOKEN_BYTES)
    if not _TOKEN.fullmatch(identifier):
        raise SourceStoreError(f"{source} is not a safe request ID")
    return identifier


def _hostname(value: object, source: str) -> str:
    hostname = _bounded_ascii(value, source, maximum=253)
    if hostname != hostname.lower() or hostname.endswith("."):
        raise SourceStoreError(f"{source} must be a lowercase DNS hostname")
    labels = hostname.split(".")
    if not labels or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise SourceStoreError(f"{source} is not a canonical DNS hostname")
    return hostname


def _https_url(value: object, source: str) -> tuple[str, str]:
    url = _bounded_ascii(value, source, maximum=MAX_URL_BYTES)
    if (
        not url.startswith("https://")
        or "#" in url
        or "\\" in url
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url)
    ):
        raise SourceStoreError(f"{source} must be one bounded HTTPS URL")
    remainder = url.removeprefix("https://")
    separators = [index for token in ("/", "?") if (index := remainder.find(token)) >= 0]
    authority = remainder[: min(separators)] if separators else remainder
    if not authority or "@" in authority or authority.count(":") > 1:
        raise SourceStoreError(f"{source} has an invalid HTTPS authority")
    if ":" in authority:
        hostname, port = authority.rsplit(":", maxsplit=1)
        if port != "443":
            raise SourceStoreError(f"{source} must use HTTPS port 443")
    else:
        hostname = authority
    if hostname != hostname.lower():
        raise SourceStoreError(f"{source} hostname must be lowercase")
    tail = remainder[len(authority) :]
    if not tail.startswith("/"):
        raise SourceStoreError(f"{source} must contain an absolute path")
    canonical_hostname = _hostname(hostname, f"{source} hostname")
    return url, canonical_hostname


def _https_origin(hostname: str) -> str:
    """Return the only persisted redirect representation."""

    return f"https://{hostname}/"


def _digest(value: object, algorithm: str, source: str) -> str:
    digest = _bounded_ascii(value, source, maximum=128)
    pattern = _LOWER_SHA256 if algorithm == "sha256" else _LOWER_SHA512
    if not pattern.fullmatch(digest):
        raise SourceStoreError(f"{source} is not a lowercase {algorithm} digest")
    return digest


def _algorithm(value: object, source: str, *, object_only: bool = False) -> str:
    accepted = {OBJECT_ALGORITHM} if object_only else {"sha256", "sha512"}
    if not isinstance(value, str) or value not in accepted:
        raise SourceStoreError(f"{source} has an unsupported digest algorithm")
    return value


def _no_case_collisions(values: Sequence[str], source: str) -> None:
    if len({value.casefold() for value in values}) != len(values):
        raise SourceStoreError(f"{source} contains case-colliding names")


def _allowed_hosts(value: object, request_host: str, source: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ALLOWED_HOSTS:
        raise SourceStoreError(f"{source} is outside its host-count bound")
    hosts = [_hostname(item, f"{source} entry") for item in value]
    if hosts != sorted(hosts) or len(hosts) != len(set(hosts)):
        raise SourceStoreError(f"{source} must be sorted and unique")
    _no_case_collisions(hosts, source)
    if request_host not in hosts:
        raise SourceStoreError(f"{source} does not include the requested host")
    return hosts


def _consumers(value: object, source: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CONSUMERS_PER_REQUEST:
        raise SourceStoreError(f"{source} is outside its consumer-count bound")
    consumers: list[str] = []
    for item in value:
        consumer = _bounded_ascii(item, f"{source} entry", maximum=MAX_TOKEN_BYTES)
        if not _TOKEN.fullmatch(consumer):
            raise SourceStoreError(f"{source} contains an unsafe consumer")
        consumers.append(consumer)
    if consumers != sorted(consumers) or len(consumers) != len(set(consumers)):
        raise SourceStoreError(f"{source} must be sorted and unique")
    _no_case_collisions(consumers, source)
    return consumers


def _redirect_origins(value: object, allowed_hosts: set[str], source: str) -> list[str]:
    """Validate one ordered list of canonical HTTPS origins.

    An entry records a hop but never its path, query, fragment, or credentials.
    Repeated origins are valid because redirects can stay on the same host.
    """

    if not isinstance(value, list) or not 1 <= len(value) <= MAX_REDIRECTS + 1:
        raise SourceStoreError(f"{source} is outside its redirect-count bound")
    result: list[str] = []
    for index, raw_origin in enumerate(value):
        origin, hostname = _https_url(raw_origin, f"{source} entry {index + 1}")
        if hostname not in allowed_hosts:
            raise SourceStoreError(f"{source} uses a host outside the plan allowlist")
        if origin != _https_origin(hostname):
            raise SourceStoreError(f"{source} must contain only canonical HTTPS origins")
        result.append(origin)
    return result


def _digest_descriptor(
    value: object,
    source: str,
    *,
    maximum: int,
) -> DigestDescriptor:
    record = _exact_mapping(
        value,
        frozenset({"algorithm", "digest", "size"}),
        source,
    )
    algorithm = _algorithm(record["algorithm"], f"{source} algorithm", object_only=True)
    return {
        "algorithm": algorithm,
        "digest": _digest(record["digest"], algorithm, f"{source} digest"),
        "size": _bounded_integer(record["size"], f"{source} size", minimum=1, maximum=maximum),
    }


def validate_source_plan(value: object) -> SourcePlan:
    """Validate the exact v1 fetch-plan schema and semantic ordering."""

    if not isinstance(value, dict):
        raise SourceStoreError("source plan must be an object")
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in SUPPORTED_PLAN_KINDS:
        raise SourceStoreError("source plan has the wrong kind")
    fields = {
        "schema_version",
        "media_type",
        "kind",
        "evidence_schema_version",
        "source_revision",
        "policy_sha256",
        "uv_lock_sha256",
        "requests",
    }
    if kind == "alpine-distfiles":
        fields.update({"parent_plan", "parent_manifest", "recipes"})
    record = _exact_mapping(
        value,
        frozenset(fields),
        "source plan",
    )
    if (
        _bounded_integer(
            record["schema_version"],
            "source plan schema_version",
            minimum=SCHEMA_VERSION,
            maximum=SCHEMA_VERSION,
        )
        != SCHEMA_VERSION
    ):
        raise SourceStoreError("source plan has an unsupported schema version")
    if record["media_type"] != PLAN_MEDIA_TYPE:
        raise SourceStoreError("source plan has the wrong media type")
    if (
        _bounded_integer(
            record["evidence_schema_version"],
            "source plan evidence_schema_version",
            minimum=SUPPORTED_EVIDENCE_SCHEMA_VERSION,
            maximum=SUPPORTED_EVIDENCE_SCHEMA_VERSION,
        )
        != SUPPORTED_EVIDENCE_SCHEMA_VERSION
    ):
        raise SourceStoreError("source plan has the wrong evidence schema version")
    source_revision = _bounded_ascii(
        record["source_revision"],
        "source plan source_revision",
        maximum=40,
    )
    if not _LOWER_COMMIT.fullmatch(source_revision):
        raise SourceStoreError("source plan has a noncanonical source revision")
    policy_sha256 = _digest(
        record["policy_sha256"],
        "sha256",
        "source plan policy_sha256",
    )
    uv_lock_sha256 = _digest(
        record["uv_lock_sha256"],
        "sha256",
        "source plan uv_lock_sha256",
    )
    raw_requests = record["requests"]
    if not isinstance(raw_requests, list) or not 1 <= len(raw_requests) <= MAX_REQUESTS:
        raise SourceStoreError("source plan is outside its request-count bound")

    requests: list[SourcePlanRequest] = []
    for index, raw_request in enumerate(raw_requests):
        source = f"source plan request {index + 1}"
        request_record = _exact_mapping(
            raw_request,
            frozenset(
                {
                    "id",
                    "url",
                    "allowed_hosts",
                    "algorithm",
                    "digest",
                    "expected_size",
                    "max_bytes",
                    "consumers",
                }
            ),
            source,
        )
        identifier = _request_id(request_record["id"], f"{source} id")
        url, request_host = _https_url(request_record["url"], f"{source} url")
        algorithm = _algorithm(request_record["algorithm"], f"{source} algorithm")
        maximum = _bounded_integer(
            request_record["max_bytes"],
            f"{source} max_bytes",
            minimum=1,
            maximum=MAX_OBJECT_BYTES,
        )
        expected_size = _nullable_size(
            request_record["expected_size"],
            f"{source} expected_size",
            maximum=maximum,
        )
        requests.append(
            {
                "id": identifier,
                "url": url,
                "allowed_hosts": _allowed_hosts(
                    request_record["allowed_hosts"],
                    request_host,
                    f"{source} allowed_hosts",
                ),
                "algorithm": algorithm,
                "digest": _digest(
                    request_record["digest"],
                    algorithm,
                    f"{source} digest",
                ),
                "expected_size": expected_size,
                "max_bytes": maximum,
                "consumers": _consumers(
                    request_record["consumers"],
                    f"{source} consumers",
                ),
            }
        )

    identifiers = [request["id"] for request in requests]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise SourceStoreError("source plan request IDs must be sorted and unique")
    _no_case_collisions(identifiers, "source plan request IDs")
    if sum(len(request["consumers"]) for request in requests) > MAX_TOTAL_CONSUMER_REFERENCES:
        raise SourceStoreError("source plan has too many consumer references")

    by_url: dict[str, tuple[str, str, int | None]] = {}
    digest_sizes: dict[tuple[str, str], int] = {}
    for plan_request_item in requests:
        binding = (
            plan_request_item["algorithm"],
            plan_request_item["digest"],
            plan_request_item["expected_size"],
        )
        previous = by_url.get(plan_request_item["url"])
        if previous is not None and (
            previous[:2] != binding[:2]
            or (previous[2] is not None and binding[2] is not None and previous[2] != binding[2])
        ):
            raise SourceStoreError("source plan gives one URL conflicting object bindings")
        by_url[plan_request_item["url"]] = binding
        if plan_request_item["expected_size"] is not None:
            identity = (plan_request_item["algorithm"], plan_request_item["digest"])
            previous_size = digest_sizes.setdefault(identity, plan_request_item["expected_size"])
            if previous_size != plan_request_item["expected_size"]:
                raise SourceStoreError("source plan gives one digest conflicting sizes")

    result: SourcePlan = {
        "schema_version": SCHEMA_VERSION,
        "media_type": PLAN_MEDIA_TYPE,
        "kind": kind,
        "evidence_schema_version": SUPPORTED_EVIDENCE_SCHEMA_VERSION,
        "source_revision": source_revision,
        "policy_sha256": policy_sha256,
        "uv_lock_sha256": uv_lock_sha256,
        "requests": requests,
    }
    if kind == "alpine-distfiles":
        result["parent_plan"] = _digest_descriptor(
            record["parent_plan"],
            "source plan parent_plan",
            maximum=MAX_PLAN_BYTES,
        )
        result["parent_manifest"] = _digest_descriptor(
            record["parent_manifest"],
            "source plan parent_manifest",
            maximum=MAX_STORE_BYTES,
        )
        raw_recipes = record["recipes"]
        if not isinstance(raw_recipes, list) or not 1 <= len(raw_recipes) <= MAX_REQUESTS:
            raise SourceStoreError("source plan is outside its recipe-count bound")
        recipes: list[AlpineRecipeBinding] = []
        for index, raw_recipe in enumerate(raw_recipes, start=1):
            source = f"source plan recipe {index}"
            recipe = _exact_mapping(
                raw_recipe,
                frozenset({"request_id", "object_sha256", "size"}),
                source,
            )
            recipes.append(
                {
                    "request_id": _request_id(recipe["request_id"], f"{source} request_id"),
                    "object_sha256": _digest(
                        recipe["object_sha256"],
                        "sha256",
                        f"{source} object_sha256",
                    ),
                    "size": _bounded_integer(
                        recipe["size"],
                        f"{source} size",
                        minimum=1,
                        maximum=MAX_OBJECT_BYTES,
                    ),
                }
            )
        recipe_ids = [recipe["request_id"] for recipe in recipes]
        if recipe_ids != sorted(recipe_ids) or len(recipe_ids) != len(set(recipe_ids)):
            raise SourceStoreError("source plan recipe IDs must be sorted and unique")
        _no_case_collisions(recipe_ids, "source plan recipe IDs")
        result["recipes"] = recipes
    return result


def _validate_attempt(
    value: object,
    *,
    index: int,
    maximum: int,
    allowed_hosts: set[str],
    request_origin: str,
    source: str,
) -> FetchAttempt:
    attempt = _exact_mapping(
        value,
        frozenset(
            {
                "number",
                "outcome",
                "http_status",
                "redirect_origins",
                "received_size",
                "sha256",
                "retry_delay_seconds",
            }
        ),
        source,
    )
    number = _bounded_integer(
        attempt["number"],
        f"{source} number",
        minimum=1,
        maximum=MAX_ATTEMPTS,
    )
    if number != index:
        raise SourceStoreError(f"{source} numbers are not contiguous")
    outcome = attempt["outcome"]
    if not isinstance(outcome, str) or outcome not in _ATTEMPT_OUTCOMES:
        raise SourceStoreError(f"{source} has an unsupported outcome")
    status_value = attempt["http_status"]
    status = (
        None
        if status_value is None
        else _bounded_integer(status_value, f"{source} http_status", minimum=100, maximum=599)
    )
    received_value = attempt["received_size"]
    received_size = (
        None
        if received_value is None
        else _bounded_integer(
            received_value,
            f"{source} received_size",
            minimum=0,
            maximum=maximum,
        )
    )
    raw_sha256 = attempt["sha256"]
    sha256 = None if raw_sha256 is None else _digest(raw_sha256, "sha256", f"{source} sha256")
    retry_value = attempt["retry_delay_seconds"]
    retry_delay = (
        None
        if retry_value is None
        else _bounded_integer(
            retry_value,
            f"{source} retry_delay_seconds",
            minimum=0,
            maximum=MAX_RETRY_DELAY_SECONDS,
        )
    )
    redirect_origins = _redirect_origins(
        attempt["redirect_origins"],
        allowed_hosts,
        f"{source} redirect_origins",
    )
    if redirect_origins[0] != request_origin:
        raise SourceStoreError(f"{source} redirect origins do not start with the request origin")

    if outcome == "success":
        if status != 200 or received_size is None or sha256 is None or retry_delay is not None:
            raise SourceStoreError(f"{source} has an invalid success result")
    elif outcome == "retryable_http":
        if (
            status not in _RETRYABLE_HTTP_STATUSES
            or received_size is not None
            or sha256 is not None
            or retry_delay is None
        ):
            raise SourceStoreError(f"{source} has an invalid retryable HTTP result")
    elif (
        status is not None
        or retry_delay != 1 << (number - 1)
        or (received_size is None) != (sha256 is None)
    ):
        raise SourceStoreError(f"{source} has an invalid retryable transport result")

    return {
        "number": number,
        "outcome": outcome,
        "http_status": status,
        "redirect_origins": redirect_origins,
        "received_size": received_size,
        "sha256": sha256,
        "retry_delay_seconds": retry_delay,
    }


def _validate_store_request(
    value: object,
    plan_request: SourcePlanRequest,
    *,
    index: int,
) -> StoreRequest:
    source = f"source-store request {index}"
    record = _exact_mapping(
        value,
        frozenset(
            {
                "id",
                "request_origin",
                "algorithm",
                "digest",
                "expected_size",
                "max_bytes",
                "object_sha256",
                "size",
                "path",
                "redirect_origins",
                "attempts",
            }
        ),
        source,
    )
    identifier = _request_id(record["id"], f"{source} id")
    request_origin, request_origin_host = _https_url(
        record["request_origin"],
        f"{source} request_origin",
    )
    if request_origin != _https_origin(request_origin_host):
        raise SourceStoreError(f"{source} has a noncanonical request origin")
    algorithm = _algorithm(record["algorithm"], f"{source} algorithm")
    digest = _digest(record["digest"], algorithm, f"{source} digest")
    maximum = _bounded_integer(
        record["max_bytes"],
        f"{source} max_bytes",
        minimum=1,
        maximum=MAX_OBJECT_BYTES,
    )
    expected_size = _nullable_size(
        record["expected_size"],
        f"{source} expected_size",
        maximum=maximum,
    )
    size = _bounded_integer(record["size"], f"{source} size", minimum=0, maximum=maximum)
    object_sha256 = _digest(record["object_sha256"], "sha256", f"{source} object_sha256")
    path = _bounded_ascii(record["path"], f"{source} path", maximum=96)
    expected_path = f"{OBJECT_DIRECTORY}/{object_sha256}"
    if path != expected_path:
        raise SourceStoreError(f"{source} has a noncanonical object path")

    _plan_url, plan_host = _https_url(
        plan_request["url"],
        f"{source} plan request URL",
    )
    expected_request_origin = _https_origin(plan_host)
    if (
        identifier != plan_request["id"]
        or request_origin != expected_request_origin
        or algorithm != plan_request["algorithm"]
        or digest != plan_request["digest"]
        or expected_size != plan_request["expected_size"]
        or maximum != plan_request["max_bytes"]
        or (expected_size is not None and size != expected_size)
    ):
        raise SourceStoreError(f"{source} does not exactly match its plan request")

    allowed_hosts = set(plan_request["allowed_hosts"])
    redirect_origins = _redirect_origins(
        record["redirect_origins"],
        allowed_hosts,
        f"{source} redirect_origins",
    )
    if redirect_origins[0] != request_origin:
        raise SourceStoreError(f"{source} redirect origins do not start with its request origin")

    raw_attempts = record["attempts"]
    if not isinstance(raw_attempts, list) or not 1 <= len(raw_attempts) <= MAX_ATTEMPTS:
        raise SourceStoreError(f"{source} is outside its attempt-count bound")
    attempts = [
        _validate_attempt(
            raw_attempt,
            index=attempt_index,
            maximum=maximum,
            allowed_hosts=allowed_hosts,
            request_origin=request_origin,
            source=f"{source} attempt {attempt_index}",
        )
        for attempt_index, raw_attempt in enumerate(raw_attempts, start=1)
    ]
    if (
        any(attempt["outcome"] == "success" for attempt in attempts[:-1])
        or attempts[-1]["outcome"] != "success"
    ):
        raise SourceStoreError(f"{source} must end with its only successful attempt")
    final_attempt = attempts[-1]
    if (
        final_attempt["redirect_origins"] != redirect_origins
        or final_attempt["received_size"] != size
        or final_attempt["sha256"] != object_sha256
    ):
        raise SourceStoreError(f"{source} does not match its final successful attempt")

    return {
        "id": identifier,
        "request_origin": request_origin,
        "algorithm": algorithm,
        "digest": digest,
        "expected_size": expected_size,
        "max_bytes": maximum,
        "object_sha256": object_sha256,
        "size": size,
        "path": path,
        "redirect_origins": redirect_origins,
        "attempts": attempts,
    }


def validate_source_store(
    value: object,
    *,
    plan: SourcePlan,
    plan_bytes: bytes,
) -> SourceStore:
    """Validate one source-store manifest against its exact canonical plan."""

    record = _exact_mapping(
        value,
        frozenset(
            {
                "schema_version",
                "media_type",
                "kind",
                "plan_sha256",
                "plan_size",
                "objects",
                "results",
            }
        ),
        "source-store manifest",
    )
    if (
        _bounded_integer(
            record["schema_version"],
            "source-store schema_version",
            minimum=SCHEMA_VERSION,
            maximum=SCHEMA_VERSION,
        )
        != SCHEMA_VERSION
    ):
        raise SourceStoreError("source-store manifest has an unsupported schema version")
    if record["media_type"] != STORE_MEDIA_TYPE:
        raise SourceStoreError("source-store manifest has the wrong media type")
    if record["kind"] != plan["kind"]:
        raise SourceStoreError("source-store manifest has the wrong kind")

    plan_sha256 = _digest(
        record["plan_sha256"],
        "sha256",
        "source-store plan_sha256",
    )
    plan_size = _bounded_integer(
        record["plan_size"],
        "source-store plan_size",
        minimum=1,
        maximum=MAX_PLAN_BYTES,
    )
    if plan_size != len(plan_bytes) or plan_sha256 != hashlib.sha256(plan_bytes).hexdigest():
        raise SourceStoreError("source-store manifest does not bind the exact plan")

    raw_results = record["results"]
    if not isinstance(raw_results, list) or len(raw_results) != len(plan["requests"]):
        raise SourceStoreError("source-store manifest has the wrong result count")
    results = [
        _validate_store_request(raw_result, plan_request, index=index)
        for index, (raw_result, plan_request) in enumerate(
            zip(raw_results, plan["requests"], strict=True),
            start=1,
        )
    ]
    identifiers = [result["id"] for result in results]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise SourceStoreError("source-store result IDs must be sorted and unique")
    _no_case_collisions(identifiers, "source-store result IDs")

    raw_objects = record["objects"]
    if not isinstance(raw_objects, list) or not 1 <= len(raw_objects) <= MAX_OBJECTS:
        raise SourceStoreError("source-store manifest is outside its object-count bound")
    objects: list[StoreObject] = []
    total_size = 0
    for index, raw_object in enumerate(raw_objects, start=1):
        source = f"source-store object {index}"
        object_record = _exact_mapping(
            raw_object,
            frozenset({"algorithm", "digest", "size", "path"}),
            source,
        )
        algorithm = _algorithm(
            object_record["algorithm"],
            f"{source} algorithm",
            object_only=True,
        )
        digest = _digest(object_record["digest"], algorithm, f"{source} digest")
        size = _bounded_integer(
            object_record["size"],
            f"{source} size",
            minimum=0,
            maximum=MAX_OBJECT_BYTES,
        )
        path = _bounded_ascii(object_record["path"], f"{source} path", maximum=96)
        if path != f"{OBJECT_DIRECTORY}/{digest}":
            raise SourceStoreError(f"{source} has a noncanonical path")
        total_size += size
        if total_size > MAX_TOTAL_OBJECT_BYTES:
            raise SourceStoreError("source-store objects exceed the aggregate byte bound")
        objects.append(
            {
                "algorithm": algorithm,
                "digest": digest,
                "size": size,
                "path": path,
            }
        )

    object_keys = [(item["algorithm"], item["digest"]) for item in objects]
    if object_keys != sorted(object_keys) or len(object_keys) != len(set(object_keys)):
        raise SourceStoreError("source-store objects must be sorted and unique")
    _no_case_collisions([item["path"] for item in objects], "source-store object paths")
    object_by_digest = {item["digest"]: item for item in objects}
    referenced = {result["object_sha256"] for result in results}
    if set(object_by_digest) != referenced:
        raise SourceStoreError("source-store manifest has missing or unreferenced objects")
    for result in results:
        source_object = object_by_digest[result["object_sha256"]]
        if source_object["size"] != result["size"] or source_object["path"] != result["path"]:
            raise SourceStoreError("source-store result disagrees with its object record")

    return {
        "schema_version": SCHEMA_VERSION,
        "media_type": STORE_MEDIA_TYPE,
        "kind": plan["kind"],
        "plan_sha256": plan_sha256,
        "plan_size": plan_size,
        "objects": objects,
        "results": results,
    }


def validate_verification_result(value: object) -> VerificationResult:
    """Validate the deterministic summary emitted by the read-only verifier."""

    record = _exact_mapping(
        value,
        frozenset(
            {
                "schema_version",
                "kind",
                "plan",
                "manifest",
                "request_count",
                "object_count",
                "total_object_bytes",
            }
        ),
        "source-store verification result",
    )
    if (
        _bounded_integer(
            record["schema_version"],
            "verification result schema_version",
            minimum=SCHEMA_VERSION,
            maximum=SCHEMA_VERSION,
        )
        != SCHEMA_VERSION
    ):
        raise SourceStoreError("verification result has an unsupported schema version")
    if record["kind"] != RESULT_KIND:
        raise SourceStoreError("verification result has the wrong kind")
    request_count = _bounded_integer(
        record["request_count"],
        "verification result request_count",
        minimum=1,
        maximum=MAX_REQUESTS,
    )
    object_count = _bounded_integer(
        record["object_count"],
        "verification result object_count",
        minimum=1,
        maximum=MAX_OBJECTS,
    )
    if object_count > request_count:
        raise SourceStoreError("verification result has more objects than requests")
    result: VerificationResult = {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "plan": _digest_descriptor(
            record["plan"],
            "verification result plan",
            maximum=MAX_PLAN_BYTES,
        ),
        "manifest": _digest_descriptor(
            record["manifest"],
            "verification result manifest",
            maximum=MAX_STORE_BYTES,
        ),
        "request_count": request_count,
        "object_count": object_count,
        "total_object_bytes": _bounded_integer(
            record["total_object_bytes"],
            "verification result total_object_bytes",
            minimum=0,
            maximum=MAX_TOTAL_OBJECT_BYTES,
        ),
    }
    if len(canonical_json(result)) > MAX_RESULT_BYTES:
        raise SourceStoreError("verification result exceeds its byte bound")
    return result


def _file_identity(
    metadata: os.stat_result,
    source: str,
    *,
    maximum: int,
    expected_size: int | None = None,
) -> FileIdentity:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SourceStoreError(f"{source} must be one single-link regular file")
    if not 0 <= metadata.st_size <= maximum or (
        expected_size is not None and metadata.st_size != expected_size
    ):
        raise SourceStoreError(f"{source} is outside its exact file-size bound")
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result, source: str) -> DirectoryIdentity:
    if not stat.S_ISDIR(metadata.st_mode):
        raise SourceStoreError(f"{source} must be a directory")
    return DirectoryIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _safe_open_flags(*, directory: bool) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or (directory and not directory_flag) or not hasattr(os, "pread"):
        raise SourceStoreError("source-store verification requires no-follow descriptor support")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    if directory:
        flags |= directory_flag
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_root_directory(path: Path) -> tuple[int, DirectoryIdentity]:
    try:
        before = _directory_identity(
            os.stat(path, follow_symlinks=False),
            "source-store root",
        )
        descriptor = os.open(path, _safe_open_flags(directory=True))
    except OSError as exc:
        raise SourceStoreError("cannot open source-store root safely") from exc
    try:
        opened = _directory_identity(os.fstat(descriptor), "source-store root")
        if opened != before:
            raise SourceStoreError("source-store root changed while it was opened")
        return descriptor, before
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _open_directory_at(
    parent: int,
    name: str,
    source: str,
) -> tuple[int, DirectoryIdentity]:
    try:
        before = _directory_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False),
            source,
        )
        descriptor = os.open(name, _safe_open_flags(directory=True), dir_fd=parent)
    except OSError as exc:
        raise SourceStoreError(f"cannot open {source} safely") from exc
    try:
        opened = _directory_identity(os.fstat(descriptor), source)
        current = _directory_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False),
            source,
        )
        if opened != before or current != before:
            raise SourceStoreError(f"{source} changed while it was opened")
        return descriptor, before
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _open_regular_at(
    parent: int,
    name: str,
    source: str,
    *,
    maximum: int,
    expected_size: int | None = None,
) -> RetainedFile:
    try:
        before = _file_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False),
            source,
            maximum=maximum,
            expected_size=expected_size,
        )
        descriptor = os.open(name, _safe_open_flags(directory=False), dir_fd=parent)
    except OSError as exc:
        raise SourceStoreError(f"cannot open {source} safely") from exc
    try:
        opened = _file_identity(
            os.fstat(descriptor),
            source,
            maximum=maximum,
            expected_size=expected_size,
        )
        current = _file_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False),
            source,
            maximum=maximum,
            expected_size=expected_size,
        )
        if opened != before or current != before:
            raise SourceStoreError(f"{source} changed while it was opened")
        return RetainedFile(descriptor, before, name, source, parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _require_file_unchanged(retained: RetainedFile) -> None:
    try:
        opened = _file_identity(
            os.fstat(retained.descriptor),
            retained.source,
            maximum=retained.identity.size,
            expected_size=retained.identity.size,
        )
        current = _file_identity(
            os.stat(
                retained.name,
                dir_fd=retained.parent_descriptor,
                follow_symlinks=False,
            ),
            retained.source,
            maximum=retained.identity.size,
            expected_size=retained.identity.size,
        )
    except (OSError, SourceStoreError) as exc:
        raise SourceStoreError(f"{retained.source} changed while it was retained") from exc
    if opened != retained.identity or current != retained.identity:
        raise SourceStoreError(f"{retained.source} changed while it was retained")


def _read_retained(retained: RetainedFile) -> bytes:
    chunks: list[bytes] = []
    position = 0
    remaining = retained.identity.size
    try:
        while remaining:
            chunk = os.pread(
                retained.descriptor,
                min(READ_CHUNK_BYTES, remaining),
                position,
            )
            if not chunk:
                raise SourceStoreError(f"{retained.source} was truncated while it was read")
            chunks.append(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(retained.descriptor, 1, position):
            raise SourceStoreError(f"{retained.source} has trailing bytes")
    except OSError as exc:
        raise SourceStoreError(f"cannot read {retained.source} safely") from exc
    _require_file_unchanged(retained)
    return b"".join(chunks)


def _hash_retained(retained: RetainedFile, algorithms: set[str]) -> dict[str, str]:
    hashers = {algorithm: hashlib.new(algorithm) for algorithm in algorithms}
    position = 0
    remaining = retained.identity.size
    try:
        while remaining:
            chunk = os.pread(
                retained.descriptor,
                min(READ_CHUNK_BYTES, remaining),
                position,
            )
            if not chunk:
                raise SourceStoreError(f"{retained.source} was truncated while hashing")
            for hasher in hashers.values():
                hasher.update(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(retained.descriptor, 1, position):
            raise SourceStoreError(f"{retained.source} has trailing bytes")
    except OSError as exc:
        raise SourceStoreError(f"cannot hash {retained.source} safely") from exc
    _require_file_unchanged(retained)
    return {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()}


def _list_exact(directory: int, expected: set[str], source: str) -> tuple[str, ...]:
    """Read at most one entry beyond the expected exact inventory."""

    names: list[str] = []
    too_many = False
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > len(expected):
                    too_many = True
                    break
    except (OSError, TypeError) as exc:
        raise SourceStoreError(f"cannot inventory {source}") from exc

    def bounded(values: set[str]) -> tuple[list[str], int]:
        ordered = sorted(values)
        return ordered[:MAX_INVENTORY_DIAGNOSTICS], len(ordered)

    if len(names) != len(set(names)):
        raise SourceStoreError(f"{source} repeats a directory entry")
    _no_case_collisions(names, source)
    observed = set(names)
    if too_many or observed != expected:
        missing, missing_count = bounded(expected.difference(observed))
        unexpected, unexpected_count = bounded(observed.difference(expected))
        raise SourceStoreError(
            f"{source} has the wrong exact inventory; "
            f"missing_count={missing_count}, missing={missing!r}, "
            f"unexpected_count={unexpected_count}, unexpected={unexpected!r}, "
            f"entry_count_exceeds_bound={too_many}"
        )
    return tuple(sorted(names))


def _require_files_unchanged(retained_files: Sequence[RetainedFile]) -> None:
    """Perform the final descriptor-and-path identity pass for retained files."""

    for retained in retained_files:
        _require_file_unchanged(retained)


def _require_object_identities_unchanged(
    digest_descriptor: int,
    object_identities: dict[str, FileIdentity],
) -> None:
    """Require every retained CAS pathname to keep its captured file identity."""

    for digest, identity in object_identities.items():
        try:
            current = _file_identity(
                os.stat(
                    digest,
                    dir_fd=digest_descriptor,
                    follow_symlinks=False,
                ),
                f"source-store reader object {digest}",
                maximum=identity.size,
                expected_size=identity.size,
            )
        except (OSError, SourceStoreError) as exc:
            raise SourceStoreError(
                f"source-store reader object {digest} changed while retained"
            ) from exc
        if current != identity:
            raise SourceStoreError(f"source-store reader object {digest} changed while retained")


def _require_directory_unchanged_at(
    descriptor: int,
    parent: int,
    name: str,
    before: DirectoryIdentity,
    source: str,
) -> None:
    try:
        opened = _directory_identity(os.fstat(descriptor), source)
        current = _directory_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False),
            source,
        )
    except OSError as exc:
        raise SourceStoreError(f"{source} changed during verification") from exc
    if opened != before or current != before:
        raise SourceStoreError(f"{source} changed during verification")


def _require_root_unchanged(
    descriptor: int,
    path: Path,
    before: DirectoryIdentity,
) -> None:
    try:
        opened = _directory_identity(os.fstat(descriptor), "source-store root")
        current = _directory_identity(
            os.stat(path, follow_symlinks=False),
            "source-store root",
        )
    except OSError as exc:
        raise SourceStoreError("source-store root changed during verification") from exc
    if opened != before or current != before:
        raise SourceStoreError("source-store root changed during verification")


def verify_source_store(
    store_root: Path,
    *,
    expected_plan_sha256: str,
    expected_plan_size: int,
) -> VerificationResult:
    """Return a point-in-time byte observation of one complete source store.

    The verifier closes its retained descriptors before returning. The result
    therefore cannot authorize a later path read from writable storage. Bind the
    plan to a trusted expected digest, then verify each object as part of the read
    that consumes it or use a trusted read-only mount. In either case, compare
    against a trusted expected plan rather than a digest supplied by the store.

    Args:
        store_root: Exact source-store directory to inspect.
        expected_plan_sha256: Independently trusted plan digest. Supply this together
            with ``expected_plan_size`` at a consuming boundary.
        expected_plan_size: Independently trusted exact plan size. Supply this together
            with ``expected_plan_sha256`` at a consuming boundary.

    Returns:
        A canonical summary of the exact bytes observed during this invocation.

    Raises:
        SourceStoreError: If the store, trusted plan binding, or filesystem changes
            fail validation.
    """

    expected_plan_sha256 = _digest(
        expected_plan_sha256,
        OBJECT_ALGORITHM,
        "trusted expected plan digest",
    )
    expected_plan_size = _bounded_integer(
        expected_plan_size,
        "trusted expected plan size",
        minimum=1,
        maximum=MAX_PLAN_BYTES,
    )

    root = Path(store_root)
    with contextlib.ExitStack() as stack:
        root_descriptor, root_identity = _open_root_directory(root)
        stack.callback(os.close, root_descriptor)
        _list_exact(
            root_descriptor,
            {PLAN_FILENAME, STORE_FILENAME, OBJECTS_DIRECTORY},
            "source-store root",
        )

        plan_file = _open_regular_at(
            root_descriptor,
            PLAN_FILENAME,
            "source plan",
            maximum=MAX_PLAN_BYTES,
        )
        stack.callback(os.close, plan_file.descriptor)
        store_file = _open_regular_at(
            root_descriptor,
            STORE_FILENAME,
            "source-store manifest",
            maximum=MAX_STORE_BYTES,
        )
        stack.callback(os.close, store_file.descriptor)
        plan_bytes = _read_retained(plan_file)
        if (
            len(plan_bytes) != expected_plan_size
            or hashlib.sha256(plan_bytes).hexdigest() != expected_plan_sha256
        ):
            raise SourceStoreError("source plan does not match the trusted expected plan")
        store_bytes = _read_retained(store_file)
        plan = validate_source_plan(
            strict_json_bytes(plan_bytes, "source plan", maximum=MAX_PLAN_BYTES)
        )
        manifest = validate_source_store(
            strict_json_bytes(
                store_bytes,
                "source-store manifest",
                maximum=MAX_STORE_BYTES,
            ),
            plan=plan,
            plan_bytes=plan_bytes,
        )

        objects_descriptor, objects_identity = _open_directory_at(
            root_descriptor,
            OBJECTS_DIRECTORY,
            "source-store objects directory",
        )
        stack.callback(os.close, objects_descriptor)
        _list_exact(
            objects_descriptor,
            {OBJECT_ALGORITHM},
            "source-store objects directory",
        )
        digest_descriptor, digest_identity = _open_directory_at(
            objects_descriptor,
            OBJECT_ALGORITHM,
            "source-store sha256 directory",
        )
        stack.callback(os.close, digest_descriptor)
        expected_digests = {item["digest"] for item in manifest["objects"]}
        _list_exact(
            digest_descriptor,
            expected_digests,
            "source-store sha256 directory",
        )

        requests_by_object: dict[str, list[StoreRequest]] = {}
        for store_result in manifest["results"]:
            requests_by_object.setdefault(store_result["object_sha256"], []).append(store_result)
        retained_files = [plan_file, store_file]
        object_by_digest = {item["digest"]: item for item in manifest["objects"]}
        for digest in sorted(expected_digests):
            object_record = object_by_digest[digest]
            requests = requests_by_object[digest]
            maximum = min(request["max_bytes"] for request in requests)
            retained = _open_regular_at(
                digest_descriptor,
                digest,
                f"source-store object {digest}",
                maximum=maximum,
                expected_size=object_record["size"],
            )
            stack.callback(os.close, retained.descriptor)
            retained_files.append(retained)
            algorithms = {OBJECT_ALGORITHM, *(request["algorithm"] for request in requests)}
            observed = _hash_retained(retained, algorithms)
            if observed[OBJECT_ALGORITHM] != digest:
                raise SourceStoreError(f"source-store object {digest} has the wrong SHA-256")
            for request in requests:
                if observed[request["algorithm"]] != request["digest"]:
                    raise SourceStoreError(
                        f"source-store object {digest} does not match request {request['id']!r}"
                    )
                if (
                    request["expected_size"] is not None
                    and retained.identity.size != request["expected_size"]
                ):
                    raise SourceStoreError(
                        f"source-store object {digest} has the wrong expected size"
                    )

        _list_exact(
            digest_descriptor,
            expected_digests,
            "source-store sha256 directory",
        )
        _require_directory_unchanged_at(
            digest_descriptor,
            objects_descriptor,
            OBJECT_ALGORITHM,
            digest_identity,
            "source-store sha256 directory",
        )
        _list_exact(
            objects_descriptor,
            {OBJECT_ALGORITHM},
            "source-store objects directory",
        )
        _require_directory_unchanged_at(
            objects_descriptor,
            root_descriptor,
            OBJECTS_DIRECTORY,
            objects_identity,
            "source-store objects directory",
        )
        _list_exact(
            root_descriptor,
            {PLAN_FILENAME, STORE_FILENAME, OBJECTS_DIRECTORY},
            "source-store root",
        )
        _require_root_unchanged(root_descriptor, root, root_identity)

        # This is deliberately the final filesystem pass. Retaining every
        # descriptor closes intermediate pathname-replacement windows, but no
        # read-only verifier can make caller-owned writable paths immutable after
        # it returns. Consumers must follow the function contract above.
        _require_files_unchanged(retained_files)

        result: VerificationResult = {
            "schema_version": SCHEMA_VERSION,
            "kind": RESULT_KIND,
            "plan": {
                "algorithm": OBJECT_ALGORITHM,
                "digest": hashlib.sha256(plan_bytes).hexdigest(),
                "size": len(plan_bytes),
            },
            "manifest": {
                "algorithm": OBJECT_ALGORITHM,
                "digest": hashlib.sha256(store_bytes).hexdigest(),
                "size": len(store_bytes),
            },
            "request_count": len(manifest["results"]),
            "object_count": len(manifest["objects"]),
            "total_object_bytes": sum(item["size"] for item in manifest["objects"]),
        }
        return validate_verification_result(result)


class VerifiedSourceStoreReader:
    """Read exact planned objects through a retained, offline store snapshot.

    Construction requires an independently trusted plan binding and performs the
    complete store verification before retaining no-follow directory descriptors.
    Each request read reopens its CAS object descriptor-relative, verifies the
    identity captured when the reader opened, and hashes the returned bytes. Paths
    are never returned to the caller.
    """

    def __init__(
        self,
        store_root: Path,
        *,
        expected_plan_sha256: str,
        expected_plan_size: int,
    ) -> None:
        self._closed = True
        self._root_path = Path(store_root).absolute()
        verification = verify_source_store(
            self._root_path,
            expected_plan_sha256=expected_plan_sha256,
            expected_plan_size=expected_plan_size,
        )

        stack = contextlib.ExitStack()
        try:
            root_descriptor, root_identity = _open_root_directory(self._root_path)
            stack.callback(os.close, root_descriptor)
            _list_exact(
                root_descriptor,
                {PLAN_FILENAME, STORE_FILENAME, OBJECTS_DIRECTORY},
                "source-store reader root",
            )
            plan_file = _open_regular_at(
                root_descriptor,
                PLAN_FILENAME,
                "source-store reader plan",
                maximum=MAX_PLAN_BYTES,
            )
            stack.callback(os.close, plan_file.descriptor)
            manifest_file = _open_regular_at(
                root_descriptor,
                STORE_FILENAME,
                "source-store reader manifest",
                maximum=MAX_STORE_BYTES,
            )
            stack.callback(os.close, manifest_file.descriptor)

            plan_bytes = _read_retained(plan_file)
            manifest_bytes = _read_retained(manifest_file)
            if (
                len(plan_bytes) != verification["plan"]["size"]
                or hashlib.sha256(plan_bytes).hexdigest() != verification["plan"]["digest"]
                or len(manifest_bytes) != verification["manifest"]["size"]
                or hashlib.sha256(manifest_bytes).hexdigest() != verification["manifest"]["digest"]
            ):
                raise SourceStoreError(
                    "source-store reader metadata does not match its verification summary"
                )
            plan = validate_source_plan(
                strict_json_bytes(
                    plan_bytes,
                    "source-store reader plan",
                    maximum=MAX_PLAN_BYTES,
                )
            )
            manifest = validate_source_store(
                strict_json_bytes(
                    manifest_bytes,
                    "source-store reader manifest",
                    maximum=MAX_STORE_BYTES,
                ),
                plan=plan,
                plan_bytes=plan_bytes,
            )
            if (
                len(manifest["results"]) != verification["request_count"]
                or len(manifest["objects"]) != verification["object_count"]
                or sum(item["size"] for item in manifest["objects"])
                != verification["total_object_bytes"]
            ):
                raise SourceStoreError(
                    "source-store reader manifest does not match its verification summary"
                )

            objects_descriptor, objects_identity = _open_directory_at(
                root_descriptor,
                OBJECTS_DIRECTORY,
                "source-store reader objects directory",
            )
            stack.callback(os.close, objects_descriptor)
            _list_exact(
                objects_descriptor,
                {OBJECT_ALGORITHM},
                "source-store reader objects directory",
            )
            digest_descriptor, digest_identity = _open_directory_at(
                objects_descriptor,
                OBJECT_ALGORITHM,
                "source-store reader sha256 directory",
            )
            stack.callback(os.close, digest_descriptor)

            object_records = {item["digest"]: item for item in manifest["objects"]}
            expected_digests = set(object_records)
            _list_exact(
                digest_descriptor,
                expected_digests,
                "source-store reader sha256 directory",
            )

            request_pairs = list(zip(plan["requests"], manifest["results"], strict=True))
            request_ids = [request["id"] for request, _result in request_pairs]
            result_ids = [result["id"] for _request, result in request_pairs]
            if (
                request_ids != result_ids
                or len(request_ids) != len(set(request_ids))
                or len({identifier.casefold() for identifier in request_ids}) != len(request_ids)
            ):
                raise SourceStoreError(
                    "source-store reader request IDs must be exact, unique, and case-distinct"
                )
            requests_by_id = {request["id"]: (request, result) for request, result in request_pairs}
            folded_request_ids = {
                identifier.casefold(): identifier for identifier in requests_by_id
            }

            results_by_object: dict[str, list[StoreRequest]] = {}
            for result in manifest["results"]:
                results_by_object.setdefault(result["object_sha256"], []).append(result)
            object_identities: dict[str, FileIdentity] = {}
            for digest in sorted(expected_digests):
                results = results_by_object[digest]
                retained = _open_regular_at(
                    digest_descriptor,
                    digest,
                    f"source-store reader object {digest}",
                    maximum=min(result["max_bytes"] for result in results),
                    expected_size=object_records[digest]["size"],
                )
                try:
                    algorithms = {
                        OBJECT_ALGORITHM,
                        *(result["algorithm"] for result in results),
                    }
                    observed = _hash_retained(retained, algorithms)
                    if observed[OBJECT_ALGORITHM] != digest:
                        raise SourceStoreError(
                            f"source-store reader object {digest} has the wrong SHA-256"
                        )
                    for result in results:
                        if observed[result["algorithm"]] != result["digest"]:
                            raise SourceStoreError(
                                "source-store reader object "
                                f"{digest} does not match request {result['id']!r}"
                            )
                        if (
                            result["expected_size"] is not None
                            and retained.identity.size != result["expected_size"]
                        ):
                            raise SourceStoreError(
                                f"source-store reader object {digest} has the wrong expected size"
                            )
                    object_identities[digest] = retained.identity
                finally:
                    with contextlib.suppress(OSError):
                        os.close(retained.descriptor)

            _list_exact(
                digest_descriptor,
                expected_digests,
                "source-store reader sha256 directory",
            )
            _require_directory_unchanged_at(
                digest_descriptor,
                objects_descriptor,
                OBJECT_ALGORITHM,
                digest_identity,
                "source-store reader sha256 directory",
            )
            _require_directory_unchanged_at(
                objects_descriptor,
                root_descriptor,
                OBJECTS_DIRECTORY,
                objects_identity,
                "source-store reader objects directory",
            )
            _require_root_unchanged(root_descriptor, self._root_path, root_identity)
            _require_files_unchanged((plan_file, manifest_file))
            _require_object_identities_unchanged(
                digest_descriptor,
                object_identities,
            )
        except BaseException:
            stack.close()
            raise

        self._stack = stack
        self._verification = verification
        self._plan = plan
        self._manifest = manifest
        self._root_descriptor = root_descriptor
        self._root_identity = root_identity
        self._objects_descriptor = objects_descriptor
        self._objects_identity = objects_identity
        self._digest_descriptor = digest_descriptor
        self._digest_identity = digest_identity
        self._plan_file = plan_file
        self._manifest_file = manifest_file
        self._expected_digests = expected_digests
        self._object_identities = object_identities
        self._requests_by_id = requests_by_id
        self._folded_request_ids = folded_request_ids
        self._closed = False

    def __enter__(self) -> VerifiedSourceStoreReader:
        self._require_open()
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        if exception_type is None:
            self.close()
        else:
            self._close_descriptors()

    @property
    def request_ids(self) -> tuple[str, ...]:
        """Return the exact validated request IDs in canonical order."""

        self._require_open()
        return tuple(self._requests_by_id)

    @property
    def plan(self) -> SourcePlan:
        """Return an independent validated copy of the retained source plan."""

        self._require_open()
        self._require_structure_unchanged()
        encoded = canonical_json(self._plan)
        return validate_source_plan(
            strict_json_bytes(
                encoded,
                "source-store reader plan copy",
                maximum=MAX_PLAN_BYTES,
            )
        )

    @property
    def verification(self) -> VerificationResult:
        """Return an independent validated copy of the store verification summary."""

        self._require_open()
        self._require_structure_unchanged()
        encoded = canonical_json(self._verification)
        return validate_verification_result(
            strict_json_bytes(
                encoded,
                "source-store reader verification copy",
                maximum=MAX_RESULT_BYTES,
            )
        )

    def _require_open(self) -> None:
        if self._closed:
            raise SourceStoreError("source-store reader is closed")

    def _require_structure_unchanged(self) -> None:
        _list_exact(
            self._digest_descriptor,
            self._expected_digests,
            "source-store reader sha256 directory",
        )
        _require_directory_unchanged_at(
            self._digest_descriptor,
            self._objects_descriptor,
            OBJECT_ALGORITHM,
            self._digest_identity,
            "source-store reader sha256 directory",
        )
        _list_exact(
            self._objects_descriptor,
            {OBJECT_ALGORITHM},
            "source-store reader objects directory",
        )
        _require_directory_unchanged_at(
            self._objects_descriptor,
            self._root_descriptor,
            OBJECTS_DIRECTORY,
            self._objects_identity,
            "source-store reader objects directory",
        )
        _list_exact(
            self._root_descriptor,
            {PLAN_FILENAME, STORE_FILENAME, OBJECTS_DIRECTORY},
            "source-store reader root",
        )
        _require_root_unchanged(
            self._root_descriptor,
            self._root_path,
            self._root_identity,
        )
        _require_files_unchanged((self._plan_file, self._manifest_file))

    def _require_all_objects_unchanged(self) -> None:
        _require_object_identities_unchanged(
            self._digest_descriptor,
            self._object_identities,
        )

    def read_request(self, exact_id: str) -> VerifiedSourceRead:
        """Read and verify the exact object assigned to ``exact_id``."""

        self._require_open()
        checked_id = _request_id(exact_id, "source-store reader request ID")
        pair = self._requests_by_id.get(checked_id)
        if pair is None:
            canonical = self._folded_request_ids.get(checked_id.casefold())
            if canonical is not None:
                raise SourceStoreError(
                    f"source-store reader request ID must match case exactly: {canonical!r}"
                )
            raise SourceStoreError(f"unknown source-store reader request ID: {checked_id!r}")

        self._require_structure_unchanged()
        request, result = pair
        digest = result["object_sha256"]
        retained = _open_regular_at(
            self._digest_descriptor,
            digest,
            f"source-store reader request {checked_id!r}",
            maximum=request["max_bytes"],
            expected_size=result["size"],
        )
        try:
            if retained.identity != self._object_identities[digest]:
                raise SourceStoreError(
                    f"source-store reader request {checked_id!r} object was replaced"
                )
            content = _read_retained(retained)
            if hashlib.sha256(content).hexdigest() != digest:
                raise SourceStoreError(
                    f"source-store reader request {checked_id!r} has the wrong SHA-256"
                )
            if hashlib.new(request["algorithm"], content).hexdigest() != request["digest"]:
                raise SourceStoreError(
                    f"source-store reader request {checked_id!r} has the wrong declared digest"
                )
            self._require_structure_unchanged()
            _require_file_unchanged(retained)
        finally:
            with contextlib.suppress(OSError):
                os.close(retained.descriptor)
        return VerifiedSourceRead(
            content,
            request["url"],
            tuple(result["redirect_origins"]),
        )

    def close(self) -> None:
        """Validate the retained snapshot one last time and close it."""

        if self._closed:
            return
        try:
            self._require_structure_unchanged()
            self._require_all_objects_unchanged()
        finally:
            self._close_descriptors()

    def _close_descriptors(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stack.close()


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify one source-store directory")
    verify.add_argument("store_root", type=Path)
    verify.add_argument("--expected-plan-sha256", required=True)
    verify.add_argument("--expected-plan-size", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only verifier and print its canonical result."""

    arguments = _argument_parser().parse_args(argv)
    try:
        result = verify_source_store(
            cast(Path, arguments.store_root),
            expected_plan_sha256=cast(str, arguments.expected_plan_sha256),
            expected_plan_size=cast(int, arguments.expected_plan_size),
        )
    except SourceStoreError as exc:
        sys.stderr.write(f"verified source store: {exc}\n")
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
