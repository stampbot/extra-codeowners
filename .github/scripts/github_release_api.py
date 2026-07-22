#!/usr/bin/env python3
"""A bounded GitHub REST adapter for the immutable release controller."""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import re
import urllib.parse
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from typing import Any, Literal, NoReturn, cast

from release_controller import (
    MAX_ASSET_BYTES,
    MAX_ID,
    MAX_PAGES,
    PAGE_SIZE,
    READ_CHUNK_BYTES,
    REPOSITORY,
    SAFE_NAME,
    SEMANTIC_TAG,
    AmbiguousMutationError,
    ControllerError,
    ReleasePlan,
    VerifiedAsset,
)

API_HOST = "api.github.com"
UPLOAD_HOST = "uploads.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "extra-codeowners-release-controller/1"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 120.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_ITEMS = 100_000
MAX_TOKEN_BYTES = 4096
MAX_REQUEST_ID_BYTES = 128

HEX40 = re.compile(r"^[0-9a-f]{40}$")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9:._-]+$")


class _ResponseValidationError(ValueError):
    """A successful response did not satisfy the bounded JSON contract."""


class _UploadReadError(OSError):
    """The retained descriptor could not supply the declared upload bytes."""


def _reject_json_constant(_value: str) -> NoReturn:
    raise _ResponseValidationError("non-finite JSON number")


def _reject_json_float(_value: str) -> NoReturn:
    raise _ResponseValidationError("floating-point JSON number")


def _bounded_json_integer(value: str) -> int:
    if len(value) > 19:
        raise _ResponseValidationError("JSON integer exceeds its lexical bound")
    parsed = int(value)
    if parsed < -MAX_ID or parsed > MAX_ID:
        raise _ResponseValidationError("JSON integer exceeds its numeric bound")
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ResponseValidationError("JSON object repeats a key")
        result[key] = value
    return result


def _json_shape(value: object, *, depth: int = 1) -> int:
    if depth > MAX_JSON_DEPTH:
        raise _ResponseValidationError("JSON exceeds its depth bound")
    if isinstance(value, dict):
        items = 1 + len(value)
        for key, child in value.items():
            if not isinstance(key, str):
                raise _ResponseValidationError("JSON object has a non-string key")
            items += _json_shape(child, depth=depth + 1)
        return items
    if isinstance(value, list):
        items = 1
        for child in value:
            items += _json_shape(child, depth=depth + 1)
        return items
    if value is None or isinstance(value, (str, int, bool)):
        return 1
    raise _ResponseValidationError("JSON contains an unsupported value")


def _strict_json(raw: bytes) -> object:
    try:
        source = raw.decode("utf-8")
        value: object = json.loads(
            source,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_bounded_json_integer,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise _ResponseValidationError("response is not strict bounded JSON") from exc
    if _json_shape(value) > MAX_JSON_ITEMS:
        raise _ResponseValidationError("JSON exceeds its item bound")
    return value


def _positive_id(value: object, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise ControllerError(f"{source} is outside its integer bounds")
    return value


def _response_positive_id(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise _ResponseValidationError("response has an invalid ID")
    return value


def _valid_timeout(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 < float(value) <= MAX_TIMEOUT_SECONDS
    ):
        raise ControllerError("GitHub API timeout is outside its bounds")
    return float(value)


def _validate_token(value: object) -> str:
    if not isinstance(value, str):
        raise ControllerError("GitHub token is invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise ControllerError("GitHub token is invalid") from None
    if (
        not encoded
        or len(encoded) > MAX_TOKEN_BYTES
        or value != value.strip()
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise ControllerError("GitHub token is invalid")
    return value


def _request_id(response: http.client.HTTPResponse) -> str:
    value = response.getheader("X-GitHub-Request-Id")
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_REQUEST_ID_BYTES
        or REQUEST_ID.fullmatch(value) is None
    ):
        return "unavailable"
    return value


def _bounded_path(path: str) -> str:
    value = path.partition("?")[0]
    if len(value) > 512:
        return value[:509] + "..."
    return value


def _request_failure(
    method: str,
    path: str,
    *,
    status: int | None,
    request_id: str,
    ambiguous: bool,
) -> ControllerError:
    status_text = "unavailable" if status is None else str(status)
    message = (
        "GitHub mutation outcome is ambiguous" if ambiguous else "GitHub request failed closed"
    )
    rendered = (
        f"{message}: method={method} path={_bounded_path(path)} "
        f"status={status_text} request_id={request_id}"
    )
    if ambiguous:
        return AmbiguousMutationError(rendered)
    return ControllerError(rendered)


def _json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ControllerError("GitHub request body is not canonical JSON") from exc


class _DescriptorBody(Iterable[bytes]):
    """Read a fixed byte range without changing or owning the descriptor."""

    __slots__ = ("_descriptor", "_size")

    def __init__(self, descriptor: int, size: int) -> None:
        self._descriptor = descriptor
        self._size = size

    def __iter__(self) -> Iterator[bytes]:
        position = 0
        while position < self._size:
            requested = min(READ_CHUNK_BYTES, self._size - position)
            try:
                chunk = os.pread(self._descriptor, requested, position)
            except OSError:
                raise _UploadReadError("retained descriptor read failed") from None
            if not chunk or len(chunk) > requested:
                raise _UploadReadError("retained descriptor was truncated")
            position += len(chunk)
            yield chunk
        try:
            trailing = os.pread(self._descriptor, 1, position)
        except OSError:
            raise _UploadReadError("retained descriptor read failed") from None
        if trailing:
            raise _UploadReadError("retained descriptor has trailing bytes")


class GitHubReleaseAPI:
    """Implement the controller's eight-method REST contract.

    The caller supplies the token directly. This object never reads process
    configuration, retries a request, follows a redirect, or owns an asset
    descriptor.
    """

    __slots__ = ("_repository", "_timeout", "_token")

    def __init__(
        self,
        *,
        token: str,
        repository: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._token = _validate_token(token)
        components = repository.split("/")
        if (
            len(repository) > 256
            or REPOSITORY.fullmatch(repository) is None
            or len(components) != 2
            or any(component in {".", ".."} or len(component) > 100 for component in components)
        ):
            raise ControllerError("GitHub repository name is invalid")
        self._repository = repository
        self._timeout = _valid_timeout(timeout)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(repository={self._repository!r}, timeout={self._timeout!r})"

    @property
    def _repository_path(self) -> str:
        return urllib.parse.quote(self._repository, safe="/")

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }

    @staticmethod
    def _response_json(response: http.client.HTTPResponse) -> object:
        encoding = response.getheader("Content-Encoding")
        if encoding is not None and encoding.strip().lower() != "identity":
            raise _ResponseValidationError("response has an unsupported content encoding")
        content_type = response.getheader("Content-Type")
        if not isinstance(content_type, str) or content_type.partition(";")[0].strip().lower() != (
            "application/json"
        ):
            raise _ResponseValidationError("response has an unsupported media type")
        length_header = response.getheader("Content-Length")
        declared_length: int | None = None
        if length_header is not None:
            if DECIMAL.fullmatch(length_header) is None or len(length_header) > len(
                str(MAX_RESPONSE_BYTES)
            ):
                raise _ResponseValidationError("response has an invalid content length")
            declared_length = int(length_header)
            if declared_length > MAX_RESPONSE_BYTES:
                raise _ResponseValidationError("response exceeds its byte bound")
        try:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException):
            raise _ResponseValidationError("response body could not be read") from None
        if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
            raise _ResponseValidationError("response exceeds its byte bound")
        if declared_length is not None and len(raw) != declared_length:
            raise _ResponseValidationError("response body is truncated or extended")
        return _strict_json(raw)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        expected_status: int,
        body: bytes | Iterable[bytes] | None = None,
        headers: Mapping[str, str] | None = None,
        mutation: bool = False,
        upload_host: bool = False,
        response_kind: Literal["object", "objects"],
        response_validator: Callable[[object], None] | None = None,
    ) -> object:
        request_headers = self._headers()
        if headers is not None:
            request_headers.update(headers)
        host = UPLOAD_HOST if upload_host else API_HOST
        try:
            connection = http.client.HTTPSConnection(host, timeout=self._timeout)
        except (OSError, http.client.HTTPException):
            raise _request_failure(
                method,
                path,
                status=None,
                request_id="unavailable",
                ambiguous=False,
            ) from None
        request_started = False
        response: http.client.HTTPResponse | None = None
        try:
            request_started = True
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
        except (OSError, http.client.HTTPException):
            with contextlib.suppress(OSError, http.client.HTTPException):
                connection.close()
            raise _request_failure(
                method,
                path,
                status=None,
                request_id="unavailable",
                ambiguous=mutation and request_started,
            ) from None
        try:
            request_id = _request_id(response)
            if response.status != expected_status:
                ambiguous_status = mutation and (
                    100 <= response.status <= 199
                    or response.status == http.client.REQUEST_TIMEOUT
                    or 200 <= response.status <= 299
                    or 500 <= response.status <= 599
                )
                raise _request_failure(
                    method,
                    path,
                    status=response.status,
                    request_id=request_id,
                    ambiguous=ambiguous_status,
                )
            try:
                value = self._response_json(response)
                if response_kind == "object" and not isinstance(value, dict):
                    raise _ResponseValidationError("response is not a JSON object")
                if response_kind == "objects" and (
                    not isinstance(value, list) or any(not isinstance(item, dict) for item in value)
                ):
                    raise _ResponseValidationError("response is not a JSON object array")
                if response_validator is not None:
                    response_validator(value)
                return value
            except _ResponseValidationError:
                raise _request_failure(
                    method,
                    path,
                    status=response.status,
                    request_id=request_id,
                    ambiguous=mutation,
                ) from None
        finally:
            with contextlib.suppress(OSError, http.client.HTTPException):
                response.close()
            with contextlib.suppress(OSError, http.client.HTTPException):
                connection.close()

    @staticmethod
    def _object(value: object, source: str) -> Mapping[str, Any]:
        if not isinstance(value, dict):
            raise ControllerError(f"{source} is not a JSON object")
        return value

    @staticmethod
    def _objects(value: object, source: str) -> Sequence[Mapping[str, Any]]:
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ControllerError(f"{source} is not a JSON object array")
        return cast(list[Mapping[str, Any]], value)

    @staticmethod
    def _page(page: int, per_page: int) -> None:
        _positive_id(page, "GitHub API page")
        if page > MAX_PAGES:
            raise ControllerError("GitHub API page is outside its integer bounds")
        if (
            not isinstance(per_page, int)
            or isinstance(per_page, bool)
            or not 1 <= per_page <= PAGE_SIZE
        ):
            raise ControllerError("GitHub API page size is outside its integer bounds")

    def repository_id(self) -> int:
        path = f"/repos/{self._repository_path}"
        value = self._object(
            self._request_json("GET", path, expected_status=http.client.OK, response_kind="object"),
            "GitHub repository response",
        )
        if value.get("full_name") != self._repository:
            raise ControllerError("GitHub repository full name does not match trusted routing")
        return _positive_id(value.get("id"), "GitHub repository ID")

    def resolve_tag(self, tag: str) -> str:
        if len(tag) > 64 or SEMANTIC_TAG.fullmatch(tag) is None:
            raise ControllerError("GitHub release tag is invalid")
        encoded_tag = urllib.parse.quote(tag, safe="")
        path = f"/repos/{self._repository_path}/git/ref/tags/{encoded_tag}"
        reference = self._object(
            self._request_json("GET", path, expected_status=http.client.OK, response_kind="object"),
            "GitHub tag reference response",
        )
        if reference.get("ref") != f"refs/tags/{tag}":
            raise ControllerError("GitHub returned a different tag reference")
        target = self._object(reference.get("object"), "GitHub tag reference object")
        target_sha = target.get("sha")
        target_type = target.get("type")
        if not isinstance(target_sha, str) or HEX40.fullmatch(target_sha) is None:
            raise ControllerError("GitHub tag reference has an invalid object ID")
        if target_type == "commit":
            return target_sha
        if target_type != "tag":
            raise ControllerError("GitHub tag reference has an unsupported object type")

        tag_path = f"/repos/{self._repository_path}/git/tags/{target_sha}"
        annotated = self._object(
            self._request_json(
                "GET", tag_path, expected_status=http.client.OK, response_kind="object"
            ),
            "GitHub annotated tag response",
        )
        if annotated.get("sha") != target_sha or annotated.get("tag") != tag:
            raise ControllerError("GitHub returned a different annotated tag")
        annotated_target = self._object(annotated.get("object"), "GitHub annotated tag object")
        commit_sha = annotated_target.get("sha")
        if annotated_target.get("type") != "commit":
            raise ControllerError("GitHub annotated tag does not point directly to a commit")
        if not isinstance(commit_sha, str) or HEX40.fullmatch(commit_sha) is None:
            raise ControllerError("GitHub annotated tag has an invalid commit ID")
        return commit_sha

    def list_releases(self, page: int, per_page: int) -> Sequence[Mapping[str, Any]]:
        self._page(page, per_page)
        path = f"/repos/{self._repository_path}/releases?per_page={per_page}&page={page}"
        return self._objects(
            self._request_json(
                "GET", path, expected_status=http.client.OK, response_kind="objects"
            ),
            "GitHub releases response",
        )

    def create_draft(self, plan: ReleasePlan) -> Mapping[str, Any]:
        if plan.repository != self._repository:
            raise ControllerError("release plan repository does not match trusted routing")
        body = _json_bytes(
            {
                "body": plan.marker,
                "draft": True,
                "generate_release_notes": False,
                "make_latest": "false",
                "name": plan.tag,
                "prerelease": False,
                "tag_name": plan.tag,
                "target_commitish": plan.target_commit,
            }
        )
        path = f"/repos/{self._repository_path}/releases"

        def validate_created(value: object) -> None:
            if not isinstance(value, dict):
                raise _ResponseValidationError("create response is not an object")
            release_id = _response_positive_id(value.get("id"))
            expected = {
                "body": plan.marker,
                "name": plan.tag,
                "tag_name": plan.tag,
                "target_commitish": plan.target_commit,
                "upload_url": (
                    f"https://{UPLOAD_HOST}/repos/{self._repository}/releases/"
                    f"{release_id}/assets{{?name,label}}"
                ),
            }
            if (
                value.get("draft") is not True
                or value.get("immutable") is not False
                or value.get("prerelease") is not False
                or any(value.get(key) != expected_value for key, expected_value in expected.items())
            ):
                raise _ResponseValidationError("create response does not match the request")

        return self._object(
            self._request_json(
                "POST",
                path,
                expected_status=http.client.CREATED,
                body=body,
                headers={
                    "Content-Length": str(len(body)),
                    "Content-Type": "application/json",
                },
                mutation=True,
                response_kind="object",
                response_validator=validate_created,
            ),
            "GitHub create-release response",
        )

    def get_release(self, release_id: int) -> Mapping[str, Any]:
        checked_id = _positive_id(release_id, "GitHub release ID")
        path = f"/repos/{self._repository_path}/releases/{checked_id}"

        def validate_release(value: object) -> None:
            if not isinstance(value, dict) or _response_positive_id(value.get("id")) != checked_id:
                raise _ResponseValidationError("release response does not match the requested ID")

        return self._object(
            self._request_json(
                "GET",
                path,
                expected_status=http.client.OK,
                response_kind="object",
                response_validator=validate_release,
            ),
            "GitHub release response",
        )

    def list_assets(self, release_id: int, page: int, per_page: int) -> Sequence[Mapping[str, Any]]:
        checked_id = _positive_id(release_id, "GitHub release ID")
        self._page(page, per_page)
        path = (
            f"/repos/{self._repository_path}/releases/{checked_id}/assets"
            f"?per_page={per_page}&page={page}"
        )
        return self._objects(
            self._request_json(
                "GET", path, expected_status=http.client.OK, response_kind="objects"
            ),
            "GitHub release-assets response",
        )

    def upload_asset(
        self, release_id: int, upload_url: str, asset: VerifiedAsset
    ) -> Mapping[str, Any]:
        checked_id = _positive_id(release_id, "GitHub release ID")
        expected_url = (
            f"https://{UPLOAD_HOST}/repos/{self._repository}/releases/"
            f"{checked_id}/assets{{?name,label}}"
        )
        if upload_url != expected_url:
            raise ControllerError("GitHub upload URL does not match trusted routing")
        name = asset.asset.name
        if not isinstance(name, str) or len(name) > 255 or SAFE_NAME.fullmatch(name) is None:
            raise ControllerError("GitHub release asset name is invalid")
        size = asset.asset.size
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_ASSET_BYTES:
            raise ControllerError("GitHub release asset size is outside its integer bounds")
        descriptor = asset.descriptor
        if not isinstance(descriptor, int) or isinstance(descriptor, bool) or descriptor < 0:
            raise ControllerError("retained release asset descriptor is invalid")
        name_query = urllib.parse.quote(name, safe="")
        path = f"/repos/{self._repository_path}/releases/{checked_id}/assets?name={name_query}"

        def validate_uploaded(value: object) -> None:
            if not isinstance(value, dict):
                raise _ResponseValidationError("upload response is not an object")
            _response_positive_id(value.get("id"))
            expected = {
                "content_type": "application/octet-stream",
                "digest": f"sha256:{asset.asset.sha256}",
                "name": name,
                "state": "uploaded",
            }
            response_size = value.get("size")
            if (
                not isinstance(response_size, int)
                or isinstance(response_size, bool)
                or response_size != size
                or "label" not in value
                or value["label"] is not None
                or any(value.get(key) != expected_value for key, expected_value in expected.items())
            ):
                raise _ResponseValidationError("upload response does not match the request")

        return self._object(
            self._request_json(
                "POST",
                path,
                expected_status=http.client.CREATED,
                body=_DescriptorBody(descriptor, size),
                headers={
                    "Content-Length": str(size),
                    "Content-Type": "application/octet-stream",
                },
                mutation=True,
                upload_host=True,
                response_kind="object",
                response_validator=validate_uploaded,
            ),
            "GitHub release-asset response",
        )

    def publish_release(self, release_id: int) -> Mapping[str, Any]:
        checked_id = _positive_id(release_id, "GitHub release ID")
        body = _json_bytes({"draft": False, "make_latest": "false"})
        path = f"/repos/{self._repository_path}/releases/{checked_id}"

        def validate_published(value: object) -> None:
            if not isinstance(value, dict):
                raise _ResponseValidationError("publish response is not an object")
            if (
                _response_positive_id(value.get("id")) != checked_id
                or value.get("draft") is not False
                or not isinstance(value.get("immutable"), bool)
                or value.get("prerelease") is not False
            ):
                raise _ResponseValidationError("publish response does not match the request")

        return self._object(
            self._request_json(
                "PATCH",
                path,
                expected_status=http.client.OK,
                body=body,
                headers={
                    "Content-Length": str(len(body)),
                    "Content-Type": "application/json",
                },
                mutation=True,
                response_kind="object",
                response_validator=validate_published,
            ),
            "GitHub publish-release response",
        )
