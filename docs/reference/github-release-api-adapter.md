# GitHub release API adapter contract

Extra CODEOWNERS includes a standard-library adapter for the immutable release
controller's `ReleaseAPI` protocol. The adapter has no command-line interface,
doesn't read a token from the environment, and isn't called by a workflow. It
cannot publish anything in the current repository.

The implementation lives in `.github/scripts/github_release_api.py`. It exists
so the network boundary can be reviewed and tested before any workflow receives
release authority. The final asset policy, privileged workflow handoff, and
operator recovery procedure remain separate work.

The separate
[immutable-release preflight contract](immutable-release-preflight.md) needs
the **Administration: read** repository permission. Do not add that permission
to this adapter's **Contents: write** publication token.

## Construction and routing

`GitHubReleaseAPI` requires a token and an exact `OWNER/REPOSITORY` name in its
constructor. Each repository-name component may contain at most 100 characters
and cannot be `.` or `..`. The token must be printable ASCII with no whitespace
or control characters and may contain at most 4,096 bytes. The adapter never
includes it in `repr()`, exceptions, or logs.

The adapter cannot inspect the token's repository selection. Future workflow
wiring must mint a short-lived token restricted to the manifest's exact
repository ID; a general personal access token or multi-repository App token is
not acceptable. The controller also rechecks the live ID before writes and
while accepting final state, but GitHub's name-based release routes offer no
atomic ID-and-mutation request.

All REST requests use `http.client.HTTPSConnection` with these fixed values:

| Setting | Value |
| --- | --- |
| API host | `api.github.com` |
| Upload host | `uploads.github.com` |
| REST API version | `2026-03-10` |
| Media type | `application/vnd.github+json` |
| Response content encoding | `identity` |
| Default socket-operation timeout | 30 seconds |
| Maximum configured socket-operation timeout | 120 seconds |

The adapter opens one connection for one request. It doesn't follow redirects
or retry any operation. This matters for writes: retrying after a lost response
could create a second draft or collide with an asset whose upload actually
finished.

The configured timeout is the `http.client` socket timeout, not a wall-clock
deadline. DNS resolution may outlast it, and a peer that keeps making progress
can extend the complete operation. Any future workflow that calls the adapter
must add a finite job-level timeout and treat cancellation during a mutation as
ambiguous state for the next run to reconcile.

GitHub documents the upstream contracts for
[releases](https://docs.github.com/en/rest/releases/releases?apiVersion=2026-03-10),
[release assets](https://docs.github.com/en/rest/releases/assets?apiVersion=2026-03-10),
[Git references](https://docs.github.com/en/rest/git/refs?apiVersion=2026-03-10),
and [annotated tags](https://docs.github.com/en/rest/git/tags?apiVersion=2026-03-10).

## Protocol methods

The adapter implements the protocol's eight operations. There is no operation
for deleting or replacing a release, asset, or Git reference.

| Method | REST request | Required success | Additional check |
| --- | --- | --- | --- |
| `repository_id()` | `GET /repos/OWNER/REPOSITORY` | `200` object | `full_name` must equal the trusted constructor value; `id` must be positive and at most `2^63 - 1`. |
| `resolve_tag(tag)` | `GET /repos/OWNER/REPOSITORY/git/ref/tags/TAG` | `200` object | The returned `ref` must be exact. A lightweight tag must point to a commit. |
| `list_releases(page, per_page)` | `GET /repos/OWNER/REPOSITORY/releases` | `200` object array | Page is 1 through 10; page size is 1 through 100. |
| `create_draft(plan)` | `POST /repos/OWNER/REPOSITORY/releases` | `201` object | Sends the exact tag, full target commit, name, controller marker, `draft: true`, `prerelease: false`, `generate_release_notes: false`, and `make_latest: "false"`. |
| `get_release(id)` | `GET /repos/OWNER/REPOSITORY/releases/ID` | `200` object | The requested and returned IDs must match and be positive integers no greater than `2^63 - 1`. |
| `list_assets(id, page, per_page)` | `GET /repos/OWNER/REPOSITORY/releases/ID/assets` | `200` object array | Applies the same ID and pagination bounds. |
| `upload_asset(id, url, asset)` | `POST` to the exact trusted upload path | `201` object | Adds one percent-encoded `name` query, sends no label, and streams the bytes as `application/octet-stream` from the retained descriptor. |
| `publish_release(id)` | `PATCH /repos/OWNER/REPOSITORY/releases/ID` | `200` object | Sends `{"draft":false,"make_latest":"false"}` so publication cannot change the repository's latest-release pointer. |

An annotated tag adds one request to `/git/tags/OBJECT_ID`. Its returned object
ID and tag name must match the reference response, and its target must be a
commit. Tag chains, trees, blobs, substituted names, and malformed object IDs
fail closed.

The create body doesn't ask GitHub to generate release notes because that would
add server-selected text outside the reviewed manifest identity. Creation and
publication both disable GitHub's default latest-release side effect. A future
workflow needs a separate reviewed policy if it intends to move that pointer.
The controller still validates every returned release and asset field described in the
[immutable release controller contract](immutable-release-controller.md).

## Successful response bounds

Every successful response must be UTF-8 `application/json` with no content
encoding other than `identity`. A response may contain at most 8 MiB, 100,000
JSON items, and 16 nested levels. Duplicate object keys, floating-point and
non-finite numbers, integers outside the signed 63-bit range, malformed content
lengths, and truncated bodies are invalid.

Methods that return one record require a JSON object. List methods require an
array containing only objects. The controller applies the narrower release and
asset schemas after the adapter returns.

## Retained descriptor uploads

`upload_asset()` accepts only this exact template, with the trusted repository
and release ID substituted:

```text
https://uploads.github.com/repos/OWNER/REPOSITORY/releases/RELEASE_ID/assets{?name,label}
```

The request sends `application/octet-stream` with the asset's exact declared
`Content-Length`. It uses `os.pread()` in 1 MiB chunks, so it doesn't change the
descriptor's current position. The adapter never closes the descriptor, seeks
it, or reopens a pathname. The controller retains ownership and rehashes the
same descriptor after upload.

The adapter checks for early end-of-file, an extra byte beyond the declared
size, and read errors. Any of these failures after the request starts has an
ambiguous outcome because GitHub may have received some or all of the body.

## Failure classification

`ControllerError` means the adapter has no evidence that a write was accepted.
`AmbiguousMutationError` means a write may have succeeded, so the controller
must use its operation-specific readback instead of retrying.

| Condition | Read request | Create, upload, or publish request |
| --- | --- | --- |
| Transport loss | `ControllerError` | `AmbiguousMutationError` after request start |
| Unexpected informational `1xx` response | `ControllerError` | `AmbiguousMutationError` |
| HTTP `408` or `5xx` | `ControllerError` | `AmbiguousMutationError` |
| Other `4xx` | `ControllerError` | `ControllerError` |
| Unexpected `2xx` | `ControllerError` | `AmbiguousMutationError` |
| Redirect or another unexpected status | `ControllerError` | `ControllerError`; never follow the redirect |
| Truncated, malformed, unbounded, or unsupported successful response | `ControllerError` | `AmbiguousMutationError` |
| Upload descriptor read failure after request start | Not applicable | `AmbiguousMutationError` |

An upload that receives `502` is never retried or deleted. GitHub may have left
a starter asset, so the controller relists assets and accepts only the exact
planned name, size, state, and server digest.

HTTP and transport errors contain only the method, a bounded path without its
query, status, and a bounded GitHub request ID. They never include the
Authorization header, token, response body, transport exception text, or asset
contents.

## Publication remains blocked

No workflow imports the adapter or controller. The release workflow's jobs with
write authority still depend directly on the unconditional
`publication-block` job, and that job exits unsuccessfully without permissions.
Adding this adapter does not supply a token, grant a permission, invoke a
mutation, or make tagged publication reachable.

Future wiring must consume the repository-ID-bound record produced by the
[immutable-release preflight](immutable-release-preflight.md) before it invokes
the controller. That endpoint requires the **Administration: read** repository
permission, so it belongs in a separate job. The **Contents: write**
publication token must not perform the check itself. Publication stays blocked
until that evidence handoff and its live contract test exist.
