# Review pull-request container evidence

This procedure is for maintainers reviewing the `linux/amd64` and `linux/arm64`
evidence artifacts from pull-request CI. At the end, you will know whether both
artifacts came from one successful workflow attempt, whether their outer ZIP
envelopes and internal references agree, and whether the observed policy drift
is understood.

!!! danger "This review does not approve distribution"
    Extra CODEOWNERS has no supported container release. A successful review
    does not make the evidence source-complete and does not authorize an image,
    chart, package, or GitHub release.

The `main` publication job has been removed. A tag run can validate source,
build proof, and scan a candidate with repository-read permission, but a
separate blocker prevents every job with package-write, signing, attestation,
or release authority from running.

Four open issues define the remaining boundary:

- [#18](https://github.com/stampbot/extra-codeowners/issues/18) covers the six
  native-wheel owners that remain after Greenlet's closed-world coverage.
- [#28](https://github.com/stampbot/extra-codeowners/issues/28) covers the
  privilege-separated release pipeline and bounded recipient verifier.
- [#32](https://github.com/stampbot/extra-codeowners/issues/32) covers retaining
  the selected Python proof in release evidence and handing it to future
  publication jobs.
- [#25](https://github.com/stampbot/extra-codeowners/issues/25) covers the first
  immutable GitHub release after the evidence and privilege boundaries close.

Pull-request CI already binds the hash-pinned PEP 517 proof and exact installed
application wheel into both platform artifacts. Read-only manual runs and the
tagged candidate scan use the same proof implementation.

## Before you start

Plan for four isolated phases. The first and fourth can use separately created
instances of the same staging-host design.

| Phase | Environment | Allowed work |
| --- | --- | --- |
| Fetch | Credentialed staging host | Query GitHub's REST API and save raw bytes with a short-lived read-only token. Do not run pull-request code or parse artifacts. |
| Parse and review | No-secret offline VM | Validate and inspect transferred inputs with no network or Docker socket, explicit resource quotas, and a fresh user-owned `0700` working directory. |
| Build and test | Separate no-secret VM | Run pull-request code and repository gates. Restricted outbound dependency access and an isolated Docker daemon are allowed here, never in the parsing VM. |
| Revalidate | Fresh credentialed staging host | Query the pull request immediately before recording a decision or merging. Do not reuse the parsing or test VM. |

The staging host needs Linux, Bash, `gh`, `jq`, `sha256sum`, and Git. The review
VM needs the same local command-line tools plus a prepared copy of the
repository's locked mise/uv environment. Prepare that environment before
disabling the network.

### Freeze the helper you trust

Use a previously reviewed, immutable helper checkout from the default branch.
Never execute the helper supplied by the pull request under review. If the pull
request changes the helper or expected artifact envelope, review that change
and its hostile-input corpus first. An older helper failing closed is not a
reason to fall back to a generic extractor.

### Treat every input as hostile

- Do not use `gh run download`, `unzip`, or an archive GUI. They extract before
  this project's bounds and envelope checks run.
- Do not open the nested evidence tar with `tar` or Python's ordinary
  `tarfile` iteration. Issue #28 must ship the bounded recipient verifier.
- Do not execute, import, or source anything retained from an artifact.
- Use a disposable VM when the contributor or input is not already trusted. A
  container shares its host kernel and is not the same isolation boundary.

CI retains these artifacts for five days. If they expire, rerun CI for the
exact pull-request head. Treat the new base, synthetic merge commit, and run
attempt as a new candidate. Never combine platforms from different runs or
attempts.

The review moves through these boundaries in order:

1. Authenticate the workflow run and raw ZIPs on the staging host.
2. Transfer the identity packet and parse both ZIPs offline.
3. Bind extracted metadata back to the GitHub REST records.
4. Review policy, inventory, and source drift.
5. Confirm that the known source gap remains explicit.
6. Run repository gates in the separate test VM.
7. Revalidate the live pull request on a fresh staging host.
8. Record the review while keeping distribution denied.

## 1. Fetch and authenticate the raw ZIPs

Run this section only on the credentialed staging host. Set `GH_TOKEN` through
that host's secret-injection mechanism; do not persist it with `gh auth login`.
Replace the pull-request and run IDs:

```bash
set -euo pipefail
umask 077

export REPOSITORY='stampbot/extra-codeowners'
export PR_NUMBER='REPLACE_WITH_PULL_REQUEST_NUMBER'
export RUN_ID='REPLACE_WITH_WORKFLOW_RUN_ID'
: "${GH_TOKEN:?inject a short-lived read-only GitHub token}"

case "$PR_NUMBER" in (*[!0-9]*|'') exit 1 ;; esac
case "$RUN_ID" in (*[!0-9]*|'') exit 1 ;; esac

FETCH_ROOT="$HOME/extra-codeowners-fetch-${RUN_ID}"
test ! -e "$FETCH_ROOT"
mkdir -m 0700 -- "$FETCH_ROOT"
mkdir -m 0700 -- "$FETCH_ROOT/raw"

gh api "/repos/${REPOSITORY}/pulls/${PR_NUMBER}" > "$FETCH_ROOT/pr.json"
gh api "/repos/${REPOSITORY}/actions/runs/${RUN_ID}" > "$FETCH_ROOT/run.json"
gh api --paginate \
  "/repos/${REPOSITORY}/actions/runs/${RUN_ID}/artifacts?per_page=100" \
  --slurp | jq '{artifacts: map(.artifacts[]) }' > "$FETCH_ROOT/artifacts.json"
```

Use the run's top-level `head_sha` as the historical pull-request head. GitHub
can rewrite the head and base fields nested under `pull_requests` when the pull
request moves, so those nested fields establish only the pull-request number;
they are not historical evidence. Require the current pull request to retain
the run head and repository identities, and bind its current base to the
synthetic merge commit below. If any value moved, stop and review a new run.
The top-level run `head_sha` is the pull-request head SHA. It is **not** the
synthetic merge SHA used by `GITHUB_SHA` in this workflow.

```bash
jq -e \
  --argjson number "$PR_NUMBER" \
  '
    .event == "pull_request"
    and .conclusion == "success"
    and .status == "completed"
    and .path == ".github/workflows/ci.yml"
    and (.head_sha | type == "string" and test("^[0-9a-f]{40}$"))
    and (.repository.id | type == "number")
    and (.head_repository.id | type == "number")
    and (.pull_requests | type == "array")
    and ([.pull_requests[].number] | index($number) != null)
  ' "$FETCH_ROOT/run.json" >/dev/null

RUN_ATTEMPT="$(jq -er '.run_attempt | select(type == "number") | tostring' \
  "$FETCH_ROOT/run.json")"
RUN_HEAD_SHA="$(jq -er '.head_sha' "$FETCH_ROOT/run.json")"
REPOSITORY_ID="$(jq -er '.repository.id' "$FETCH_ROOT/run.json")"
RUN_HEAD_REPOSITORY_ID="$(jq -er '.head_repository.id' "$FETCH_ROOT/run.json")"

jq -e \
  --argjson number "$PR_NUMBER" \
  --arg head "$RUN_HEAD_SHA" \
  --argjson repository "$REPOSITORY_ID" \
  --argjson head_repository "$RUN_HEAD_REPOSITORY_ID" '
    .number == $number
    and .head.sha == $head
    and (.base.sha | type == "string" and test("^[0-9a-f]{40}$"))
    and .head.repo.id == $head_repository
    and .base.repo.id == $repository
  ' "$FETCH_ROOT/pr.json" >/dev/null

PR_HEAD_SHA="$RUN_HEAD_SHA"
PR_BASE_SHA="$(jq -er '.base.sha' "$FETCH_ROOT/pr.json")"
PR_HEAD_REPOSITORY_ID="$(jq -er '.head.repo.id' "$FETCH_ROOT/pr.json")"

gh api --paginate \
  "/repos/${REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}/jobs?per_page=100" \
  --slurp | jq '{jobs: map(.jobs[]) }' > "$FETCH_ROOT/jobs.json"
jq -e --argjson run "$RUN_ID" '
  [
    .jobs[]
    | select(.name == "Container build (amd64)" or .name == "Container build (arm64)")
  ] as $container_jobs
  | ($container_jobs | length) == 2
    and ([$container_jobs[].name] | unique | length) == 2
    and all($container_jobs[];
      .run_id == $run and .status == "completed" and .conclusion == "success"
    )
' "$FETCH_ROOT/jobs.json" >/dev/null
```

Each artifact name is expanded by GitHub before upload and exposes its
architecture, synthetic merge SHA, and run attempt without parsing contributor
ZIP bytes. Select exactly two matching, unexpired artifacts and bind their REST
metadata to the workflow run and pull-request head:

```bash
ARTIFACT_PATTERN='^container-evidence-(?<architecture>amd64|arm64)-(?<merge>[0-9a-f]{40})-attempt-(?<attempt>[1-9][0-9]*)$'

jq -e \
  --arg pattern "$ARTIFACT_PATTERN" \
  --arg attempt "$RUN_ATTEMPT" \
  --arg head "$PR_HEAD_SHA" \
  --argjson run "$RUN_ID" \
  --argjson repository "$REPOSITORY_ID" \
  --argjson head_repository "$PR_HEAD_REPOSITORY_ID" '
    [
      .artifacts[]
      | (.name | try capture($pattern) catch empty) as $identity
      | select($identity.attempt == $attempt)
      | . + {identity: $identity}
    ] as $selected
    | if
        ($selected | length) == 2
        and ([$selected[].identity.architecture] | sort) == ["amd64", "arm64"]
        and ([$selected[].identity.merge] | unique | length) == 1
        and all($selected[];
          .expired == false
          and (.size_in_bytes | type) == "number"
          and .size_in_bytes > 0
          and (.digest | type) == "string"
          and (.digest | test("^sha256:[0-9a-f]{64}$"))
          and .workflow_run.id == $run
          and .workflow_run.repository_id == $repository
          and .workflow_run.head_repository_id == $head_repository
          and .workflow_run.head_sha == $head
        )
      then $selected
      else error("artifact identities do not describe one exact run")
      end
  ' "$FETCH_ROOT/artifacts.json" > "$FETCH_ROOT/selected-artifacts.json"

MERGE_SHA="$(jq -er '[.[].identity.merge] | unique | if length == 1 then .[0] else error end' \
  "$FETCH_ROOT/selected-artifacts.json")"
```

Fetch that exact commit object. A current pull-request candidate must be a
two-parent synthetic merge whose parents are the recorded base and head, in
that order:

```bash
gh api "/repos/${REPOSITORY}/commits/${MERGE_SHA}" > "$FETCH_ROOT/merge-commit.json"
jq -e \
  --arg merge "$MERGE_SHA" \
  --arg base "$PR_BASE_SHA" \
  --arg head "$PR_HEAD_SHA" '
    .sha == $merge
    and (.parents | length) == 2
    and .parents[0].sha == $base
    and .parents[1].sha == $head
  ' "$FETCH_ROOT/merge-commit.json" >/dev/null
```

Download each raw ZIP through the artifact REST endpoint. The `digest` returned
by the API is the SHA-256 of those raw ZIP bytes. Verify both size and digest
before transfer:

```bash
for architecture in amd64 arm64; do
  artifact_id="$(jq -er --arg architecture "$architecture" \
    '.[] | select(.identity.architecture == $architecture) | .id' \
    "$FETCH_ROOT/selected-artifacts.json")"
  expected_size="$(jq -er --arg architecture "$architecture" \
    '.[] | select(.identity.architecture == $architecture) | .size_in_bytes' \
    "$FETCH_ROOT/selected-artifacts.json")"
  expected_digest="$(jq -er --arg architecture "$architecture" \
    '.[] | select(.identity.architecture == $architecture) | .digest' \
    "$FETCH_ROOT/selected-artifacts.json")"
  archive="$FETCH_ROOT/raw/${architecture}.zip"
  gh api "/repos/${REPOSITORY}/actions/artifacts/${artifact_id}/zip" > "$archive"
  test "$(stat -c %s "$archive")" -eq "$expected_size"
  test "$(sha256sum "$archive" | cut -d' ' -f1)" = "${expected_digest#sha256:}"
done
(cd "$FETCH_ROOT/raw" && sha256sum amd64.zip arm64.zip > SHA256SUMS)
(cd "$FETCH_ROOT" && sha256sum \
  pr.json run.json jobs.json selected-artifacts.json merge-commit.json \
  raw/SHA256SUMS raw/amd64.zip raw/arm64.zip > IDENTITY_SHA256SUMS)
IDENTITY_PACKET_DIGEST="$(sha256sum "$FETCH_ROOT/IDENTITY_SHA256SUMS" | cut -d' ' -f1)"
printf 'Record this identity-packet digest out of band: %s\n' \
  "$IDENTITY_PACKET_DIGEST"
```

Unset and revoke the token, then transfer `pr.json`, `run.json`, `jobs.json`,
`selected-artifacts.json`, `merge-commit.json`, `IDENTITY_SHA256SUMS`, and the
`raw/` directory to the no-secret VM. Send `IDENTITY_PACKET_DIGEST` through a
separate authenticated channel or record it in the review ticket. Destroy the
credentialed staging host after the transfer is verified.

```bash
unset GH_TOKEN
```

## 2. Validate and extract in the no-secret VM

Mount the transferred directory and the previously reviewed helper checkout
read-only. Provision that trusted checkout's locked Python environment before
disabling networking; the parsing VM must not perform a cold mise or uv install.
Bind the helper checkout to the exact commit and out-of-band identity below.
The commands reject symlinks and group- or other-writable components in the
existing directory chains for every input root and the extraction parent. They
then create the extraction root as a private directory owned by the current
user.

!!! warning "A format migration needs a one-time trust bootstrap"
    A schema or provider-envelope migration may have no earlier default-branch
    helper that understands the new format. Stop before opening an artifact.
    In a separate no-secret VM, review the candidate helper, workflow, resource
    bounds, and hostile-input corpus as security-sensitive code. Run the full
    adversarial test suite, freeze the reviewed commit and helper bytes, and
    record that identity in the review ticket.
    Only that frozen candidate may become `TRUSTED_ROOT` for its one-time
    integration review. After the change merges, return to a previously
    reviewed default-branch helper. If you cannot establish this bootstrap
    trust, do not review or merge the evidence change.

```bash
set -euo pipefail
umask 077

export INCOMING='/mnt/read-only/extra-codeowners-fetch-RUN_ID'
export TRUSTED_ROOT='/mnt/read-only/trusted-extra-codeowners'
export TRUSTED_HELPER_SHA='REPLACE_WITH_REVIEWED_40_CHARACTER_HELPER_COMMIT'
export PR_SOURCE='/mnt/read-only/pull-request-source'
export REVIEW_PARENT="$HOME/extra-codeowners-review-RUN_ID"
export EXPECTED_IDENTITY_PACKET_DIGEST='REPLACE_WITH_OUT_OF_BAND_SHA256'
export GIT_NO_REPLACE_OBJECTS=1

require_safe_directory_chain() {
  local requested="$1"
  local current='/'
  local remainder component permissions
  case "$requested" in (/*) ;; (*) return 1 ;; esac
  test "$(realpath -e -- "$requested")" = "$requested" || return 1
  test -d "$current" || return 1
  test ! -L "$current" || return 1
  permissions="$(stat -c %a -- "$current")" || return 1
  (( (8#$permissions & 0022) == 0 )) || return 1
  remainder="${requested#/}"
  while test -n "$remainder"; do
    component="${remainder%%/*}"
    test -n "$component" || return 1
    current="${current%/}/${component}"
    test -d "$current" || return 1
    test ! -L "$current" || return 1
    permissions="$(stat -c %a -- "$current")" || return 1
    (( (8#$permissions & 0022) == 0 )) || return 1
    case "$remainder" in
      (*/*) remainder="${remainder#*/}" ;;
      (*) remainder='' ;;
    esac
  done
  return 0
}

DIRECTORY_PROBE="$(mktemp -d "${HOME}/.extra-codeowners-directory-probe.XXXXXX")"
chmod 0700 -- "$DIRECTORY_PROBE"
require_safe_directory_chain "$DIRECTORY_PROBE"
chmod 0777 -- "$DIRECTORY_PROBE"
if require_safe_directory_chain "$DIRECTORY_PROBE"; then
  exit 1
fi
chmod 0700 -- "$DIRECTORY_PROBE"
DIRECTORY_PROBE_LINK="${DIRECTORY_PROBE}.link"
ln -s -- "$DIRECTORY_PROBE" "$DIRECTORY_PROBE_LINK"
if require_safe_directory_chain "$DIRECTORY_PROBE_LINK"; then
  exit 1
fi
rm -- "$DIRECTORY_PROBE_LINK"
rmdir -- "$DIRECTORY_PROBE"

for trusted_directory in "$INCOMING" "$TRUSTED_ROOT" "$PR_SOURCE" \
  "$(dirname -- "$REVIEW_PARENT")"; do
  require_safe_directory_chain "$trusted_directory"
done

case "$TRUSTED_HELPER_SHA" in (*[!0-9a-f]*|'') exit 1 ;; esac
test "${#TRUSTED_HELPER_SHA}" -eq 40
test "$(git -C "$TRUSTED_ROOT" rev-parse HEAD)" = "$TRUSTED_HELPER_SHA"
test -z "$(git -C "$TRUSTED_ROOT" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=all)"
test "$(sha256sum "$INCOMING/IDENTITY_SHA256SUMS" | cut -d' ' -f1)" = \
  "$EXPECTED_IDENTITY_PACKET_DIGEST"
(cd "$INCOMING" && sha256sum --check IDENTITY_SHA256SUMS)

MERGE_SHA="$(jq -er '[.[].identity.merge] | unique | if length == 1 then .[0] else error end' \
  "$INCOMING/selected-artifacts.json")"
test "$(git -C "$PR_SOURCE" rev-parse HEAD)" = "$MERGE_SHA"
test -z "$(git -C "$PR_SOURCE" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=all)"

test ! -e "$REVIEW_PARENT"
mkdir -m 0700 -- "$REVIEW_PARENT"
test -d "$REVIEW_PARENT" && test ! -L "$REVIEW_PARENT"
test "$(stat -c %u "$REVIEW_PARENT")" -eq "$(id -u)"
test "$(stat -c %a "$REVIEW_PARENT")" = 700
require_safe_directory_chain "$REVIEW_PARENT"

REVIEWED_INPUTS="$REVIEW_PARENT/reviewed-inputs"
mkdir -m 0700 -- "$REVIEWED_INPUTS"
materialize_regular_blob() {
  local path="$1"
  local output="$2"
  local entry mode object_type object_id retained_path
  entry="$(git -C "$PR_SOURCE" ls-tree "$MERGE_SHA" -- "$path")"
  IFS=$' \t' read -r mode object_type object_id retained_path <<< "$entry"
  test "$mode" = 100644
  test "$object_type" = blob
  test "$retained_path" = "$path"
  case "$object_id" in (*[!0-9a-f]*|'') return 1 ;; esac
  case "${#object_id}" in (40|64) ;; (*) return 1 ;; esac
  git -C "$PR_SOURCE" show "${MERGE_SHA}:${path}" > "$output"
  chmod 0600 -- "$output"
  test -f "$output" && test ! -L "$output"
  test "$(git -C "$PR_SOURCE" hash-object "$output")" = "$object_id"
}
materialize_regular_blob .compliance/container-policy.json \
  "$REVIEWED_INPUTS/container-policy.json"
materialize_regular_blob Dockerfile "$REVIEWED_INPUTS/Dockerfile"
POLICY="$REVIEWED_INPUTS/container-policy.json"
DOCKERFILE="$REVIEWED_INPUTS/Dockerfile"

"$TRUSTED_ROOT/.venv/bin/python" \
  "$TRUSTED_ROOT/.github/scripts/container_evidence.py" extract-ci-artifact \
  --archive "$INCOMING/raw/amd64.zip" \
  --architecture amd64 \
  --output "$REVIEW_PARENT/amd64"
"$TRUSTED_ROOT/.venv/bin/python" \
  "$TRUSTED_ROOT/.github/scripts/container_evidence.py" extract-ci-artifact \
  --archive "$INCOMING/raw/arm64.zip" \
  --architecture arm64 \
  --output "$REVIEW_PARENT/arm64"
"$TRUSTED_ROOT/.venv/bin/python" \
  "$TRUSTED_ROOT/.github/scripts/container_evidence.py" compare-ci-artifacts \
  --amd64 "$REVIEW_PARENT/amd64" \
  --arm64 "$REVIEW_PARENT/arm64"
for architecture in amd64 arm64; do
  "$TRUSTED_ROOT/.venv/bin/python" \
    "$TRUSTED_ROOT/.github/scripts/container_evidence.py" verify-ci-policy \
    --inventory "$REVIEW_PARENT/${architecture}/components-${architecture}.json" \
    --files-inventory "$REVIEW_PARENT/${architecture}/all-layer-files-${architecture}.json" \
    --policy "$POLICY" \
    --dockerfile "$DOCKERFILE"
done
(cd "$REVIEW_PARENT" && find amd64 arm64 -type f -printf '%p\n' | sort)
```

The helper requires the exact raw envelope currently emitted by pinned
`actions/upload-artifact@v7.0.1`. It bounds the ZIP and central directory before
Python allocates entries, requires exact provider metadata and record order,
streams CRC-checked payloads into exclusive no-follow files, validates
canonical JSON and every cross-file digest, and renames the completed directory
atomically. A GitHub backend-envelope change intentionally fails. Review and
update the helper and its hostile corpus; never switch to an ordinary unzip.

The final listing must contain exactly:

```text
amd64/all-layer-files-amd64.json
amd64/components-amd64.json
amd64/evidence-predicate-amd64.json
amd64/extra-codeowners-ci-linux-amd64-evidence.tar.gz
amd64/extra-codeowners-ci-linux-amd64-evidence.tar.gz.sha256
amd64/run-metadata-amd64.json
arm64/all-layer-files-arm64.json
arm64/components-arm64.json
arm64/evidence-predicate-arm64.json
arm64/extra-codeowners-ci-linux-arm64-evidence.tar.gz
arm64/extra-codeowners-ci-linux-arm64-evidence.tar.gz.sha256
arm64/run-metadata-arm64.json
```

The comparator requires both platforms to share one workflow context while
having distinct platform configuration digests. It does not authenticate that
context against GitHub; the next step does.

## 3. Bind extracted metadata to the REST records

Recompute the trusted values from the transferred API responses. For both
architectures, require the extracted run metadata to match the REST run, pull
request, artifact name, and exact merge commit:

```bash
PR_NUMBER="$(jq -er '.number | tostring' "$INCOMING/pr.json")"
PR_HEAD_SHA="$(jq -er '.head_sha' "$INCOMING/run.json")"
PR_BASE_SHA="$(jq -er '.base.sha' "$INCOMING/pr.json")"
REPOSITORY_ID="$(jq -er '.repository.id | tostring' "$INCOMING/run.json")"
PR_HEAD_REPOSITORY_ID="$(jq -er '.head_repository.id | tostring' \
  "$INCOMING/run.json")"
RUN_ID="$(jq -er '.id | tostring' "$INCOMING/run.json")"
RUN_ATTEMPT="$(jq -er '.run_attempt' "$INCOMING/run.json")"
MERGE_SHA="$(jq -er '[.[].identity.merge] | unique | if length == 1 then .[0] else error end' \
  "$INCOMING/selected-artifacts.json")"
EXPECTED_WORKFLOW_REF="stampbot/extra-codeowners/.github/workflows/ci.yml@refs/pull/${PR_NUMBER}/merge"
PYTHON_ARTIFACT_NAME="python-distributions-selected-${MERGE_SHA}-attempt-${RUN_ATTEMPT}"
PYTHON_ARTIFACT="$REVIEW_PARENT/selected-python-artifact.json"
jq -e \
  --arg name "$PYTHON_ARTIFACT_NAME" \
  --arg head "$PR_HEAD_SHA" \
  --argjson run "$RUN_ID" \
  --argjson repository "$REPOSITORY_ID" \
  --argjson head_repository "$PR_HEAD_REPOSITORY_ID" '
    [
      .artifacts[]
      | select(
          .name == $name
          and .expired == false
          and (.id | type) == "number"
          and .id > 0
          and (.size_in_bytes | type) == "number"
          and .size_in_bytes > 0
          and (.digest | type) == "string"
          and (.digest | test("^sha256:[0-9a-f]{64}$"))
          and .workflow_run.id == $run
          and .workflow_run.repository_id == $repository
          and .workflow_run.head_repository_id == $head_repository
          and .workflow_run.head_sha == $head
        )
    ]
    | if length == 1
      then .[0]
      else error("selected Python artifact mismatch")
      end
  ' "$INCOMING/artifacts.json" > "$PYTHON_ARTIFACT"
PYTHON_ARTIFACT_ID="$(jq -er '.id | tostring' "$PYTHON_ARTIFACT")"
PYTHON_ARTIFACT_DIGEST="$(jq -er \
  '.digest | capture("^sha256:(?<value>[0-9a-f]{64})$").value' \
  "$PYTHON_ARTIFACT")"

jq -e \
  --argjson number "$PR_NUMBER" \
  --arg head "$PR_HEAD_SHA" \
  --argjson repository "$REPOSITORY_ID" \
  --argjson head_repository "$PR_HEAD_REPOSITORY_ID" '
    .event == "pull_request"
    and .head_sha == $head
    and .repository.id == $repository
    and .head_repository.id == $head_repository
    and ([.pull_requests[].number] | index($number) != null)
  ' "$INCOMING/run.json" >/dev/null
jq -e \
  --argjson number "$PR_NUMBER" \
  --arg head "$PR_HEAD_SHA" \
  --arg base "$PR_BASE_SHA" \
  --argjson repository "$REPOSITORY_ID" \
  --argjson head_repository "$PR_HEAD_REPOSITORY_ID" '
    .number == $number
    and .head.sha == $head
    and .base.sha == $base
    and .head.repo.id == $head_repository
    and .base.repo.id == $repository
  ' "$INCOMING/pr.json" >/dev/null
jq -e \
  --arg merge "$MERGE_SHA" \
  --arg base "$PR_BASE_SHA" \
  --arg head "$PR_HEAD_SHA" '
    .sha == $merge
    and (.parents | length) == 2
    and .parents[0].sha == $base
    and .parents[1].sha == $head
  ' "$INCOMING/merge-commit.json" >/dev/null

for architecture in amd64 arm64; do
  metadata="$REVIEW_PARENT/${architecture}/run-metadata-${architecture}.json"
  jq -e \
    --arg run "$RUN_ID" \
    --argjson attempt "$RUN_ATTEMPT" \
    --arg pr "$PR_NUMBER" \
    --arg head "$PR_HEAD_SHA" \
    --arg base "$PR_BASE_SHA" \
    --arg repository "$REPOSITORY_ID" \
    --arg head_repository "$PR_HEAD_REPOSITORY_ID" \
    --arg merge "$MERGE_SHA" \
    --arg workflow_ref "$EXPECTED_WORKFLOW_REF" \
    --arg python_artifact_id "$PYTHON_ARTIFACT_ID" \
    --arg python_artifact_digest "$PYTHON_ARTIFACT_DIGEST" \
    --arg architecture "$architecture" '
      .run_id == $run
      and .run_attempt == $attempt
      and .event_name == "pull_request"
      and .repository_id == $repository
      and .pr_number == $pr
      and .pr_head_sha == $head
      and .pr_base_sha == $base
      and .pr_head_repository_id == $head_repository
      and .github_sha == $merge
      and .checkout_sha == $merge
      and .workflow_ref == $workflow_ref
      and (.workflow_sha | test("^[0-9a-f]{40}$"))
      and .python_distribution_artifact_id == $python_artifact_id
      and .python_distribution_artifact_digest == $python_artifact_digest
      and .application_source_revision == $merge
      and (.application_wheel_sha256 | test("^[0-9a-f]{64}$"))
      and (.application_selection_record_sha256 | test("^[0-9a-f]{64}$"))
      and .platform == ("linux/" + $architecture)
      and .architecture == $architecture
    ' "$metadata" >/dev/null
done
```

The helper also requires the image revision, selected-wheel and selection-record
labels, inventory subject, and local image configuration digest to match each
metadata record. It requires both platforms to share the source, wheel,
selection, selected-artifact ID, and selected-artifact digest. The selected
artifact's REST digest includes a `sha256:` prefix; the upload action output
recorded by the workflow is the 64-character value. Current GitHub REST run and
artifact responses do not independently expose `github.workflow_sha`; record
and compare it across platforms, but do not describe that field alone as a
signature or external provenance statement.

## 4. Review policy and inventory drift

Use the pull request's exact source tree only as untrusted review data. The
trusted helper invocation above enforces the standalone inventory, complete
policy schema, components, payload baselines, APK history, and license
coverage. It also replays and enforces canonical post-base directory effects
and removals. The artifact extractor separately enforces the all-layer schema
and cross-file relationships. The
following diffs make the policy decisions visible to a human. Set `PR_SOURCE`
to the same read-only checkout of the exact synthetic merge commit used above:

```bash
test "$POLICY" = "$REVIEWED_INPUTS/container-policy.json"
PR_BASE_SHA="$(jq -er '.base.sha' "$INCOMING/pr.json")"

DIFF_ROOT="$REVIEW_PARENT/policy-diff"
test ! -e "$DIFF_ROOT"
mkdir -m 0700 -- "$DIFF_ROOT"
SOURCE_DIFF="$DIFF_ROOT/reviewed-source.patch"
git -C "$PR_SOURCE" --no-pager -c core.pager=cat -c diff.external= \
  diff --no-color --no-ext-diff --no-textconv --text \
  "$PR_BASE_SHA" "$MERGE_SHA" -- \
  .compliance/container-policy.json Dockerfile uv.lock \
  .github/scripts/container_evidence.py .github/workflows/ci.yml \
  > "$SOURCE_DIFF"
LC_ALL=C sed -n 'l' "$SOURCE_DIFF"

for architecture in amd64 arm64; do
  platform="linux/${architecture}"
  inventory="$REVIEW_PARENT/${architecture}/components-${architecture}.json"
  files="$REVIEW_PARENT/${architecture}/all-layer-files-${architecture}.json"

  jq -e --ascii-output --sort-keys --arg platform "$platform" \
    '.platforms[$platform]' "$POLICY" \
    > "$DIFF_ROOT/${architecture}-expected-components.json"
  jq -e --ascii-output --sort-keys '.components' "$inventory" \
    > "$DIFF_ROOT/${architecture}-observed-components.json"
  diff --unified "$DIFF_ROOT/${architecture}-expected-components.json" \
    "$DIFF_ROOT/${architecture}-observed-components.json"

  jq -e --ascii-output --sort-keys '
      [.components[] | select(.ecosystem == "runtime" and .name == "cpython")]
      | if length == 1 then .[0] else error("expected one CPython runtime") end
    ' "$inventory" > "$DIFF_ROOT/${architecture}-cpython-runtime.json"
  LC_ALL=C sed -n 'l' "$DIFF_ROOT/${architecture}-cpython-runtime.json"

  for category in embedded_sboms native_payloads wheel_identity_files; do
    jq -e --ascii-output --sort-keys \
      --arg platform "$platform" --arg category "$category" \
      '.unexpanded_python_payloads[$platform][$category]' "$POLICY" \
      > "$DIFF_ROOT/${architecture}-expected-${category}.json"
    jq -e --ascii-output --sort-keys --arg category "$category" '
        if $category == "wheel_identity_files"
        then .[$category]
        else [.[$category][] | {
          effective, layer, path, sha256, size, mode, uid, gid
        }]
        end
      ' "$inventory" \
      > "$DIFF_ROOT/${architecture}-observed-${category}.json"
    diff --unified "$DIFF_ROOT/${architecture}-expected-${category}.json" \
      "$DIFF_ROOT/${architecture}-observed-${category}.json"
  done

  jq -e --ascii-output --sort-keys '
      {
        embedded_sboms: [
          .embedded_sboms[] | {owner, path, cyclonedx}
        ],
        native_payloads: [
          .native_payloads[] | {owner, path, elf}
        ]
      }
    ' "$inventory" > "$DIFF_ROOT/${architecture}-structured-wheel-payloads.json"
  LC_ALL=C sed -n 'l' \
    "$DIFF_ROOT/${architecture}-structured-wheel-payloads.json"

  "$TRUSTED_ROOT/.venv/bin/python" \
    "$TRUSTED_ROOT/.github/scripts/container_evidence.py" \
    native-component-coverage-view \
    --inventory "$inventory" \
    --policy "$POLICY" \
    --output "$DIFF_ROOT/${architecture}-native-component-coverage.json"
  jq -e --arg platform "$platform" '
      .schema_version == 5
      and .platform == $platform
      and .complete == false
      and ([.resolved_owners[].owner] == ["python:greenlet@3.5.3"])
      and (.unresolved_owners | length == 6)
    ' "$DIFF_ROOT/${architecture}-native-component-coverage.json" >/dev/null
  LC_ALL=C sed -n 'l' \
    "$DIFF_ROOT/${architecture}-native-component-coverage.json"

  jq -e --ascii-output --sort-keys --arg platform "$platform" \
    '.filesystem_baselines[$platform].apk_database_occurrences' "$POLICY" \
    > "$DIFF_ROOT/${architecture}-expected-apk-databases.json"
  jq -e --ascii-output --sort-keys '.apk_database_occurrences' "$inventory" \
    > "$DIFF_ROOT/${architecture}-observed-apk-databases.json"
  diff --unified "$DIFF_ROOT/${architecture}-expected-apk-databases.json" \
    "$DIFF_ROOT/${architecture}-observed-apk-databases.json"

  base_count="$(jq -er --arg platform "$platform" \
    '.base_image_platforms[$platform].layer_diff_ids | length' "$POLICY")"
  jq -e --ascii-output --sort-keys --arg platform "$platform" \
    '.base_image_platforms[$platform].layer_diff_ids' "$POLICY" \
    > "$DIFF_ROOT/${architecture}-expected-base-layers.json"
  jq -e --ascii-output --sort-keys --argjson count "$base_count" \
    '[.layers[].digest][0:$count]' "$files" \
    > "$DIFF_ROOT/${architecture}-observed-base-layers.json"
  diff --unified "$DIFF_ROOT/${architecture}-expected-base-layers.json" \
    "$DIFF_ROOT/${architecture}-observed-base-layers.json"

  "$TRUSTED_ROOT/.venv/bin/python" \
    "$TRUSTED_ROOT/.github/scripts/container_evidence.py" filesystem-policy-view \
    --files-inventory "$files" \
    --policy "$POLICY" \
    --output "$DIFF_ROOT/${architecture}-observed-filesystem-policy.json"
  jq -e --ascii-output --sort-keys --arg platform "$platform" '
      {
        platform: $platform,
        post_base_directory_effects:
          .filesystem_baselines[$platform].post_base_directory_effects,
        post_base_removals:
          .filesystem_baselines[$platform].post_base_removals
      }
    ' "$POLICY" > "$DIFF_ROOT/${architecture}-expected-filesystem-policy.json"
  diff --unified "$DIFF_ROOT/${architecture}-expected-filesystem-policy.json" \
    "$DIFF_ROOT/${architecture}-observed-filesystem-policy.json"
done
```

No diff output means the exact ordered base diff IDs, top-level components,
raw wheel surfaces, APK database history, and canonical post-base directory
effects and removals match reviewed policy. Review the printed structured wheel
payloads, coverage ledger, and CPython runtime record as well. The CPython
record must bind the expected version header, interpreter link, interpreter,
and shared library from one reviewed base layer. Each embedded SBOM and native
payload must name the expected wheel owner, and its CycloneDX or ELF identity
must agree with the upstream component and selected architecture.

The filesystem projection validates all raw headers but omits only
exporter-specific directory re-emissions and whiteout marker attributes that do
not change filesystem state. Raw records and layer digests remain in
`all-layer-files.json` for review. No diff does not mean the policy is correct.
The manual diff does not independently re-run the post-base regular-file or
link provenance gates, application source binding, or exact source-policy
coverage; those still depend on the independently reviewed CI collector,
workflow, and exact successful job. For every change, establish the upstream
identity, why the bytes are distributed, their effective or lower-layer
status, applicable notices, and corresponding source.

Review source policy with these precise boundaries:

- `uv.lock` supplies immutable top-level Python source URLs, sizes, and hashes;
  wheel-only or lower-layer packages need exact fallback records; pull-request
  CI, manual runs, and tagged candidate scans use the same isolated-build proof,
  while issue #32 remains open for retained release evidence and future
  publication consumers
- Alpine policy pins every `ORIGIN@APORTS_COMMIT`, recipe-subtree hash, verified
  `sha512sums` input, and any narrow parser exception; never execute an
  `APKBUILD`
- native-component coverage must reproduce the resolved owner's complete
  native path-and-digest set, use the role derived from each path, and keep the
  same derived role set across platforms. A role cannot be moved between
  payload records. Coverage must also reproduce every embedded-SBOM component
  and bind the wheel and owner sdist to `uv.lock`. Component records must not
  contain payload fields: the SBOM provides no file, hash, or SONAME
  relationship. One package URL cannot acquire a different identity, source,
  or reviewed license in another owner or SBOM. The Greenlet record separately
  pins the Alpine 3.22 GCC recipe, distfile, and source-carried notices reviewed
  for the SBOM's `libgcc` and `libstdc++` identities
- Docker Official Python policy pins the multi-platform index, exact ordered
  base diff IDs, recipe, recipe license, CPython source archive, and exact
  source-carried `LICENSE` and `Include/patchlevel.h`; the source version and
  hash must match the recipe, and the source patchlevel digest must match both
  platform image headers; the policy does not contain unused platform manifest
  or configuration digest fields
- application evidence is built from every tracked regular Git blob and its
  executable mode at `HEAD`, using recursive `git ls-tree -rz` and `git show`;
  it is not a mutable working-tree copy and is not described as `git archive`
- every top-level `LicenseRef-*` must name exactly the covered components and
  pin the source-carried notice path and digest for each one; schema 5 rejects
  `LicenseRef-*` in nested native-component expressions.

The nested evidence tar is checksum-bound by the predicate and sidecar, but the
current repository does not ship the bounded verifier required to inspect that
tar as a recipient. Do not extract it to compensate. Review the policy, raw
inventories, collector change, and workflow logs; keep release publication
blocked until issue #28 supplies the tested tar verifier and runnable recipient
procedure.

## 5. Confirm the remaining source-completeness gap stays explicit

Both component inventories must contain exactly:

```json
{
  "complete": false,
  "reason": "Six native-wheel owners still lack closed-world component/source coverage in issue #18; public distribution remains blocked pending issue #28."
}
```

Do not weaken or remove that state. The coverage ledger must resolve Greenlet
on both platforms, list the other six owners as unresolved, and remain
`complete: false`. Issue #18 must close those remaining records with the same
payload, component, notice, and corresponding-source evidence.

CPython is no longer part of the incomplete status. The trusted helper requires
one effective top-level CPython component per platform, binds its four runtime
identities to the all-layer inventory and reviewed base boundary, and verifies
the pinned recipe, source archive, source-carried version header, and license
evidence. That closes the CPython tranche without making the entire image
source-complete.

Greenlet is also no longer part of the incomplete status. Its resolved ledger
record binds the exact platform wheel and owner sdist, records all five native
payloads as one owner-level set, reproduces both nested SBOM component
identities, and pins the GCC recipe, source archive, and reviewed notices. This
proves exact co-membership in the wheel, not a component-to-file mapping. Treat
a missing Greenlet record or any additional resolved owner as policy drift that
requires a separate review.

The trusted helper has already validated `wheel_installations` against
the all-layer file inventory. It requires every historical installation to bind
its canonical owner, METADATA, WHEEL, RECORD, tags, purelib state, and normalized
owned occurrences. It also preserves the effective-only
`python_record_ownership` projection. Do not treat that attribution evidence as
component expansion or corresponding-source delivery.

Raw path/hash baselines make every surface visible. The separate coverage
ledger says which owners have corresponding-source closure; a raw baseline by
itself does not satisfy source delivery. `wheel_identity_files` also retains
base-image WHEEL and RECORD occurrences outside `/opt/venv`; those records have
no runtime virtual-environment installation to replay.

## 6. Run the repository gates

Run pull-request code in a second disposable no-secret build/test VM. Do not
mount the evidence artifacts or GitHub token there. This VM may use restricted
outbound access to fetch locked tools, dependencies, and public base images and
may have an isolated Docker daemon; the artifact-parsing VM remains offline and
has no Docker socket. Start from a separate exact synthetic-merge checkout and
require it to be clean, including untracked files:

```bash
export TEST_SOURCE='/path/to/disposable-clean-merge-checkout'
export GIT_NO_REPLACE_OBJECTS=1
test "$(git -C "$TEST_SOURCE" rev-parse HEAD)" = "$MERGE_SHA"
test -z "$(git -C "$TEST_SOURCE" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=all)"
cd "$TEST_SOURCE"
mise trust
mise install
mise run bootstrap
mise run check
mise exec -- uv run --frozen pytest --no-cov tests/test_container_evidence.py
mise exec -- uv run --frozen mkdocs build --strict
```

The staging procedure already required both exact container matrix jobs in
`jobs.json` to finish successfully for this run attempt. A canceled or
partially uploaded job is not review evidence, even if its diagnostic artifact
can be parsed.

## 7. Revalidate the pull request before deciding

The pull request can move while the offline review runs. On a new credentialed
staging host, inject another short-lived read-only token and query the pull
request again immediately before recording a review decision or merging. Do
not run pull-request code on this host. Populate every expected value from the
verified identity packet, not from the new response:

```bash
set -euo pipefail
umask 077

export REPOSITORY='stampbot/extra-codeowners'
export PR_NUMBER='REPLACE_WITH_REVIEWED_PR_NUMBER'
export EXPECTED_PR_HEAD_SHA='REPLACE_WITH_REVIEWED_40_CHARACTER_HEAD'
export EXPECTED_PR_BASE_SHA='REPLACE_WITH_REVIEWED_40_CHARACTER_BASE'
export EXPECTED_REPOSITORY_ID='REPLACE_WITH_REVIEWED_REPOSITORY_ID'
export EXPECTED_HEAD_REPOSITORY_ID='REPLACE_WITH_REVIEWED_HEAD_REPOSITORY_ID'

case "$PR_NUMBER" in (*[!0-9]*|'') exit 1 ;; esac
case "$EXPECTED_PR_HEAD_SHA" in (*[!0-9a-f]*|'') exit 1 ;; esac
case "$EXPECTED_PR_BASE_SHA" in (*[!0-9a-f]*|'') exit 1 ;; esac
test "${#EXPECTED_PR_HEAD_SHA}" -eq 40
test "${#EXPECTED_PR_BASE_SHA}" -eq 40
case "$EXPECTED_REPOSITORY_ID" in (*[!0-9]*|'') exit 1 ;; esac
case "$EXPECTED_HEAD_REPOSITORY_ID" in (*[!0-9]*|'') exit 1 ;; esac
: "${GH_TOKEN:?inject a fresh short-lived read-only token}"

FINAL_ROOT="$(mktemp -d)"
chmod 0700 "$FINAL_ROOT"
gh api "/repos/${REPOSITORY}/pulls/${PR_NUMBER}" > "$FINAL_ROOT/pr-final.json"
jq -e \
  --argjson number "$PR_NUMBER" \
  --arg head "$EXPECTED_PR_HEAD_SHA" \
  --arg base "$EXPECTED_PR_BASE_SHA" \
  --argjson repository "$EXPECTED_REPOSITORY_ID" \
  --argjson head_repository "$EXPECTED_HEAD_REPOSITORY_ID" '
    .number == $number
    and .state == "open"
    and .head.sha == $head
    and .base.sha == $base
    and .head.repo.id == $head_repository
    and .base.repo.id == $repository
  ' "$FINAL_ROOT/pr-final.json" >/dev/null
sha256sum "$FINAL_ROOT/pr-final.json"
unset GH_TOKEN
```

Record the query time and final response digest with the review. If validation
fails, discard the decision and review a successful run for the new head and
base. Destroy the staging host after revoking the token. Keep strict
up-to-date required checks enabled. If an accepted review is merged with the
GitHub CLI, bind that operation to the same head with
`--match-head-commit "$EXPECTED_PR_HEAD_SHA"`; do not merge after another push.

## 8. Keep distribution denied

Keep `distribution_approval.approved` set to `false`. The current executable
schema requires source completeness to remain false and rejects an attempt to
require distribution approval. The tag workflow independently stops before
privileged jobs, there is no `main` publication job to enable, and issue #32's
release-evidence and publication handoff remains a separate requirement.

A future supported release must satisfy the
[container evidence release contract](../reference/container-evidence-release-contract.md),
including both platform manifest subjects, signed predicates and attestations,
complete sources, the bounded recipient verifier, and isolated short-lived
publication authority. Qualified legal review for a paid hosted distribution
is a separate launch decision; collector success does not provide it.

Destroy the no-secret VM and review inputs after retaining only the approved
audit record your project requires. The evidence can contain private
repository, path, component, and workflow metadata.
