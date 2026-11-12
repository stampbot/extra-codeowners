"""Fingerprint the base-side inputs that can change ownership requirements."""

from __future__ import annotations

import hashlib
import json

from extra_codeowners.codeowners import parse_codeowners
from extra_codeowners.models import ChangedFile, RepositoryPolicy


def base_evidence_fingerprint(
    *,
    head_sha: str,
    base_ref: str,
    repository_policy: RepositoryPolicy,
    codeowners_text: str,
    changed_files: tuple[ChangedFile, ...],
    labels: frozenset[str],
    author_identity: tuple[int, str] | None,
    allow_insecure_changes: bool,
    policy_path: str,
) -> str:
    """Compare authorization inputs, not commits, formatting or diff hunks.

    A digest is useful only with the confirmed successful audit that produced
    it and fresh GitHub observations. It is not approval evidence by itself.
    """
    document = parse_codeowners(codeowners_text)
    paths = sorted(
        {path for file in changed_files for path in (file.path, file.previous_path) if path}
    )
    if len(paths) * len(document.rules) > 2_000_000:
        raise ValueError("base evidence exceeds the bounded ownership matching budget")
    evidence = {
        "schema_version": 1,
        "head_sha": head_sha,
        "base_ref": base_ref,
        "repository_policy": repository_policy.model_dump(mode="json"),
        "changed_files": sorted(
            (file.path, file.status.value, file.previous_path or "") for file in changed_files
        ),
        "owners": [(path, sorted(document.owners_for(path))) for path in paths],
        "labels": sorted(labels),
        "author_identity": author_identity,
        "allow_insecure_changes": allow_insecure_changes,
        "policy_path": policy_path,
    }
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
