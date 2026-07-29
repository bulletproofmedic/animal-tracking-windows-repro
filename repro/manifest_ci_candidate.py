from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

MANIFEST_PATH = "IMPLEMENTATION_SOURCE_MANIFEST.json"
REPOSITORY = "synthetic/manifest-repository"
GENERATOR_VERSION = "2.1.0-diagnostic"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(RuntimeError):
    pass


class DuplicateKeyError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def git_text(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=root, text=True, encoding="utf-8"
    ).strip()


def git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root)


def resolve_commit(root: Path, ref: str) -> str:
    return git_text(root, "rev-parse", "--verify", f"{ref}^{{commit}}")


def resolve_tree(root: Path, commit: str) -> str:
    return git_text(root, "rev-parse", "--verify", f"{commit}^{{tree}}")


def ensure_ancestor(root: Path, base_commit: str, source_commit: str) -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base_commit, source_commit],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        raise ValidationError(
            f"Base commit {base_commit} is not an ancestor of source {source_commit}."
        )


def category_for(path: str) -> str:
    if path.startswith(".github/workflows/"):
        return "CI_WORKFLOW"
    if "/migrations/" in path or path.startswith("migrations/"):
        return "MIGRATION"
    if path.startswith("src/"):
        return "APPLICATION_SOURCE"
    if path.startswith("tests/"):
        return "TEST"
    if path.startswith("requirements/") or path.endswith((".lock", "lock.json")):
        return "DEPENDENCY_LOCK"
    if path.startswith("scripts/"):
        return "VALIDATION_SCRIPT"
    if path.startswith("docs/governance/"):
        return "GOVERNANCE"
    if path.startswith("docs/remediation/") or path.startswith("docs/audits/"):
        return "EVIDENCE"
    if "/fixtures/" in path or path.startswith("fixtures/"):
        return "FIXTURE"
    if path.startswith(("proofs/", "ios/")):
        return "BOUNDED_PROOF"
    if path.startswith("docs/"):
        return "DOCUMENTATION"
    return "CONFIGURATION"


def tracked_entries(root: Path, source_commit: str) -> list[dict[str, Any]]:
    output = git_bytes(root, "ls-tree", "-r", "-z", "--full-tree", source_commit)
    entries: list[dict[str, Any]] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, blob_sha = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="strict")
        if object_type != "blob":
            raise ValidationError(f"Unsupported tracked object {object_type} at {path}.")
        if path == MANIFEST_PATH:
            continue
        content = git_bytes(root, "cat-file", "blob", blob_sha)
        entries.append(
            {
                "path": path,
                "category": category_for(path),
                "git_mode": mode,
                "git_blob_sha": blob_sha,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        )
    entries.sort(key=lambda item: item["path"])
    paths = [item["path"] for item in entries]
    if len(paths) != len(set(paths)):
        raise ValidationError("The source tree contains duplicate decoded paths.")
    return entries


def build_payload(
    root: Path, source_ref: str, base_ref: str, state: str
) -> dict[str, Any]:
    source_commit = resolve_commit(root, source_ref)
    base_commit = resolve_commit(root, base_ref)
    ensure_ancestor(root, base_commit, source_commit)
    source_tree = resolve_tree(root, source_commit)
    files = tracked_entries(root, source_commit)
    category_counts = Counter(item["category"] for item in files)
    category_sizes: Counter[str] = Counter()
    for item in files:
        category_sizes[item["category"]] += item["size_bytes"]
    return {
        "schema_version": 4,
        "manifest_format": "ANIMAL_TRACKING_IMPLEMENTATION_SOURCE_MANIFEST",
        "state": state,
        "repository": REPOSITORY,
        "source_commit": source_commit,
        "source_git_tree": source_tree,
        "source_base_commit": base_commit,
        "authorized_scope": "Release 1 only",
        "authority_state": {
            "release_1_implementation_authorized": True,
            "implementation_accepted": False,
            "owner_operational_use_authorized": False,
            "release_readiness_established": False,
            "production_release_authorized": False,
            "release_1_1_and_later_implementation_authorized": False,
        },
        "generation": {
            "generator_path": "scripts/generate_source_manifest.py",
            "generator_version": GENERATOR_VERSION,
            "source_mode": "IMMUTABLE_GIT_OBJECT_DATABASE",
            "file_population": "ALL_TRACKED_BLOBS_AT_SOURCE_COMMIT_EXCLUDING_MANIFEST_SELF",
            "ordering": "repository-relative UTF-8 path ascending",
            "hash_algorithm": "SHA-256",
            "size_definition": "exact Git blob byte length",
        },
        "excluded_entries": [
            {
                "path": MANIFEST_PATH,
                "reason": "Self-referential generated output; manifest commit identity is recorded externally.",
            }
        ],
        "files": files,
        "summary": {
            "total_file_count": len(files),
            "total_size_bytes": sum(item["size_bytes"] for item in files),
            "count_by_category": dict(sorted(category_counts.items())),
            "size_by_category": dict(sorted(category_sizes.items())),
            "excluded_entry_count": 1,
        },
        "verification": {
            "duplicate_path_count": 0,
            "missing_tracked_file_count": 0,
            "extra_manifest_entry_count": 0,
            "hash_mismatch_count": 0,
            "size_mismatch_count": 0,
            "git_blob_mismatch_count": 0,
            "source_tree_mismatch_count": 0,
            "stale_source_identity_count": 0,
        },
    }


def write_manifest(
    root: Path, source_ref: str, base_ref: str, state: str
) -> dict[str, Any]:
    payload = build_payload(root, source_ref, base_ref, state)
    (root / MANIFEST_PATH).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return payload


def source_population(root: Path, commit: str) -> dict[str, dict[str, Any]]:
    return {entry["path"]: {key: value for key, value in entry.items() if key != "path"} for entry in tracked_entries(root, commit)}


def validate_checkout_context(
    root: Path, context: str, expected_head_ref: str, errors: list[str]
) -> dict[str, Any]:
    checkout_commit = resolve_commit(root, "HEAD")
    checkout_tree = resolve_tree(root, checkout_commit)
    expected_head = resolve_commit(root, expected_head_ref)
    expected_tree = resolve_tree(root, expected_head)
    parents = git_text(root, "rev-list", "--parents", "-n", "1", checkout_commit).split()[1:]
    result = {
        "validation_context": context,
        "checkout_commit": checkout_commit,
        "checkout_tree": checkout_tree,
        "expected_head": expected_head,
        "expected_head_tree": expected_tree,
        "tree_equivalent_to_expected_head": checkout_tree == expected_tree,
        "distinct_from_expected_head": checkout_commit != expected_head,
        "parent_count": len(parents),
        "expected_head_is_direct_parent": expected_head in parents,
    }
    if context == "exact-head":
        if checkout_commit != expected_head:
            errors.append(
                f"Exact-head validation checked out {checkout_commit}, expected {expected_head}."
            )
    elif context == "merge-ref":
        if checkout_commit == expected_head:
            errors.append("Merge-ref validation must not run on the exact head commit.")
        if len(parents) < 2:
            errors.append("Merge-ref validation requires a commit with at least two parents.")
        if expected_head not in parents:
            errors.append(
                f"Merge-ref checkout {checkout_commit} does not have expected head {expected_head} as a direct parent."
            )
    else:
        errors.append(f"Unsupported checkout context: {context}")
    return result


def validate_manifest(
    root: Path,
    manifest_path: Path,
    expected_source_ref: str,
    expected_base_ref: str,
    expected_state: str,
    checkout_context: str,
    expected_head_ref: str,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except Exception as error:
        raise ValidationError(f"Manifest parse failed: {error}") from error
    if not isinstance(manifest, dict):
        raise ValidationError("Manifest root must be an object.")

    required = {
        "schema_version",
        "manifest_format",
        "state",
        "repository",
        "source_commit",
        "source_git_tree",
        "source_base_commit",
        "authorized_scope",
        "authority_state",
        "generation",
        "excluded_entries",
        "files",
        "summary",
        "verification",
    }
    missing_fields = sorted(required - set(manifest))
    extra_fields = sorted(set(manifest) - required)
    if missing_fields:
        errors.append(f"Missing top-level fields: {missing_fields}")
    if extra_fields:
        errors.append(f"Unexpected top-level fields: {extra_fields}")
    if manifest.get("schema_version") != 4:
        errors.append("schema_version must be 4.")
    if manifest.get("manifest_format") != "ANIMAL_TRACKING_IMPLEMENTATION_SOURCE_MANIFEST":
        errors.append("manifest_format is invalid.")
    if manifest.get("repository") != REPOSITORY:
        errors.append(f"repository must be {REPOSITORY}.")
    if manifest.get("state") != expected_state:
        errors.append(f"state is stale or incorrect: {manifest.get('state')!r}.")
    if manifest.get("authorized_scope") != "Release 1 only":
        errors.append("authorized_scope is stale or incorrect.")

    expected_source = resolve_commit(root, expected_source_ref)
    expected_base = resolve_commit(root, expected_base_ref)
    ensure_ancestor(root, expected_base, expected_source)
    actual_tree = resolve_tree(root, expected_source)
    if manifest.get("source_commit") != expected_source:
        errors.append("source_commit is stale or incorrect.")
    if manifest.get("source_base_commit") != expected_base:
        errors.append("source_base_commit is stale or incorrect.")
    if manifest.get("source_git_tree") != actual_tree:
        errors.append("source_git_tree is stale or incorrect.")

    expected = source_population(root, expected_source)
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        errors.append("files must be a list.")
        raw_files = []
    listed: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    fields = {"path", "category", "git_mode", "git_blob_sha", "sha256", "size_bytes"}
    for index, entry in enumerate(raw_files):
        if not isinstance(entry, dict):
            errors.append(f"File entry {index} is not an object.")
            continue
        if set(entry) != fields:
            errors.append(f"File entry {index} has an invalid schema.")
        path = entry.get("path")
        if not isinstance(path, str):
            errors.append(f"File entry {index} path is not text.")
            continue
        if path in listed:
            errors.append(f"Duplicate manifest path: {path}")
            continue
        if path == MANIFEST_PATH:
            errors.append("Manifest must not list itself.")
        listed[path] = entry
        order.append(path)
    if order != sorted(order):
        errors.append("Manifest file entries are not in ascending path order.")

    missing_paths = sorted(set(expected) - set(listed))
    extra_paths = sorted(set(listed) - set(expected))
    if missing_paths:
        errors.append(f"Missing tracked manifest entries: {missing_paths}")
    if extra_paths:
        errors.append(f"Extra or stale manifest entries: {extra_paths}")
    mismatch_fields = ("category", "git_mode", "git_blob_sha", "sha256", "size_bytes")
    mismatch_counts = {field: 0 for field in mismatch_fields}
    for path in sorted(set(expected) & set(listed)):
        for field in mismatch_fields:
            if listed[path].get(field) != expected[path][field]:
                mismatch_counts[field] += 1
                errors.append(f"{field} mismatch for {path}.")
        if not isinstance(listed[path].get("git_blob_sha"), str) or not HEX40.fullmatch(str(listed[path].get("git_blob_sha"))):
            errors.append(f"Invalid Git blob syntax for {path}.")
        if not isinstance(listed[path].get("sha256"), str) or not HEX64.fullmatch(str(listed[path].get("sha256"))):
            errors.append(f"Invalid SHA-256 syntax for {path}.")

    category_counts = Counter(entry.get("category") for entry in listed.values())
    category_sizes: Counter[str] = Counter()
    for entry in listed.values():
        if isinstance(entry.get("category"), str) and isinstance(entry.get("size_bytes"), int):
            category_sizes[str(entry["category"])] += int(entry["size_bytes"])
    summary = manifest.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object.")
        summary = {}
    if summary.get("total_file_count") != len(expected):
        errors.append("summary.total_file_count is stale or incorrect.")
    if summary.get("total_size_bytes") != sum(item["size_bytes"] for item in expected.values()):
        errors.append("summary.total_size_bytes is stale or incorrect.")
    if summary.get("count_by_category") != dict(sorted(category_counts.items())):
        errors.append("summary.count_by_category is stale or incorrect.")
    if summary.get("size_by_category") != dict(sorted(category_sizes.items())):
        errors.append("summary.size_by_category is stale or incorrect.")
    if summary.get("excluded_entry_count") != 1:
        errors.append("summary.excluded_entry_count must be 1.")

    exclusions = manifest.get("excluded_entries")
    if not isinstance(exclusions, list) or len(exclusions) != 1 or not isinstance(exclusions[0], dict) or exclusions[0].get("path") != MANIFEST_PATH:
        errors.append("Exactly one controlled manifest self-exclusion is required.")
    verification = manifest.get("verification")
    zero_fields = {
        "duplicate_path_count",
        "missing_tracked_file_count",
        "extra_manifest_entry_count",
        "hash_mismatch_count",
        "size_mismatch_count",
        "git_blob_mismatch_count",
        "source_tree_mismatch_count",
        "stale_source_identity_count",
    }
    if not isinstance(verification, dict) or set(verification) != zero_fields or any(verification.get(field) != 0 for field in zero_fields):
        errors.append("verification must contain the exact zero-valued control counters.")

    checkout = validate_checkout_context(root, checkout_context, expected_head_ref, errors)
    result = {
        "result": "PASS" if not errors else "FAIL",
        "source_commit": expected_source,
        "source_git_tree": actual_tree,
        "source_base_commit": expected_base,
        "missing_entry_count": len(missing_paths),
        "extra_entry_count": len(extra_paths),
        "mismatch_counts": mismatch_counts,
        "checkout_identity": checkout,
        "errors": errors,
    }
    if errors:
        raise ValidationError(json.dumps(result, sort_keys=True))
    return result
