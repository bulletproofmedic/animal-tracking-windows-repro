from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

MANIFEST_PATH = "IMPLEMENTATION_SOURCE_MANIFEST.json"
CONTROLLED_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)


def category(path: str) -> str:
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
    if path.startswith(("docs/remediation/", "docs/audits/")):
        return "EVIDENCE"
    if "/fixtures/" in path or path.startswith("fixtures/"):
        return "FIXTURE"
    if path.startswith(("proofs/", "ios/")):
        return "BOUNDED_PROOF"
    if path.startswith("docs/"):
        return "DOCUMENTATION"
    return "CONFIGURATION"


@dataclass(frozen=True)
class Facts:
    base_commit: str
    source_commit: str
    source_tree: str
    source_paths: tuple[str, ...]
    base_is_ancestor: bool
    control_commit: str
    control_tree: str
    control_parent: str
    control_changed_paths: tuple[str, ...]
    head_commit: str
    head_tree: str
    head_parent: str
    head_changed_paths: tuple[str, ...]
    manifest_bytes_match: bool
    checkout_commit: str
    checkout_parents: tuple[str, ...]


def flatten_inventory(groups: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    paths: list[str] = []
    errors: list[str] = []
    group_order: list[str] = []
    for index, group in enumerate(groups):
        if not isinstance(group, dict) or set(group) != {"directory", "entries"}:
            errors.append(f"group {index} schema")
            continue
        directory = group["directory"]
        entries = group["entries"]
        group_order.append(directory)
        if entries != sorted(entries):
            errors.append(f"entries ordering {directory}")
        for name in entries:
            paths.append(f"{directory}/{name}" if directory else name)
    if group_order != sorted(group_order):
        errors.append("group ordering")
    if len(paths) != len(set(paths)):
        errors.append("duplicate path")
    return paths, errors


def validate(manifest: dict[str, Any], facts: Facts, context: str) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != 6:
        errors.append("schema")
    if manifest.get("state") != "R1_SECURITY_COMBINED_FINAL_TARGET_MANIFEST_CONTROL":
        errors.append("state")
    if manifest.get("source_commit") != facts.source_commit:
        errors.append("source")
    if manifest.get("source_git_tree") != facts.source_tree:
        errors.append("source tree")
    if manifest.get("source_base_commit") != facts.base_commit or not facts.base_is_ancestor:
        errors.append("base")
    if manifest.get("control_commit") != facts.control_commit:
        errors.append("control")
    if manifest.get("control_git_tree") != facts.control_tree:
        errors.append("control tree")
    if tuple(manifest.get("controlled_paths", ())) != tuple(sorted(CONTROLLED_PATHS)):
        errors.append("controlled paths")
    if facts.control_parent != facts.source_commit:
        errors.append("control parent")
    if facts.control_changed_paths != tuple(sorted(CONTROLLED_PATHS)):
        errors.append("control changed paths")

    paths, inventory_errors = flatten_inventory(manifest.get("path_inventory", []))
    errors.extend(inventory_errors)
    expected = set(facts.source_paths)
    listed = set(paths)
    if expected - listed:
        errors.append("missing")
    if listed - expected:
        errors.append("extra")
    counts = dict(sorted(Counter(category(path) for path in paths).items()))
    if manifest.get("summary") != {
        "total_file_count": len(expected),
        "count_by_category": counts,
        "excluded_entry_count": 1,
    }:
        errors.append("summary")

    if facts.head_parent != facts.control_commit:
        errors.append("head parent")
    if facts.head_changed_paths != (MANIFEST_PATH,):
        errors.append("head changed paths")
    if not facts.manifest_bytes_match:
        errors.append("manifest bytes")

    if context == "exact-head":
        if facts.checkout_commit != facts.head_commit:
            errors.append("exact head")
    elif context == "merge-ref":
        if facts.checkout_commit == facts.head_commit:
            errors.append("merge distinct")
        if len(facts.checkout_parents) < 2:
            errors.append("merge parents")
        if facts.head_commit not in facts.checkout_parents:
            errors.append("merge direct parent")
    else:
        errors.append("context")
    return errors
