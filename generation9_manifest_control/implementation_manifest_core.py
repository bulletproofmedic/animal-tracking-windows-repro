from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = "IMPLEMENTATION_SOURCE_MANIFEST.json"
REPOSITORY = "bulletproofmedic/animal-tracking"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
CONTROLLED_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)
CONTROL_GENERATION = 9
TARGET_MODES = ("manifest-head", "retained-head", "post-merge-main")
MAIN_MERGE_METHODS = ("merge", "squash")
UNSUPPORTED_LINEAR_METHOD = "unsupported-linear-history"


class DuplicateKeyError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def git_text(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
    ).strip()


def git_bytes(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def commit(ref: str) -> str:
    return git_text("rev-parse", "--verify", f"{ref}^{{commit}}")


def tree(ref: str) -> str:
    return git_text("rev-parse", "--verify", f"{ref}^{{tree}}")


def parents(ref: str) -> list[str]:
    return git_text("rev-list", "--parents", "-n", "1", ref).split()[1:]


def changed_paths(base: str, head: str) -> list[str]:
    return sorted(
        filter(
            None,
            git_text(
                "diff",
                "--name-only",
                "--no-renames",
                base,
                head,
            ).splitlines(),
        )
    )


def is_ancestor(ancestor: str, descendant: str) -> bool:
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def merge_base(left: str, right: str) -> str:
    return git_text("merge-base", left, right)


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


def blob_inventory(ref: str) -> dict[str, tuple[str, str]]:
    raw = git_bytes("ls-tree", "-r", "-z", "--full-tree", ref)
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="strict")
        if kind != "blob":
            raise RuntimeError(f"Unsupported tracked object {kind} at {path}.")
        result[path] = (mode, oid)
    return result


def population(source: str) -> dict[str, str]:
    return {
        path: category(path)
        for path in blob_inventory(source)
        if path != MANIFEST_PATH
    }


def manifest_blob_oid(manifest_path: Path) -> str:
    return (
        subprocess.run(
            ["git", "hash-object", "--stdin"],
            cwd=ROOT,
            input=manifest_path.read_bytes(),
            check=True,
            capture_output=True,
        )
        .stdout.decode("ascii")
        .strip()
    )


def expected_integrated_inventory(
    source: str,
    control: str,
    manifest_path: Path,
) -> dict[str, tuple[str, str]]:
    expected = blob_inventory(source)
    controlled = blob_inventory(control)
    for path in CONTROLLED_PATHS:
        expected[path] = controlled[path]
    expected[MANIFEST_PATH] = ("100644", manifest_blob_oid(manifest_path))
    return expected


def expected_post_merge_inventory(
    previous_main: str,
    source: str,
    control: str,
    manifest_path: Path,
) -> tuple[dict[str, tuple[str, str]], str, list[str], list[str]]:
    integrated = expected_integrated_inventory(source, control, manifest_path)
    base = merge_base(previous_main, source)
    base_inventory = blob_inventory(base)
    previous_inventory = blob_inventory(previous_main)
    approved_paths = sorted(
        path
        for path in set(base_inventory) | set(integrated)
        if base_inventory.get(path) != integrated.get(path)
    )
    expected = dict(previous_inventory)
    for path in approved_paths:
        if path in integrated:
            expected[path] = integrated[path]
        else:
            expected.pop(path, None)
    expected_changed = sorted(
        path
        for path in set(previous_inventory) | set(expected)
        if previous_inventory.get(path) != expected.get(path)
    )
    return expected, base, approved_paths, expected_changed


def manifest_head_result(
    source: str,
    control: str,
    head: str,
    manifest_path: Path,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    if parents(control) != [source]:
        errors.append("control_commit must have source_commit as its sole parent.")
    observed_control = changed_paths(source, control)
    if observed_control != sorted(CONTROLLED_PATHS):
        errors.append(
            f"control_commit changed {observed_control}; "
            f"expected {sorted(CONTROLLED_PATHS)}."
        )
    if parents(head) != [control]:
        errors.append("manifest_head must have control_commit as its sole parent.")
    observed_manifest = changed_paths(control, head)
    if observed_manifest != [MANIFEST_PATH]:
        errors.append(
            f"manifest_head must change only {MANIFEST_PATH}; "
            f"observed {observed_manifest}."
        )
    try:
        manifest_matches = (
            git_bytes("show", f"{head}:{MANIFEST_PATH}")
            == manifest_path.read_bytes()
        )
    except subprocess.CalledProcessError:
        manifest_matches = False
    if not manifest_matches:
        errors.append("Validated manifest bytes differ from manifest-head bytes.")
    return errors, {
        "manifest_head": head,
        "manifest_head_tree": tree(head),
        "control_changed_paths": observed_control,
        "manifest_head_changed_paths": observed_manifest,
        "manifest_matches_manifest_head": manifest_matches,
    }


def validate_retained_head(
    source: str,
    control: str,
    retained: str,
    manifest_path: Path,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    retained_parents = parents(retained)
    manifest_head = retained_parents[1] if len(retained_parents) == 2 else control
    if retained_parents != [source, manifest_head]:
        errors.append(
            "retained_head parents must be exactly "
            "[source_commit, manifest_head]."
        )
    manifest_errors, result = manifest_head_result(
        source,
        control,
        manifest_head,
        manifest_path,
    )
    errors.extend(manifest_errors)
    delta = changed_paths(manifest_head, retained)
    tree_matches = tree(retained) == tree(manifest_head)
    manifest_matches = False
    try:
        manifest_matches = (
            git_bytes("show", f"{retained}:{MANIFEST_PATH}")
            == manifest_path.read_bytes()
        )
    except subprocess.CalledProcessError:
        pass
    if delta:
        errors.append(
            "retained_head must have zero delta from manifest_head; "
            f"observed {delta}."
        )
    if not tree_matches:
        errors.append("retained_head tree must equal manifest_head tree.")
    if not manifest_matches:
        errors.append("Validated manifest bytes differ from retained-head bytes.")
    result.update(
        {
            "retained_head": retained,
            "retained_head_parents": retained_parents,
            "retained_head_tree": tree(retained),
            "retained_head_changed_paths": delta,
            "retained_tree_matches_manifest_head": tree_matches,
            "manifest_matches_retained_head": manifest_matches,
        }
    )
    return errors, result


def validate_commit_chain(
    source: str,
    control: str,
    expected_head: str,
    manifest_path: Path,
    target_mode: str,
    errors: list[str],
) -> dict[str, Any]:
    if target_mode == "manifest-head":
        observed, result = manifest_head_result(
            source,
            control,
            expected_head,
            manifest_path,
        )
    elif target_mode == "retained-head":
        observed, result = validate_retained_head(
            source,
            control,
            expected_head,
            manifest_path,
        )
    else:
        errors.append(f"Unsupported pre-merge target mode: {target_mode}.")
        return {}
    errors.extend(observed)
    result.update(
        {
            "target_mode": target_mode,
            "expected_head": expected_head,
            "expected_head_tree": tree(expected_head),
        }
    )
    return result


def detect_merge_method(previous_main: str, head: str) -> tuple[str, list[str]]:
    head_parents = parents(head)
    commits = list(
        filter(
            None,
            git_text(
                "rev-list",
                "--first-parent",
                "--reverse",
                f"{previous_main}..{head}",
            ).splitlines(),
        )
    )
    if len(head_parents) == 2 and head_parents[0] == previous_main:
        return "merge", commits
    if len(commits) == 1 and head_parents == [previous_main]:
        return "squash", commits
    return UNSUPPORTED_LINEAR_METHOD, commits


def validate_post_merge_main(
    source: str,
    control: str,
    head: str,
    previous_main: str,
    manifest_path: Path,
    requested_method: str,
    errors: list[str],
) -> dict[str, Any]:
    expected, base, approved_paths, expected_changed = expected_post_merge_inventory(
        previous_main,
        source,
        control,
        manifest_path,
    )
    actual = blob_inventory(head)
    detected, commits = detect_merge_method(previous_main, head)
    method = detected if requested_method == "auto" else requested_method
    if detected not in MAIN_MERGE_METHODS:
        errors.append(
            "Post-merge history does not match an allowed merge or squash "
            "integration. Rebase and other multi-commit linear histories are "
            "prohibited."
        )
    if method not in MAIN_MERGE_METHODS:
        errors.append(f"Unsupported main merge method: {method}.")
    if requested_method != "auto" and method != detected:
        errors.append(
            f"Requested method {method} does not match detected method {detected}."
        )
    if not is_ancestor(previous_main, head):
        errors.append("previous_main is not an ancestor of post-merge head.")
    if not commits:
        errors.append("Post-merge first-parent range is empty.")
    valid_retained: list[str] = []
    if method == "merge":
        for candidate in parents(head)[1:]:
            candidate_errors, _ = validate_retained_head(
                source,
                control,
                candidate,
                manifest_path,
            )
            if not candidate_errors:
                valid_retained.append(candidate)
        if len(valid_retained) != 1 or parents(head) != [
            previous_main,
            *valid_retained,
        ]:
            errors.append(
                "merge integration must have exactly "
                "[previous_main, retained_target] parents."
            )
    elif method == "squash":
        if len(commits) != 1 or parents(head) != [previous_main]:
            errors.append(
                "squash integration must be exactly one commit whose sole "
                "parent is previous_main."
            )
    manifest_matches = False
    try:
        manifest_matches = (
            git_bytes("show", f"{head}:{MANIFEST_PATH}")
            == manifest_path.read_bytes()
        )
    except subprocess.CalledProcessError:
        pass
    observed_changed = changed_paths(previous_main, head)
    if actual != expected:
        errors.append(
            "Post-merge path/mode/blob inventory differs from the approved overlay."
        )
    if observed_changed != expected_changed:
        errors.append(
            f"Post-merge changed paths {observed_changed}; "
            f"expected {expected_changed}."
        )
    if not manifest_matches:
        errors.append("Post-merge manifest bytes differ from the approved manifest.")
    return {
        "target_mode": "post-merge-main",
        "main_head": head,
        "main_tree": tree(head),
        "previous_main": previous_main,
        "detected_merge_method": detected,
        "validated_merge_method": method,
        "range_commits": commits,
        "common_merge_base": base,
        "approved_delta_paths": approved_paths,
        "expected_changed_paths": expected_changed,
        "observed_changed_paths": observed_changed,
        "expected_inventory_matches": actual == expected,
        "manifest_matches": manifest_matches,
        "valid_retained_parents": valid_retained,
    }


def validate_checkout_context(
    context: str,
    expected_head: str,
    errors: list[str],
) -> dict[str, Any]:
    checkout = commit("HEAD")
    checkout_parents = parents(checkout)
    if context == "exact-head" and checkout != expected_head:
        errors.append(f"Exact-head checkout {checkout} != {expected_head}.")
    elif context == "merge-ref":
        if checkout == expected_head:
            errors.append("Merge-ref validation ran on exact head.")
        if len(checkout_parents) < 2 or expected_head not in checkout_parents:
            errors.append("Expected head is not a direct parent of merge-ref checkout.")
    elif context not in {"exact-head", "merge-ref"}:
        errors.append(f"Unsupported checkout context: {context}.")
    return {
        "context": context,
        "checkout_commit": checkout,
        "checkout_tree": tree(checkout),
        "checkout_parent_count": len(checkout_parents),
        "expected_head": expected_head,
        "expected_head_is_direct_parent": expected_head in checkout_parents,
    }
