from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

MANIFEST = "IMPLEMENTATION_SOURCE_MANIFEST.json"
CONTROLLED = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)
STATE = "R1_SECURITY_GENERATION_6_REMEDIATION_MANIFEST_CONTROL"


def git(repo: Path, *args: str, input_text: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def write(repo: Path, relative: str, text: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def parents(repo: Path, ref: str) -> list[str]:
    return git(repo, "rev-list", "--parents", "-n", "1", ref).split()[1:]


def changed(repo: Path, base: str, head: str) -> list[str]:
    return sorted(p for p in git(repo, "diff", "--name-only", "--no-renames", base, head).splitlines() if p)


def population(repo: Path, source: str) -> list[str]:
    raw = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", source])
    paths: list[str] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        _mode, kind, _oid = metadata.decode("ascii").split()
        if kind != "blob":
            raise RuntimeError("non-blob tracked object")
        path = raw_path.decode("utf-8")
        if path != MANIFEST:
            paths.append(path)
    return sorted(paths)


def generate(repo: Path, source: str, base: str, control: str) -> dict[str, Any]:
    if not parents(repo, control) or parents(repo, control)[0] != source:
        raise ValueError("control is not a direct child of source")
    if changed(repo, source, control) != sorted(CONTROLLED):
        raise ValueError("control path boundary mismatch")
    paths = population(repo, source)
    groups: dict[str, list[str]] = {}
    for path in paths:
        directory, name = path.rsplit("/", 1) if "/" in path else ("", path)
        groups.setdefault(directory, []).append(name)
    return {
        "schema_version": 6,
        "state": STATE,
        "source_commit": source,
        "source_tree": git(repo, "rev-parse", f"{source}^{{tree}}"),
        "source_base_commit": base,
        "control_commit": control,
        "control_tree": git(repo, "rev-parse", f"{control}^{{tree}}"),
        "controlled_paths": list(sorted(CONTROLLED)),
        "generator_version": "6.0.0",
        "path_inventory": [
            {"directory": directory, "entries": sorted(groups[directory])}
            for directory in sorted(groups)
        ],
        "summary": {"total_file_count": len(paths)},
        "verification": {
            "duplicate_path_count": 0,
            "missing_tracked_file_count": 0,
            "extra_manifest_entry_count": 0,
            "source_tree_mismatch_count": 0,
            "control_tree_mismatch_count": 0,
            "unexpected_control_change_count": 0,
            "unexpected_manifest_commit_change_count": 0,
        },
    }


def listed_paths(manifest: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for group in manifest["path_inventory"]:
        directory = group["directory"]
        for name in group["entries"]:
            result.append(f"{directory}/{name}" if directory else name)
    return result


def validate(
    repo: Path,
    manifest: dict[str, Any],
    expected_head: str,
    checkout: str,
    context: str,
) -> None:
    errors: list[str] = []
    source = manifest.get("source_commit")
    control = manifest.get("control_commit")
    if manifest.get("schema_version") != 6 or manifest.get("state") != STATE:
        errors.append("schema/state mismatch")
    if manifest.get("generator_version") != "6.0.0":
        errors.append("generator version mismatch")
    if manifest.get("controlled_paths") != list(sorted(CONTROLLED)):
        errors.append("controlled paths mismatch")
    if not isinstance(source, str) or not isinstance(control, str):
        errors.append("missing source/control")
    else:
        if parents(repo, control)[:1] != [source]:
            errors.append("control parent mismatch")
        if changed(repo, source, control) != sorted(CONTROLLED):
            errors.append("control path mismatch")
        if manifest.get("source_tree") != git(repo, "rev-parse", f"{source}^{{tree}}"):
            errors.append("source tree mismatch")
        if manifest.get("control_tree") != git(repo, "rev-parse", f"{control}^{{tree}}"):
            errors.append("control tree mismatch")
        expected_paths = population(repo, source)
        actual_paths = listed_paths(manifest)
        if actual_paths != expected_paths:
            errors.append("inventory mismatch")
        if manifest.get("summary") != {"total_file_count": len(expected_paths)}:
            errors.append("summary mismatch")
    if parents(repo, expected_head)[:1] != [control]:
        errors.append("head parent mismatch")
    if changed(repo, control, expected_head) != [MANIFEST]:
        errors.append("head path mismatch")
    expected_bytes = git(repo, "show", f"{expected_head}:{MANIFEST}") + "\n"
    rendered = json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n"
    if rendered != expected_bytes:
        errors.append("manifest byte mismatch")
    checkout_parents = parents(repo, checkout)
    if context == "exact-head":
        if checkout != expected_head:
            errors.append("exact-head mismatch")
    elif context == "merge-ref":
        if checkout == expected_head or expected_head not in checkout_parents or len(checkout_parents) < 2:
            errors.append("merge-ref mismatch")
    else:
        errors.append("unsupported context")
    if errors:
        raise ValueError("; ".join(errors))


def create_chain(repo: Path) -> dict[str, str]:
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "public-repro@example.invalid")
    git(repo, "config", "user.name", "Public Reproducer")
    write(repo, "README.md", "synthetic source\n")
    base = commit_all(repo, "synthetic base")
    write(repo, "src/example.py", "VALUE = 1\n")
    source = commit_all(repo, "synthetic source")
    for index, path in enumerate(CONTROLLED, start=1):
        write(repo, path, f"GENERATION = {index}\n")
    control = commit_all(repo, "synthetic control")
    manifest = generate(repo, source, base, control)
    write(repo, MANIFEST, json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n")
    head = commit_all(repo, "synthetic manifest head")
    git(repo, "checkout", "-b", "synthetic-base", source)
    write(repo, "BASE_MARKER.txt", "merge parent\n")
    merge_base = commit_all(repo, "synthetic merge base")
    git(repo, "merge", "--no-ff", "--no-edit", head)
    merge_ref = git(repo, "rev-parse", "HEAD")
    return {
        "base": base,
        "source": source,
        "control": control,
        "head": head,
        "merge_base": merge_base,
        "merge_ref": merge_ref,
    }
