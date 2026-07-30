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
STATE = "R1_SECURITY_GENERATION_7_REMEDIATION_MANIFEST_CONTROL"


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


def tree(repo: Path, ref: str) -> str:
    return git(repo, "rev-parse", f"{ref}^{{tree}}")


def changed(repo: Path, base: str, head: str) -> list[str]:
    output = git(repo, "diff", "--name-only", "--no-renames", base, head)
    return sorted(path for path in output.splitlines() if path)


def population(repo: Path, source: str) -> list[str]:
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", source]
    )
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
    if parents(repo, control) != [source]:
        raise ValueError("control parent mismatch")
    if changed(repo, source, control) != sorted(CONTROLLED):
        raise ValueError("control path boundary mismatch")
    paths = population(repo, source)
    groups: dict[str, list[str]] = {}
    for path in paths:
        directory, name = path.rsplit("/", 1) if "/" in path else ("", path)
        groups.setdefault(directory, []).append(name)
    return {
        "schema_version": 7,
        "state": STATE,
        "source_commit": source,
        "source_tree": tree(repo, source),
        "source_base_commit": base,
        "control_commit": control,
        "control_tree": tree(repo, control),
        "controlled_paths": list(sorted(CONTROLLED)),
        "generator_version": "7.0.0",
        "retained_head_rule": "ordered parents, equal tree, zero delta, exact manifest bytes",
        "path_inventory": [
            {"directory": directory, "entries": sorted(groups[directory])}
            for directory in sorted(groups)
        ],
        "summary": {"total_file_count": len(paths)},
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
    retained_head: str,
    checkout: str,
    context: str,
) -> None:
    errors: list[str] = []
    source = manifest.get("source_commit")
    control = manifest.get("control_commit")
    retained_parents = parents(repo, retained_head)
    manifest_head = retained_parents[1] if len(retained_parents) == 2 else control
    if manifest.get("schema_version") != 7 or manifest.get("state") != STATE:
        errors.append("schema/state mismatch")
    if manifest.get("generator_version") != "7.0.0":
        errors.append("generator mismatch")
    if manifest.get("controlled_paths") != list(sorted(CONTROLLED)):
        errors.append("controlled paths mismatch")
    if not isinstance(source, str) or not isinstance(control, str):
        errors.append("missing source/control")
    else:
        if parents(repo, control) != [source]:
            errors.append("control parent mismatch")
        if changed(repo, source, control) != sorted(CONTROLLED):
            errors.append("control path mismatch")
        if manifest.get("source_tree") != tree(repo, source):
            errors.append("source tree mismatch")
        if manifest.get("control_tree") != tree(repo, control):
            errors.append("control tree mismatch")
        paths = population(repo, source)
        if listed_paths(manifest) != paths:
            errors.append("inventory mismatch")
        if manifest.get("summary") != {"total_file_count": len(paths)}:
            errors.append("summary mismatch")
    if not isinstance(source, str) or retained_parents != [source, manifest_head]:
        errors.append("retained parent order/identity mismatch")
    if not isinstance(control, str) or parents(repo, manifest_head) != [control]:
        errors.append("manifest-head parent mismatch")
    if not isinstance(control, str) or changed(repo, control, manifest_head) != [MANIFEST]:
        errors.append("manifest-head path mismatch")
    if tree(repo, retained_head) != tree(repo, manifest_head):
        errors.append("retained tree mismatch")
    if changed(repo, manifest_head, retained_head):
        errors.append("retained delta mismatch")
    expected_bytes = git(repo, "show", f"{retained_head}:{MANIFEST}") + "\n"
    rendered = json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n"
    if expected_bytes != rendered:
        errors.append("manifest byte mismatch")
    checkout_parents = parents(repo, checkout)
    if context == "exact-head":
        if checkout != retained_head:
            errors.append("exact-head mismatch")
    elif context == "merge-ref":
        if checkout == retained_head or retained_head not in checkout_parents:
            errors.append("merge-ref mismatch")
    else:
        errors.append("unsupported context")
    if errors:
        raise ValueError("; ".join(errors))


def commit_tree(repo: Path, tree_sha: str, ordered_parents: list[str], message: str) -> str:
    args = ["commit-tree", tree_sha]
    for parent in ordered_parents:
        args.extend(["-p", parent])
    return git(repo, *args, input_text=message + "\n")


def create_chain(repo: Path) -> dict[str, str]:
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "public-repro@example.invalid")
    git(repo, "config", "user.name", "Public Reproducer")
    write(repo, "README.md", "synthetic base\n")
    base = commit_all(repo, "base")
    write(repo, "src/example.py", "VALUE = 1\n")
    source = commit_all(repo, "source")
    for index, path in enumerate(CONTROLLED, start=1):
        write(repo, path, f"GENERATION = {index}\n")
    control = commit_all(repo, "control")
    manifest = generate(repo, source, base, control)
    write(repo, MANIFEST, json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n")
    manifest_head = commit_all(repo, "manifest head")
    retained = commit_tree(repo, tree(repo, manifest_head), [source, manifest_head], "retained")
    git(repo, "branch", "retained", retained)
    git(repo, "checkout", "-b", "merge-base", source)
    write(repo, "BASE_MARKER.txt", "merge parent\n")
    commit_all(repo, "merge base")
    git(repo, "merge", "--no-ff", "--no-edit", retained)
    merge_ref = git(repo, "rev-parse", "HEAD")
    return {
        "base": base,
        "source": source,
        "control": control,
        "manifest_head": manifest_head,
        "retained": retained,
        "merge_ref": merge_ref,
    }
