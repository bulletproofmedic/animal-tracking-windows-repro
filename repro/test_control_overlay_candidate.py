from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

MANIFEST = "IMPLEMENTATION_SOURCE_MANIFEST.json"
CONTROLLED_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)


def run(root: Path, *args: str) -> None:
    subprocess.run(args, cwd=root, check=True, text=True, capture_output=True)


def out(root: Path, *args: str) -> str:
    return subprocess.check_output(args, cwd=root, text=True).strip()


def commit(root: Path, message: str) -> str:
    run(root, "git", "add", "-A")
    run(
        root,
        "git",
        "-c",
        "user.name=Diagnostic",
        "-c",
        "user.email=d@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return out(root, "git", "rev-parse", "HEAD")


def checkout(root: Path, ref: str) -> None:
    run(root, "git", "checkout", "--detach", "-q", ref)


def tree(root: Path, ref: str) -> str:
    return out(root, "git", "rev-parse", f"{ref}^{{tree}}")


def parents(root: Path, ref: str) -> list[str]:
    return out(root, "git", "rev-list", "--parents", "-n", "1", ref).split()[1:]


def changed(root: Path, base: str, head: str) -> list[str]:
    value = out(root, "git", "diff", "--name-only", "--no-renames", base, head)
    return sorted(item for item in value.splitlines() if item)


def write_control_files(root: Path, *, omit: str | None = None) -> None:
    for index, path in enumerate(CONTROLLED_PATHS):
        if path == omit:
            continue
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"CONTROL={index}\n", encoding="utf-8")


def payload(root: Path, source: str, control: str) -> dict[str, object]:
    return {
        "source_commit": source,
        "source_git_tree": tree(root, source),
        "control_commit": control,
        "control_git_tree": tree(root, control),
        "controlled_paths": list(sorted(CONTROLLED_PATHS)),
    }


def validate(
    root: Path,
    candidate: dict[str, object],
    expected_head: str,
    context: str,
    manifest_path: Path,
) -> list[str]:
    errors: list[str] = []
    source = candidate.get("source_commit")
    control = candidate.get("control_commit")
    if not isinstance(source, str) or not isinstance(control, str):
        return ["identity"]
    try:
        source_tree = tree(root, source)
        control_tree = tree(root, control)
    except subprocess.CalledProcessError:
        return ["identity"]
    if candidate.get("source_git_tree") != source_tree:
        errors.append("source tree")
    if candidate.get("control_git_tree") != control_tree:
        errors.append("control tree")
    if candidate.get("controlled_paths") != list(sorted(CONTROLLED_PATHS)):
        errors.append("controlled paths")
    control_parents = parents(root, control)
    if not control_parents or control_parents[0] != source:
        errors.append("control parent")
    if changed(root, source, control) != list(sorted(CONTROLLED_PATHS)):
        errors.append("control changes")
    head_parents = parents(root, expected_head)
    if not head_parents or head_parents[0] != control:
        errors.append("head parent")
    if changed(root, control, expected_head) != [MANIFEST]:
        errors.append("head changes")
    try:
        head_manifest = subprocess.check_output(
            ["git", "show", f"{expected_head}:{MANIFEST}"], cwd=root
        )
    except subprocess.CalledProcessError:
        head_manifest = b""
    if head_manifest != manifest_path.read_bytes():
        errors.append("manifest bytes")
    checkout_commit = out(root, "git", "rev-parse", "HEAD")
    checkout_parents = parents(root, checkout_commit)
    if context == "exact-head":
        if checkout_commit != expected_head:
            errors.append("exact head")
    elif context == "merge-ref":
        if checkout_commit == expected_head:
            errors.append("merge distinct")
        if len(checkout_parents) < 2:
            errors.append("merge parents")
        if expected_head not in checkout_parents:
            errors.append("merge direct parent")
    else:
        errors.append("context")
    return errors


def make_head(
    root: Path,
    source: str,
    control: str,
    candidate: dict[str, object],
    message: str,
    *,
    extra_path: str | None = None,
) -> tuple[str, Path]:
    checkout(root, control)
    manifest = root / MANIFEST
    manifest.write_text(json.dumps(candidate, sort_keys=True) + "\n", encoding="utf-8")
    if extra_path:
        target = root / extra_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("unexpected\n", encoding="utf-8")
    return commit(root, message), manifest


def main() -> None:
    results: list[dict[str, object]] = []

    def record(name: str, expected: str, errors: list[str]) -> None:
        actual = "PASS" if not errors else "FAIL"
        results.append(
            {
                "name": name,
                "expected": expected,
                "actual": actual,
                "ok": actual == expected,
                "errors": errors,
            }
        )

    with tempfile.TemporaryDirectory(prefix="cf004-overlay-") as temporary:
        root = Path(temporary) / "repo"
        root.mkdir()
        run(root, "git", "init", "-q")
        run(root, "git", "config", "core.autocrlf", "false")
        (root / "src").mkdir()
        (root / "src/app.py").write_text("VALUE=1\n", encoding="utf-8")
        source = commit(root, "source")
        write_control_files(root)
        control = commit(root, "control")
        candidate = payload(root, source, control)
        head, manifest = make_head(root, source, control, candidate, "manifest")

        checkout(root, head)
        record("overlay_positive_exact_head", "PASS", validate(root, candidate, head, "exact-head", manifest))

        checkout(root, source)
        (root / "side.txt").write_text("side\n", encoding="utf-8")
        side = commit(root, "side")
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Diagnostic",
                "GIT_AUTHOR_EMAIL": "d@example.invalid",
                "GIT_COMMITTER_NAME": "Diagnostic",
                "GIT_COMMITTER_EMAIL": "d@example.invalid",
            }
        )
        merge = subprocess.check_output(
            ["git", "commit-tree", tree(root, head), "-p", head, "-p", side, "-m", "merge"],
            cwd=root,
            text=True,
            env=environment,
        ).strip()
        checkout(root, merge)
        manifest.write_text(json.dumps(candidate, sort_keys=True) + "\n", encoding="utf-8")
        record("overlay_positive_merge_ref", "PASS", validate(root, candidate, head, "merge-ref", manifest))
        checkout(root, head)
        record("overlay_merge_ref_on_exact_head", "FAIL", validate(root, candidate, head, "merge-ref", manifest))

        checkout(root, source)
        write_control_files(root, omit=CONTROLLED_PATHS[-1])
        incomplete_control = commit(root, "incomplete-control")
        incomplete_payload = payload(root, source, incomplete_control)
        incomplete_head, incomplete_manifest = make_head(
            root, source, incomplete_control, incomplete_payload, "incomplete-manifest"
        )
        checkout(root, incomplete_head)
        record(
            "overlay_incomplete_control_paths",
            "FAIL",
            validate(root, incomplete_payload, incomplete_head, "exact-head", incomplete_manifest),
        )

        checkout(root, source)
        write_control_files(root)
        (root / "src/unauthorized.py").write_text("VALUE=2\n", encoding="utf-8")
        extra_control = commit(root, "extra-control")
        extra_payload = payload(root, source, extra_control)
        extra_head, extra_manifest = make_head(root, source, extra_control, extra_payload, "extra-manifest")
        checkout(root, extra_head)
        record(
            "overlay_unauthorized_control_path",
            "FAIL",
            validate(root, extra_payload, extra_head, "exact-head", extra_manifest),
        )

        stale_source_tree = dict(candidate)
        stale_source_tree["source_git_tree"] = "0" * 40
        stale_head, stale_manifest = make_head(root, source, control, stale_source_tree, "stale-source-tree")
        checkout(root, stale_head)
        record("overlay_stale_source_tree", "FAIL", validate(root, stale_source_tree, stale_head, "exact-head", stale_manifest))

        stale_control_tree = dict(candidate)
        stale_control_tree["control_git_tree"] = "0" * 40
        stale_control_head, stale_control_manifest = make_head(root, source, control, stale_control_tree, "stale-control-tree")
        checkout(root, stale_control_head)
        record("overlay_stale_control_tree", "FAIL", validate(root, stale_control_tree, stale_control_head, "exact-head", stale_control_manifest))

        stale_source = dict(candidate)
        stale_source["source_commit"] = side
        stale_source_head, stale_source_manifest = make_head(root, source, control, stale_source, "stale-source")
        checkout(root, stale_source_head)
        record("overlay_stale_source_identity", "FAIL", validate(root, stale_source, stale_source_head, "exact-head", stale_source_manifest))

        stale_control = dict(candidate)
        stale_control["control_commit"] = source
        stale_control_head, stale_control_manifest = make_head(root, source, control, stale_control, "stale-control")
        checkout(root, stale_control_head)
        record("overlay_stale_control_identity", "FAIL", validate(root, stale_control, stale_control_head, "exact-head", stale_control_manifest))

        extra_head, extra_head_manifest = make_head(
            root, source, control, candidate, "extra-head-path", extra_path="unexpected.txt"
        )
        checkout(root, extra_head)
        record("overlay_manifest_head_extra_path", "FAIL", validate(root, candidate, extra_head, "exact-head", extra_head_manifest))

    summary = {
        "schema": "CF004_CONTROL_OVERLAY_PUBLIC_WINDOWS_MATRIX_V1",
        "private_source_target": "b37caf381a127af49d3b1b7b1f4999451318b63e",
        "private_source_tree": "373c5fffd4e74f9bf2138c300e022f99e775f500",
        "private_control_commit": "ab845555dcec21e1565bb429a4022dc7e39281b6",
        "private_control_tree": "5faa59bc93016b2ab493b4ebb5e8c138c5251a87",
        "private_manifest_head": "c7d79248dd14d1d2c40b32320e617fd04af8190e",
        "test_count": len(results),
        "pass_count": sum(bool(result["ok"]) for result in results),
        "all_expected": all(bool(result["ok"]) for result in results),
        "results": results,
    }
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["all_expected"] else 1)


if __name__ == "__main__":
    main()
