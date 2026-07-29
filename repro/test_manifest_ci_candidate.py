from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from manifest_ci_candidate import MANIFEST, build, category, tree, validate

STATE = "R1_SECURITY_EVENTS_MANIFEST_CONTROL_SOURCE"
HERE = Path(__file__).resolve().parent


def run(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=root, check=check, text=True, capture_output=True)


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


def first_path(payload: dict[str, object]) -> str:
    groups = payload["path_inventory"]
    assert isinstance(groups, list)
    group = groups[0]
    assert isinstance(group, dict)
    directory = group["directory"]
    entries = group["entries"]
    assert isinstance(directory, str)
    assert isinstance(entries, list) and entries
    name = entries[0]
    assert isinstance(name, str)
    return f"{directory}/{name}" if directory else name


def adjust_count(payload: dict[str, object], path: str, amount: int) -> None:
    summary = payload["summary"]
    assert isinstance(summary, dict)
    summary["total_file_count"] = int(summary["total_file_count"]) + amount
    counts = summary["count_by_category"]
    assert isinstance(counts, dict)
    key = category(path)
    counts[key] = int(counts.get(key, 0)) + amount
    if counts[key] == 0:
        del counts[key]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cf004-v5-final-") as temporary:
        repository = Path(temporary) / "repo"
        repository.mkdir()
        run(repository, "git", "init", "-q")
        run(repository, "git", "config", "core.autocrlf", "false")
        run(repository, "git", "config", "core.filemode", "true")

        for directory in [
            "src/pkg",
            "tests",
            "docs",
            "scripts",
            ".github/workflows",
        ]:
            (repository / directory).mkdir(parents=True, exist_ok=True)

        (repository / "src/pkg/app.py").write_text("VALUE=1\n", encoding="utf-8")
        (repository / "tests/test_app.py").write_text(
            "def test_x(): assert True\n", encoding="utf-8"
        )
        (repository / "docs/readme.md").write_text(
            "# synthetic\n", encoding="utf-8"
        )
        base = commit(repository, "base")

        shutil.copy2(
            HERE / "manifest_ci_candidate.py",
            repository / "scripts/manifest_ci_candidate.py",
        )
        (repository / ".github/workflows/ci.yml").write_text(
            "name: synthetic\n", encoding="utf-8"
        )
        source = commit(repository, "source")
        source_tree = tree(repository, source)

        payload = build(repository, source, base, STATE)
        manifest_path = repository / MANIFEST
        manifest_path.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        valid = commit(repository, "manifest")
        valid_text = manifest_path.read_text(encoding="utf-8")
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

        checkout(repository, valid)
        record(
            "positive_exact_head",
            "PASS",
            validate(
                repository,
                json.loads(valid_text),
                base,
                STATE,
                "exact-head",
                valid,
                manifest_path,
            ),
        )

        def manifest_mutation(
            name: str, change: Callable[[dict[str, object]], None]
        ) -> None:
            checkout(repository, source)
            candidate = json.loads(valid_text)
            change(candidate)
            manifest_path.write_text(
                json.dumps(candidate, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            head = commit(repository, name)
            record(
                name,
                "FAIL",
                validate(
                    repository,
                    candidate,
                    base,
                    STATE,
                    "exact-head",
                    head,
                    manifest_path,
                ),
            )

        def remove_path(candidate: dict[str, object]) -> None:
            groups = candidate["path_inventory"]
            assert isinstance(groups, list)
            group = groups[0]
            assert isinstance(group, dict)
            entries = group["entries"]
            assert isinstance(entries, list)
            directory = group["directory"]
            assert isinstance(directory, str)
            removed = entries.pop(0)
            assert isinstance(removed, str)
            path = f"{directory}/{removed}" if directory else removed
            adjust_count(candidate, path, -1)

        def add_path(candidate: dict[str, object]) -> None:
            groups = candidate["path_inventory"]
            assert isinstance(groups, list)
            group = groups[0]
            assert isinstance(group, dict)
            entries = group["entries"]
            assert isinstance(entries, list)
            entries.append("zz-extra.txt")
            entries.sort()
            adjust_count(candidate, "zz-extra.txt", 1)

        def duplicate_path(candidate: dict[str, object]) -> None:
            groups = candidate["path_inventory"]
            assert isinstance(groups, list)
            group = groups[0]
            assert isinstance(group, dict)
            entries = group["entries"]
            assert isinstance(entries, list) and entries
            entries.append(entries[0])
            entries.sort()

        def reverse_order(candidate: dict[str, object]) -> None:
            groups = candidate["path_inventory"]
            assert isinstance(groups, list)
            group = groups[0]
            assert isinstance(group, dict)
            entries = group["entries"]
            assert isinstance(entries, list)
            entries.reverse()

        def category_mismatch(candidate: dict[str, object]) -> None:
            summary = candidate["summary"]
            assert isinstance(summary, dict)
            counts = summary["count_by_category"]
            assert isinstance(counts, dict)
            counts["APPLICATION_SOURCE"] = int(counts["APPLICATION_SOURCE"]) + 1

        manifest_mutation("missing_path", remove_path)
        manifest_mutation("extra_path", add_path)
        manifest_mutation("duplicate_path", duplicate_path)
        manifest_mutation("ordering_mutation", reverse_order)
        manifest_mutation("category_mutation", category_mismatch)
        manifest_mutation(
            "stale_source_identity",
            lambda candidate: candidate.__setitem__("source_commit", base),
        )
        manifest_mutation(
            "stale_source_tree",
            lambda candidate: candidate.__setitem__("source_git_tree", "0" * 40),
        )
        manifest_mutation(
            "stale_state",
            lambda candidate: candidate.__setitem__("state", "STALE"),
        )
        manifest_mutation(
            "summary_mutation",
            lambda candidate: candidate["summary"].__setitem__(
                "total_file_count",
                int(candidate["summary"]["total_file_count"]) + 1,
            ),
        )

        def source_tree_mutation(
            name: str, mutate_source: Callable[[Path], None]
        ) -> None:
            checkout(repository, source)
            mutate_source(repository)
            mutated_source = commit(repository, f"{name}-source")
            mutated_tree = tree(repository, mutated_source)
            if mutated_tree == source_tree:
                raise AssertionError(f"{name} did not change the source tree")
            candidate = build(repository, mutated_source, base, STATE)
            candidate["source_git_tree"] = source_tree
            manifest_path.write_text(
                json.dumps(candidate, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            head = commit(repository, name)
            errors = validate(
                repository,
                candidate,
                base,
                STATE,
                "exact-head",
                head,
                manifest_path,
            )
            record(name, "FAIL", errors)

        source_tree_mutation(
            "mode_mutation",
            lambda root: run(
                root, "git", "update-index", "--chmod=+x", "src/pkg/app.py"
            ),
        )
        source_tree_mutation(
            "blob_identity_mutation",
            lambda root: (root / "src/pkg/app.py").write_text(
                "VALUE=2\n", encoding="utf-8"
            ),
        )
        source_tree_mutation(
            "content_hash_mutation",
            lambda root: (root / "docs/readme.md").write_text(
                "# synthetix\n", encoding="utf-8"
            ),
        )
        source_tree_mutation(
            "size_mutation",
            lambda root: (root / "tests/test_app.py").write_text(
                "def test_x(): assert True\n# larger\n", encoding="utf-8"
            ),
        )

        checkout(repository, valid)
        (repository / "src/pkg/app.py").write_text("VALUE=9\n", encoding="utf-8")
        unexpected = commit(repository, "unexpected-post-manifest-change")
        record(
            "unexpected_post_manifest_source_change",
            "FAIL",
            validate(
                repository,
                json.loads(valid_text),
                base,
                STATE,
                "exact-head",
                unexpected,
                manifest_path,
            ),
        )

        checkout(repository, base)
        (repository / "side.txt").write_text("side\n", encoding="utf-8")
        side = commit(repository, "side")
        valid_tree = out(repository, "git", "rev-parse", f"{valid}^{{tree}}")
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
            [
                "git",
                "commit-tree",
                valid_tree,
                "-p",
                valid,
                "-p",
                side,
                "-m",
                "merge",
            ],
            cwd=repository,
            text=True,
            env=environment,
        ).strip()
        checkout(repository, merge)
        manifest_path.write_text(valid_text, encoding="utf-8", newline="\n")
        record(
            "positive_true_two_parent_merge_ref",
            "PASS",
            validate(
                repository,
                json.loads(valid_text),
                base,
                STATE,
                "merge-ref",
                valid,
                manifest_path,
            ),
        )
        checkout(repository, valid)
        record(
            "merge_ref_label_on_exact_head",
            "FAIL",
            validate(
                repository,
                json.loads(valid_text),
                base,
                STATE,
                "merge-ref",
                valid,
                manifest_path,
            ),
        )

        summary = {
            "schema": "CF004_FINAL_TARGET_PUBLIC_WINDOWS_MATRIX_V3",
            "private_target": "b37caf381a127af49d3b1b7b1f4999451318b63e",
            "private_target_tree": "373c5fffd4e74f9bf2138c300e022f99e775f500",
            "private_manifest_head": "7dba55413b9f6f66ad15b4a0ab6ed56e456c5090",
            "private_manifest_tree": "3919cc1f761b71b424436f673155bc5300a36e13",
            "test_count": len(results),
            "pass_count": sum(bool(result["ok"]) for result in results),
            "all_expected": all(bool(result["ok"]) for result in results),
            "results": results,
        }
        print(json.dumps(summary, indent=2))
        raise SystemExit(0 if summary["all_expected"] else 1)


if __name__ == "__main__":
    main()
