from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from manifest_ci_candidate import (
    MANIFEST_PATH,
    ValidationError,
    validate_manifest,
    write_manifest,
)

STATE = "R1_SECURITY_LOGGING_IMMUTABLE_SOURCE_TARGET"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=root, text=True, encoding="utf-8"
    ).strip()


def run_git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True)


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def commit_all(root: Path, message: str) -> str:
    run_git(root, "add", "--all")
    run_git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


def expect_failure(label: str, action, expected_fragment: str) -> dict[str, str]:
    try:
        action()
    except ValidationError as error:
        rendered = str(error)
        if expected_fragment not in rendered:
            raise AssertionError(
                f"{label} failed for the wrong reason: {rendered}"
            ) from error
        return {"check": label, "result": "EXPECTED_FAIL"}
    raise AssertionError(f"{label} unexpectedly passed")


def main() -> None:
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="cf004-manifest-") as temporary:
        root = Path(temporary)
        run_git(root, "init", "-b", "main")
        run_git(root, "config", "user.name", "Public Diagnostic")
        run_git(root, "config", "user.email", "diagnostic@example.invalid")
        run_git(root, "config", "core.autocrlf", "false")

        files = {
            ".github/workflows/ci.yml": "name: synthetic\n",
            "docs/governance/policy.md": "# Synthetic policy\n",
            "docs/remediation/receipt.md": "# Synthetic receipt\n",
            "requirements/dev.lock": "example==1.0.0\n",
            "scripts/helper.py": "VALUE = 1\n",
            "src/example/__init__.py": "\n",
            "src/example/app.py": "VALUE = 'base'\n",
            "src/example/migrations/0001_initial.py": "MIGRATION = 1\n",
            "tests/test_app.py": "def test_value():\n    assert True\n",
        }
        for relative, content in files.items():
            write(root, relative, content)
        base = commit_all(root, "Create synthetic base")

        write(root, "src/example/app.py", "VALUE = 'source'\n")
        write(root, "src/example/new_module.py", "NEW_VALUE = 2\n")
        source = commit_all(root, "Create immutable source target")
        source_tree = git(root, "rev-parse", f"{source}^{{tree}}")

        payload = write_manifest(root, source, base, STATE)
        manifest = root / MANIFEST_PATH
        assert payload["source_commit"] == source
        assert payload["source_git_tree"] == source_tree
        assert payload["source_base_commit"] == base
        assert [row["path"] for row in payload["files"]] == sorted(
            row["path"] for row in payload["files"]
        )
        migration = next(
            row
            for row in payload["files"]
            if row["path"] == "src/example/migrations/0001_initial.py"
        )
        assert migration["category"] == "MIGRATION"
        app_row = next(
            row for row in payload["files"] if row["path"] == "src/example/app.py"
        )
        assert app_row["sha256"] == hashlib.sha256(b"VALUE = 'source'\n").hexdigest()
        assert app_row["size_bytes"] == len(b"VALUE = 'source'\n")
        results.append(
            {
                "check": "generator_exact_target_tree_paths_hashes_sizes",
                "result": "PASS",
                "files": payload["summary"]["total_file_count"],
            }
        )

        write(root, "validation_marker.txt", "manifest correction head\n")
        exact_head = commit_all(root, "Commit generated manifest correction")
        exact_result = validate_manifest(
            root,
            manifest,
            source,
            base,
            STATE,
            "exact-head",
            exact_head,
        )
        assert exact_result["checkout_identity"]["distinct_from_expected_head"] is False
        results.append({"check": "exact_head_positive", "result": "PASS"})

        results.append(
            expect_failure(
                "merge_ref_rejects_exact_head_checkout",
                lambda: validate_manifest(
                    root,
                    manifest,
                    source,
                    base,
                    STATE,
                    "merge-ref",
                    exact_head,
                ),
                "must not run on the exact head",
            )
        )

        run_git(root, "branch", "validation-head", exact_head)
        run_git(root, "checkout", "-b", "base-advance", base)
        write(root, "base_only.txt", "synthetic base advancement\n")
        commit_all(root, "Advance synthetic base")
        run_git(root, "checkout", "validation-head")
        run_git(root, "merge", "--no-ff", "base-advance", "-m", "Create synthetic merge ref")
        merge_ref = git(root, "rev-parse", "HEAD")
        merge_result = validate_manifest(
            root,
            manifest,
            source,
            base,
            STATE,
            "merge-ref",
            exact_head,
        )
        identity = merge_result["checkout_identity"]
        assert identity["distinct_from_expected_head"] is True
        assert identity["parent_count"] == 2
        assert identity["expected_head_is_direct_parent"] is True
        results.append(
            {
                "check": "two_parent_merge_ref_positive",
                "result": "PASS",
                "merge_ref": merge_ref,
            }
        )

        original = copy.deepcopy(payload)

        def validate_current() -> dict[str, object]:
            return validate_manifest(
                root,
                manifest,
                source,
                base,
                STATE,
                "merge-ref",
                exact_head,
            )

        def mutate_and_validate(mutator) -> dict[str, object]:
            mutated = copy.deepcopy(original)
            mutator(mutated)
            manifest.write_text(
                json.dumps(mutated, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            try:
                return validate_current()
            finally:
                manifest.write_text(
                    json.dumps(original, indent=2) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )

        results.append(
            expect_failure(
                "missing_entry",
                lambda: mutate_and_validate(lambda value: value["files"].pop()),
                "Missing tracked manifest entries",
            )
        )

        def add_extra(value: dict[str, object]) -> None:
            rows = value["files"]
            assert isinstance(rows, list)
            rows.append(
                {
                    "path": "zz-extra.txt",
                    "category": "CONFIGURATION",
                    "git_mode": "100644",
                    "git_blob_sha": "0" * 40,
                    "sha256": "0" * 64,
                    "size_bytes": 1,
                }
            )

        results.append(
            expect_failure(
                "extra_entry",
                lambda: mutate_and_validate(add_extra),
                "Extra or stale manifest entries",
            )
        )

        def change_field(field: str, value: object):
            def mutate(payload_value: dict[str, object]) -> None:
                rows = payload_value["files"]
                assert isinstance(rows, list)
                rows[0][field] = value
            return mutate

        results.append(
            expect_failure(
                "category_mismatch",
                lambda: mutate_and_validate(change_field("category", "WRONG")),
                "category mismatch",
            )
        )
        results.append(
            expect_failure(
                "git_blob_mismatch",
                lambda: mutate_and_validate(change_field("git_blob_sha", "0" * 40)),
                "git_blob_sha mismatch",
            )
        )
        results.append(
            expect_failure(
                "sha256_mismatch",
                lambda: mutate_and_validate(change_field("sha256", "0" * 64)),
                "sha256 mismatch",
            )
        )
        results.append(
            expect_failure(
                "size_mismatch",
                lambda: mutate_and_validate(change_field("size_bytes", 999999)),
                "size_bytes mismatch",
            )
        )
        results.append(
            expect_failure(
                "stale_source_commit",
                lambda: mutate_and_validate(
                    lambda value: value.__setitem__("source_commit", base)
                ),
                "source_commit is stale",
            )
        )
        results.append(
            expect_failure(
                "stale_source_tree",
                lambda: mutate_and_validate(
                    lambda value: value.__setitem__("source_git_tree", "0" * 40)
                ),
                "source_git_tree is stale",
            )
        )
        results.append(
            expect_failure(
                "stale_state",
                lambda: mutate_and_validate(
                    lambda value: value.__setitem__("state", "STALE")
                ),
                "state is stale",
            )
        )
        results.append(
            expect_failure(
                "exact_head_rejects_merge_checkout",
                lambda: validate_manifest(
                    root,
                    manifest,
                    source,
                    base,
                    STATE,
                    "exact-head",
                    exact_head,
                ),
                "Exact-head validation checked out",
            )
        )

        assert validate_current()["result"] == "PASS"
        results.append({"check": "restored_manifest_positive", "result": "PASS"})

    print(
        json.dumps(
            {
                "result": "PASS",
                "diagnostic": "AT-R1-SEC-CF-004 manifest and checkout-context controls",
                "checks": results,
                "check_count": len(results),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
