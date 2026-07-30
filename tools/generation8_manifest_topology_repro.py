from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

HEX40 = re.compile(r"\b[0-9a-f]{40}\b")
CONTROL_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)
MANIFEST = "IMPLEMENTATION_SOURCE_MANIFEST.json"


def run(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, input=input_bytes)


def text(root: Path, *args: str) -> str:
    return run(root, *args).decode("utf-8").strip()


def commit(root: Path, message: str, parents: list[str] | None = None, tree: str | None = None) -> str:
    if tree is None:
        tree = text(root, "write-tree")
    command = ["commit-tree", tree, "-m", message]
    for parent in parents or []:
        command.extend(["-p", parent])
    return text(root, *command)


def inventory(root: Path, ref: str) -> dict[str, tuple[str, str]]:
    raw = run(root, "ls-tree", "-r", "-z", "--full-tree", ref)
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        assert kind == "blob"
        result[path.decode()] = (mode, oid)
    return result


def tree_from_inventory(root: Path, entries: dict[str, tuple[str, str]]) -> str:
    index = root / ".synthetic-index"
    index.unlink(missing_ok=True)
    env = dict(os.environ, GIT_INDEX_FILE=str(index))
    subprocess.run(["git", "read-tree", "--empty"], cwd=root, env=env, check=True)
    for path, (mode, oid) in sorted(entries.items()):
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo", f"{mode},{oid},{path}"],
            cwd=root,
            env=env,
            check=True,
        )
    result = subprocess.check_output(["git", "write-tree"], cwd=root, env=env).decode().strip()
    index.unlink(missing_ok=True)
    return result


def overlay_expected(root: Path, previous_main: str, source: str, retained: str) -> tuple[dict[str, tuple[str, str]], list[str]]:
    base = text(root, "merge-base", previous_main, source)
    base_inv = inventory(root, base)
    retained_inv = inventory(root, retained)
    previous_inv = inventory(root, previous_main)
    approved_paths = sorted(
        path
        for path in set(base_inv) | set(retained_inv)
        if base_inv.get(path) != retained_inv.get(path)
    )
    expected = dict(previous_inv)
    for path in approved_paths:
        if path in retained_inv:
            expected[path] = retained_inv[path]
        else:
            expected.pop(path, None)
    return expected, approved_paths


def parents(root: Path, ref: str) -> list[str]:
    return text(root, "rev-list", "--parents", "-n", "1", ref).split()[1:]


def validate_post_merge(root: Path, head: str, previous_main: str, source: str, retained: str, method: str) -> bool:
    expected, approved_paths = overlay_expected(root, previous_main, source, retained)
    if inventory(root, head) != expected:
        return False
    if MANIFEST not in approved_paths or any(path not in inventory(root, head) for path in CONTROL_PATHS):
        return False
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", previous_main, head], cwd=root
    ).returncode != 0:
        return False
    head_parents = parents(root, head)
    range_commits = [
        line
        for line in text(
            root, "rev-list", "--first-parent", "--reverse", f"{previous_main}..{head}"
        ).splitlines()
        if line
    ]
    if method == "merge":
        return head_parents == [previous_main, retained]
    if method == "squash":
        return len(range_commits) == 1 and head_parents == [previous_main]
    if method == "rebase":
        return bool(range_commits) and all(len(parents(root, item)) == 1 for item in range_commits)
    return False


def write_blob(root: Path, content: str) -> str:
    return run(root, "hash-object", "-w", "--stdin", input_bytes=content.encode()).decode().strip()


def build_fixture() -> tuple[Path, dict[str, str]]:
    root = Path(tempfile.mkdtemp(prefix="gen8-public-"))
    subprocess.run(["git", "init", "-q", "--initial-branch=main"], cwd=root, check=True)
    subprocess.run(
        ["git", "config", "user.email", "public-repro@example.invalid"], cwd=root, check=True
    )
    subprocess.run(["git", "config", "user.name", "Public Reproducer"], cwd=root, check=True)

    (root / "base.txt").write_text("base\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    base = commit(root, "base")

    source_inv = inventory(root, base)
    source_inv["src/guard.py"] = ("100644", write_blob(root, "def guard(): return True\n"))
    source_inv["tests/test_guard.py"] = ("100644", write_blob(root, "assert True\n"))
    source = commit(root, "source", [base], tree_from_inventory(root, source_inv))

    control_inv = dict(source_inv)
    for index, path in enumerate(CONTROL_PATHS):
        control_inv[path] = ("100644", write_blob(root, f"control-{index}\n"))
    control = commit(root, "control", [source], tree_from_inventory(root, control_inv))

    manifest_inv = dict(control_inv)
    manifest_inv[MANIFEST] = ("100644", write_blob(root, '{"schema_version":8}\n'))
    manifest_head = commit(root, "manifest", [control], tree_from_inventory(root, manifest_inv))
    retained = commit(root, "retained", [source, manifest_head], tree_from_inventory(root, manifest_inv))

    main_inv = inventory(root, base)
    main_inv["unrelated-main.txt"] = ("100644", write_blob(root, "preserve-me\n"))
    previous_main = commit(root, "prior-main", [base], tree_from_inventory(root, main_inv))

    expected, _ = overlay_expected(root, previous_main, source, retained)
    expected_tree = tree_from_inventory(root, expected)
    merge_head = commit(root, "merge", [previous_main, retained], expected_tree)
    squash_head = commit(root, "squash", [previous_main], expected_tree)

    rebase_mid_inv = dict(main_inv)
    rebase_mid_inv["src/guard.py"] = source_inv["src/guard.py"]
    rebase_mid = commit(root, "rebase-source", [previous_main], tree_from_inventory(root, rebase_mid_inv))
    rebase_head = commit(root, "rebase-final", [rebase_mid], expected_tree)

    return root, {
        "base": base,
        "source": source,
        "control": control,
        "manifest_head": manifest_head,
        "retained": retained,
        "previous_main": previous_main,
        "merge": merge_head,
        "squash": squash_head,
        "rebase": rebase_head,
    }


def payload_guard(script: Path) -> list[str]:
    content = script.read_text(encoding="utf-8")
    forbidden = {
        "private_repository_name": "bullet" + "proofmedic/animal-tracking",
        "north_coordinate": "lat" + "itude",
        "east_coordinate": "long" + "itude",
        "password_assignment": "pass" + "word=",
        "api_key_assignment": "api" + "_key=",
        "token_assignment": "tok" + "en=",
        "requests_import": "requests" + ".",
        "urllib_import": "url" + "lib.",
        "httpx_import": "http" + "x.",
    }
    lower = content.lower()
    checks = {
        "no_private_repository_name": forbidden["private_repository_name"] not in content,
        "no_private_commit_ids": not bool(HEX40.search(content)),
        "no_coordinates": forbidden["north_coordinate"] not in lower
        and forbidden["east_coordinate"] not in lower,
        "no_credentials": all(
            forbidden[key] not in lower
            for key in ("password_assignment", "api_key_assignment", "token_assignment")
        ),
        "synthetic_identity": "example.invalid" in content,
        "temporary_repository": "tempfile.mkdtemp" in content,
        "no_network_calls": all(
            forbidden[key] not in content
            for key in ("requests_import", "urllib_import", "httpx_import")
        ),
        "bounded_control_paths": len(CONTROL_PATHS) == 4,
        "manifest_self_exclusion": MANIFEST not in CONTROL_PATHS,
    }
    failures = [name for name, passed in checks.items() if not passed]
    print(
        json.dumps(
            {"payload_guard": "PASS" if not failures else "FAIL", "checks": checks},
            indent=2,
        )
    )
    return failures


def main() -> None:
    script = Path(__file__).resolve()
    guard_failures = payload_guard(script)
    if guard_failures:
        raise SystemExit(f"payload guard failed: {guard_failures}")

    root, ids = build_fixture()
    try:
        results = {
            method: validate_post_merge(
                root,
                ids[method],
                ids["previous_main"],
                ids["source"],
                ids["retained"],
                method,
            )
            for method in ("merge", "squash", "rebase")
        }
        expected, _ = overlay_expected(
            root, ids["previous_main"], ids["source"], ids["retained"]
        )
        mutations: dict[str, bool] = {}

        def mutated(
            name: str, changes: dict[str, tuple[str, str] | None], method: str = "squash"
        ) -> None:
            candidate = dict(expected)
            for path, value in changes.items():
                if value is None:
                    candidate.pop(path, None)
                else:
                    candidate[path] = value
            head = commit(root, name, [ids["previous_main"]], tree_from_inventory(root, candidate))
            mutations[name] = not validate_post_merge(
                root,
                head,
                ids["previous_main"],
                ids["source"],
                ids["retained"],
                method,
            )

        mutated("extra-path", {"unexpected.txt": ("100644", write_blob(root, "bad\n"))})
        mutated("missing-path", {"src/guard.py": None})
        mutated(
            "manifest-bytes",
            {MANIFEST: ("100644", write_blob(root, '{"schema_version":9}\n'))},
        )
        mutated(
            "control-bytes",
            {CONTROL_PATHS[0]: ("100644", write_blob(root, "mutated\n"))},
        )
        mutated("mode-change", {"src/guard.py": ("100755", expected["src/guard.py"][1])})
        mutated("remove-control", {CONTROL_PATHS[1]: None})

        expected_tree = tree_from_inventory(root, expected)
        wrong_merge = commit(
            root,
            "wrong-merge-parent",
            [ids["previous_main"], ids["manifest_head"]],
            expected_tree,
        )
        mutations["wrong-merge-parent"] = not validate_post_merge(
            root,
            wrong_merge,
            ids["previous_main"],
            ids["source"],
            ids["retained"],
            "merge",
        )
        wrong_squash = commit(root, "wrong-squash-parent", [ids["base"]], expected_tree)
        mutations["wrong-squash-parent"] = not validate_post_merge(
            root,
            wrong_squash,
            ids["previous_main"],
            ids["source"],
            ids["retained"],
            "squash",
        )
        non_linear = commit(
            root, "non-linear", [ids["previous_main"], ids["retained"]], expected_tree
        )
        mutations["non-linear-rebase"] = not validate_post_merge(
            root,
            non_linear,
            ids["previous_main"],
            ids["source"],
            ids["retained"],
            "rebase",
        )

        unrelated_preserved = (
            inventory(root, ids["merge"])["unrelated-main.txt"]
            == inventory(root, ids["previous_main"])["unrelated-main.txt"]
        )
        all_pass = all(results.values()) and all(mutations.values()) and unrelated_preserved
        output = {
            "result": "PASS" if all_pass else "FAIL",
            "windows_python": os.sys.version,
            "merge_methods": results,
            "mutation_count": len(mutations),
            "mutations_rejected": mutations,
            "unrelated_main_content_preserved": unrelated_preserved,
            "evidence_digest": hashlib.sha256(
                json.dumps(
                    {"methods": results, "mutations": mutations}, sort_keys=True
                ).encode()
            ).hexdigest(),
        }
        print(json.dumps(output, indent=2))
        if not all_pass:
            raise SystemExit(1)
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
