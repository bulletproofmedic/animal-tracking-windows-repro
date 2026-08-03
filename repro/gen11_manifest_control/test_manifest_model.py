from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Callable

MANIFEST_PATH = "IMPLEMENTATION_SOURCE_MANIFEST.json"
CONTROLLED_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)


class InvalidTopology(RuntimeError):
    pass


def git(*args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise InvalidTopology(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def commit(message: str) -> str:
    git("add", "-A")
    git("commit", "-q", "-m", message)
    return git("rev-parse", "HEAD")


def tree(commit_sha: str) -> str:
    return git("rev-parse", f"{commit_sha}^{{tree}}")


def parents(commit_sha: str) -> list[str]:
    return git("rev-list", "--parents", "-n", "1", commit_sha).split()[1:]


def changed(parent: str, child: str) -> list[str]:
    output = git("diff", "--name-only", "--no-renames", parent, child)
    return sorted(output.splitlines()) if output else []


def entry(commit_sha: str, path: str) -> tuple[str, str] | None:
    output = git("ls-tree", commit_sha, "--", path)
    if not output:
        return None
    metadata, returned_path = output.split("\t", 1)
    if returned_path != path:
        raise InvalidTopology("unexpected ls-tree path")
    mode, object_type, blob = metadata.split()
    if object_type != "blob":
        raise InvalidTopology("non-blob path")
    return mode, blob


def apply_path(env: dict[str, str], commit_sha: str, path: str) -> None:
    value = entry(commit_sha, path)
    if value is None:
        git("update-index", "--force-remove", "--", path, env=env)
        return
    mode, blob = value
    git("update-index", "--add", "--cacheinfo", mode, blob, path, env=env)


def expected_merge_tree(
    manifest: dict[str, object], main_parent: str, manifest_head: str
) -> str:
    with tempfile.TemporaryDirectory(prefix="gen11-index-") as temporary_directory:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(Path(temporary_directory) / "index")
        git("read-tree", main_parent, env=env)
        source = str(manifest["source_commit"])
        for path in manifest["source_delta_paths"]:
            apply_path(env, source, str(path))
        control = str(manifest["control_commit"])
        for path in CONTROLLED_PATHS:
            apply_path(env, control, path)
        apply_path(env, manifest_head, MANIFEST_PATH)
        return git("write-tree", env=env)


def validate(
    manifest: dict[str, object],
    retained: str,
    merge: str,
    *,
    main_parent: str,
    merge_method: str = "merge",
) -> None:
    if manifest.get("schema_version") != 10:
        raise InvalidTopology("wrong schema")
    if manifest.get("binding_mode") != "EXACT_BASE_PLUS_DELTA_GIT_TREE_BINDING":
        raise InvalidTopology("wrong binding mode")
    if manifest.get("controlled_paths") != list(CONTROLLED_PATHS):
        raise InvalidTopology("wrong controlled paths")

    base = str(manifest["source_base_commit"])
    source = str(manifest["source_commit"])
    control = str(manifest["control_commit"])
    if parents(source) != [base]:
        raise InvalidTopology("wrong source parent")
    if tree(source) != manifest.get("source_git_tree"):
        raise InvalidTopology("wrong source tree")
    if changed(base, source) != manifest.get("source_delta_paths"):
        raise InvalidTopology("wrong source delta")
    if parents(control) != [source]:
        raise InvalidTopology("wrong control parent")
    if tree(control) != manifest.get("control_git_tree"):
        raise InvalidTopology("wrong control tree")
    if changed(source, control) != list(CONTROLLED_PATHS):
        raise InvalidTopology("wrong control delta")

    retained_parents = parents(retained)
    if len(retained_parents) != 2 or retained_parents[0] != source:
        raise InvalidTopology("wrong retained parents")
    manifest_head = retained_parents[1]
    if parents(manifest_head) != [control]:
        raise InvalidTopology("wrong manifest parent")
    if changed(control, manifest_head) != [MANIFEST_PATH]:
        raise InvalidTopology("wrong manifest delta")
    if tree(retained) != tree(manifest_head) or changed(manifest_head, retained):
        raise InvalidTopology("wrong retained tree")

    if merge_method != "merge":
        raise InvalidTopology("non-merge method")
    merge_parents = parents(merge)
    if merge_parents != [main_parent, retained]:
        raise InvalidTopology("wrong merge parents")
    if tree(merge) != expected_merge_tree(manifest, main_parent, manifest_head):
        raise InvalidTopology("wrong merge tree")


def must_fail(action: Callable[[], None]) -> None:
    with unittest.TestCase().assertRaises(InvalidTopology):
        action()


class Generation11ManifestModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_cwd = Path.cwd()
        self._temporary = tempfile.TemporaryDirectory(prefix="gen11-model-")
        os.chdir(self._temporary.name)
        git("init", "-q")
        git("config", "user.name", "Animal Tracking Validator")
        git("config", "user.email", "validator@example.invalid")

        write("README.md", "base\n")
        write(MANIFEST_PATH, "{}\n")
        for path in CONTROLLED_PATHS:
            write(path, f"base {path}\n")
        self.base = commit("base")

        write("src/example.py", "VALUE = 1\n")
        write("tests/test_example.py", "def test_value(): assert True\n")
        self.source = commit("source")

        for path in CONTROLLED_PATHS:
            write(path, f"control {path}\n")
        self.control = commit("control")

        self.manifest: dict[str, object] = {
            "schema_version": 10,
            "binding_mode": "EXACT_BASE_PLUS_DELTA_GIT_TREE_BINDING",
            "source_base_commit": self.base,
            "source_commit": self.source,
            "source_git_tree": tree(self.source),
            "source_delta_paths": changed(self.base, self.source),
            "control_commit": self.control,
            "control_git_tree": tree(self.control),
            "controlled_paths": list(CONTROLLED_PATHS),
        }
        write(MANIFEST_PATH, json.dumps(self.manifest, sort_keys=True) + "\n")
        self.manifest_head = commit("manifest")
        manifest_tree = tree(self.manifest_head)
        self.retained = git(
            "commit-tree",
            manifest_tree,
            "-p",
            self.source,
            "-p",
            self.manifest_head,
            "-m",
            "retained",
        )
        self.merge = git(
            "commit-tree",
            manifest_tree,
            "-p",
            self.base,
            "-p",
            self.retained,
            "-m",
            "merge",
        )

    def tearDown(self) -> None:
        os.chdir(self._old_cwd)
        self._temporary.cleanup()

    def test_positive_topology(self) -> None:
        validate(self.manifest, self.retained, self.merge, main_parent=self.base)

    def test_eleven_mutations_fail_closed(self) -> None:
        cases: list[Callable[[], None]] = []

        wrong = copy.deepcopy(self.manifest)
        wrong["source_base_commit"] = self.source
        cases.append(lambda value=wrong: validate(value, self.retained, self.merge, main_parent=self.base))

        wrong = copy.deepcopy(self.manifest)
        wrong["source_delta_paths"] = list(wrong["source_delta_paths"])[:-1]
        cases.append(lambda value=wrong: validate(value, self.retained, self.merge, main_parent=self.base))

        wrong = copy.deepcopy(self.manifest)
        wrong["source_delta_paths"] = sorted([*wrong["source_delta_paths"], "extra.txt"])
        cases.append(lambda value=wrong: validate(value, self.retained, self.merge, main_parent=self.base))

        wrong = copy.deepcopy(self.manifest)
        wrong["source_git_tree"] = tree(self.base)
        cases.append(lambda value=wrong: validate(value, self.retained, self.merge, main_parent=self.base))

        bad_control = git("commit-tree", tree(self.control), "-p", self.base, "-m", "bad control")
        wrong = copy.deepcopy(self.manifest)
        wrong["control_commit"] = bad_control
        cases.append(lambda value=wrong: validate(value, self.retained, self.merge, main_parent=self.base))

        wrong_retained = git(
            "commit-tree",
            tree(self.manifest_head),
            "-p",
            self.base,
            "-p",
            self.manifest_head,
            "-m",
            "wrong retained parent",
        )
        cases.append(lambda: validate(self.manifest, wrong_retained, self.merge, main_parent=self.base))

        wrong_retained = git(
            "commit-tree",
            tree(self.source),
            "-p",
            self.source,
            "-p",
            self.manifest_head,
            "-m",
            "wrong retained tree",
        )
        cases.append(lambda: validate(self.manifest, wrong_retained, self.merge, main_parent=self.base))

        git("checkout", "-q", "--detach", self.manifest_head)
        write("extra.txt", "extra\n")
        git("add", "-A")
        extra_tree = git("write-tree")
        extra_merge = git(
            "commit-tree",
            extra_tree,
            "-p",
            self.base,
            "-p",
            self.retained,
            "-m",
            "extra merge",
        )
        cases.append(lambda: validate(self.manifest, self.retained, extra_merge, main_parent=self.base))

        other_main = git("commit-tree", tree(self.base), "-p", self.base, "-m", "other main")
        wrong_merge = git(
            "commit-tree",
            tree(self.manifest_head),
            "-p",
            other_main,
            "-p",
            self.retained,
            "-m",
            "wrong merge parent",
        )
        cases.append(lambda: validate(self.manifest, self.retained, wrong_merge, main_parent=self.base))

        cases.append(
            lambda: validate(
                self.manifest,
                self.retained,
                self.merge,
                main_parent=self.base,
                merge_method="squash",
            )
        )

        wrong = copy.deepcopy(self.manifest)
        wrong["controlled_paths"] = list(CONTROLLED_PATHS[:-1])
        cases.append(lambda value=wrong: validate(value, self.retained, self.merge, main_parent=self.base))

        self.assertEqual(len(cases), 11)
        for case in cases:
            must_fail(case)

    def test_private_identity_binding(self) -> None:
        binding = json.loads(
            Path(__file__).with_name("private_identity_binding.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(binding["private_retained_target"], "6e5649c68080c27d407d20f17fc8632cfe332666")
        self.assertEqual(binding["private_manifest_blob"], "f8a3866659d611052f04b991d67116c5ff32ec69")
        self.assertEqual(binding["private_source_delta_count"], 59)
        self.assertFalse(binding["replaces_private_validation"])


if __name__ == "__main__":
    unittest.main()
