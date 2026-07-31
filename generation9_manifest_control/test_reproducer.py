from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import implementation_manifest_core as core

EXPECTED_CORE_BLOB = "37851167b6f7a9abd2f1bf47a4f0530296daf3be"


def run(
    repo: Path,
    *args: str,
    data: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    return subprocess.run(
        args,
        cwd=repo,
        check=True,
        text=True,
        encoding="utf-8",
        input=data,
        capture_output=True,
        env=env,
    ).stdout.strip()


def git(repo: Path, *args: str, data: str | None = None) -> str:
    return run(repo, "git", *args, data=data)


def write(repo: Path, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def commit_tree(repo: Path, tree_sha: str, parents: list[str], message: str) -> str:
    args = ["commit-tree", tree_sha]
    for parent in parents:
        args += ["-p", parent]
    return git(repo, *args, data=message + "\n")


def mutate_tree(repo: Path, base_tree: str, changes: dict[str, str]) -> str:
    index = repo / ".git" / f"index-{os.getpid()}"
    env = os.environ | {"GIT_INDEX_FILE": str(index)}
    try:
        run(repo, "git", "read-tree", base_tree, env=env)
        for path, content in changes.items():
            blob = run(
                repo,
                "git",
                "hash-object",
                "-w",
                "--stdin",
                data=content,
            )
            run(
                repo,
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{blob},{path}",
                env=env,
            )
        return run(repo, "git", "write-tree", env=env)
    finally:
        index.unlink(missing_ok=True)


class Generation9ProductionCoreReproducer(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="at-g9-public-")
        self.repo = Path(self.temp.name)
        run(self.repo, "git", "init", "--quiet", "--initial-branch=main")
        git(self.repo, "config", "user.name", "Animal Tracking Validation")
        git(self.repo, "config", "user.email", "validation@example.invalid")
        core.ROOT = self.repo

        write(self.repo, "README.md", "sanitized fixture\n")
        write(self.repo, "src/example.py", "VALUE = 'base'\n")
        write(self.repo, core.MANIFEST_PATH, "{}\n")
        for path in core.CONTROLLED_PATHS:
            write(self.repo, path, f"base {path}\n")
        self.base = commit_all(self.repo, "base")

        write(self.repo, "src/example.py", "VALUE = 'source'\n")
        self.source = commit_all(self.repo, "source")
        self.source_tree = git(self.repo, "rev-parse", self.source + "^{tree}")

        for path in core.CONTROLLED_PATHS:
            write(self.repo, path, f"controlled {path}\n")
        self.control = commit_all(self.repo, "control")

        write(self.repo, core.MANIFEST_PATH, '{"fixture":true}\n')
        self.manifest = commit_all(self.repo, "manifest")
        self.integrated_tree = git(
            self.repo,
            "rev-parse",
            self.manifest + "^{tree}",
        )
        self.retained = commit_tree(
            self.repo,
            self.integrated_tree,
            [self.source, self.manifest],
            "retained",
        )
        self.merge = commit_tree(
            self.repo,
            self.integrated_tree,
            [self.base, self.retained],
            "merge",
        )
        self.squash = commit_tree(
            self.repo,
            self.integrated_tree,
            [self.base],
            "squash",
        )
        self.manifest_path = self.repo / core.MANIFEST_PATH

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_retained_fails(self, head: str, control: str | None = None) -> None:
        errors, _ = core.validate_retained_head(
            self.source,
            control or self.control,
            head,
            self.manifest_path,
        )
        self.assertTrue(errors)

    def assert_main_fails(self, head: str) -> None:
        errors: list[str] = []
        core.validate_post_merge_main(
            self.source,
            self.control,
            head,
            self.base,
            self.manifest_path,
            "auto",
            errors,
        )
        self.assertTrue(errors)

    def test_exact_production_core_blob(self) -> None:
        path = Path(__file__).with_name("implementation_manifest_core.py")
        observed = subprocess.check_output(
            ["git", "hash-object", str(path)],
            text=True,
            encoding="utf-8",
        ).strip()
        self.assertEqual(observed, EXPECTED_CORE_BLOB)

    def test_positive_retained_merge_and_squash(self) -> None:
        errors, _ = core.validate_retained_head(
            self.source,
            self.control,
            self.retained,
            self.manifest_path,
        )
        self.assertEqual(errors, [])
        for head, method in ((self.merge, "merge"), (self.squash, "squash")):
            with self.subTest(method=method):
                post_errors: list[str] = []
                result = core.validate_post_merge_main(
                    self.source,
                    self.control,
                    head,
                    self.base,
                    self.manifest_path,
                    method,
                    post_errors,
                )
                self.assertEqual(post_errors, [])
                self.assertEqual(result["detected_merge_method"], method)

    def test_retained_mutations_fail_through_production_core(self) -> None:
        reversed_parents = commit_tree(
            self.repo,
            self.integrated_tree,
            [self.manifest, self.source],
            "reversed parents",
        )
        changed_tree = commit_tree(
            self.repo,
            mutate_tree(
                self.repo,
                self.integrated_tree,
                {"unexpected.txt": "x\n"},
            ),
            [self.source, self.manifest],
            "changed tree",
        )
        changed_manifest = commit_tree(
            self.repo,
            mutate_tree(
                self.repo,
                self.integrated_tree,
                {core.MANIFEST_PATH: "{}\n"},
            ),
            [self.source, self.manifest],
            "changed manifest",
        )
        three_paths = {
            path: f"controlled {path}\n"
            for path in core.CONTROLLED_PATHS[:-1]
        }
        bad_control_tree = mutate_tree(self.repo, self.source_tree, three_paths)
        bad_control = commit_tree(
            self.repo,
            bad_control_tree,
            [self.source],
            "incomplete control",
        )
        bad_manifest_tree = mutate_tree(
            self.repo,
            bad_control_tree,
            {core.MANIFEST_PATH: '{"fixture":true}\n'},
        )
        bad_manifest = commit_tree(
            self.repo,
            bad_manifest_tree,
            [bad_control],
            "bad manifest child",
        )
        incomplete_control = commit_tree(
            self.repo,
            bad_manifest_tree,
            [self.source, bad_manifest],
            "bad retained",
        )
        cases = (
            (reversed_parents, None),
            (changed_tree, None),
            (changed_manifest, None),
            (incomplete_control, bad_control),
        )
        for head, control in cases:
            with self.subTest(head=head):
                self.assert_retained_fails(head, control)

    def test_post_merge_mutations_and_transient_rebase_fail(self) -> None:
        bad_inventory = commit_tree(
            self.repo,
            mutate_tree(
                self.repo,
                self.integrated_tree,
                {"unauthorized.txt": "x\n"},
            ),
            [self.base, self.retained],
            "bad inventory",
        )
        bad_manifest = commit_tree(
            self.repo,
            mutate_tree(
                self.repo,
                self.integrated_tree,
                {core.MANIFEST_PATH: "{}\n"},
            ),
            [self.base, self.retained],
            "bad manifest",
        )
        wrong_previous = commit_tree(
            self.repo,
            git(self.repo, "rev-parse", self.base + "^{tree}"),
            [self.base],
            "wrong previous",
        )
        bad_provenance = commit_tree(
            self.repo,
            self.integrated_tree,
            [wrong_previous, self.retained],
            "bad provenance",
        )
        transient = commit_tree(
            self.repo,
            mutate_tree(
                self.repo,
                git(self.repo, "rev-parse", self.base + "^{tree}"),
                {"transient-secret.txt": "synthetic\n"},
            ),
            [self.base],
            "transient unauthorized history",
        )
        rebase_final = commit_tree(
            self.repo,
            self.integrated_tree,
            [transient],
            "restore approved final tree",
        )
        for head in (bad_inventory, bad_manifest, bad_provenance, rebase_final):
            with self.subTest(head=head):
                self.assert_main_fails(head)
        detected, _ = core.detect_merge_method(self.base, rebase_final)
        self.assertEqual(detected, core.UNSUPPORTED_LINEAR_METHOD)


if __name__ == "__main__":
    unittest.main()
