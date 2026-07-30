from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

CONTROLLED_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)
MANIFEST_PATH = "IMPLEMENTATION_SOURCE_MANIFEST.json"
ALLOWED_METHODS = ("merge", "squash", "rebase")


def run(repo: Path, *args: str, input_bytes: bytes | None = None, check: bool = True) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"git {' '.join(args)} failed ({completed.returncode}): "
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed.stdout


def text(repo: Path, *args: str) -> str:
    return run(repo, *args).decode("utf-8").strip()


def commit(repo: Path, ref: str) -> str:
    return text(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")


def tree(repo: Path, ref: str) -> str:
    return text(repo, "rev-parse", "--verify", f"{ref}^{{tree}}")


def parents(repo: Path, ref: str) -> list[str]:
    return text(repo, "rev-list", "--parents", "-n", "1", ref).split()[1:]


def changed_paths(repo: Path, base: str, head: str) -> list[str]:
    raw = text(repo, "diff", "--name-only", "--no-renames", base, head)
    return sorted(item for item in raw.splitlines() if item)


def inventory(repo: Path, ref: str) -> dict[str, tuple[str, str]]:
    raw = run(repo, "ls-tree", "-r", "-z", "--full-tree", ref)
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        if kind != "blob":
            raise AssertionError(f"unexpected object kind: {kind}")
        result[raw_path.decode("utf-8")] = (mode, oid)
    return result


def write(repo: Path, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")


def commit_worktree(repo: Path, message: str) -> str:
    run(repo, "add", "--all")
    run(repo, "commit", "-m", message)
    return commit(repo, "HEAD")


def commit_tree(repo: Path, tree_id: str, message: str, parent_ids: list[str]) -> str:
    args = ["commit-tree", tree_id, "-m", message]
    for parent in parent_ids:
        args.extend(["-p", parent])
    return run(repo, *args).decode("ascii").strip()


def hash_manifest(repo: Path, payload: dict[str, object]) -> tuple[str, bytes]:
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    oid = run(repo, "hash-object", "-w", "--stdin", input_bytes=data).decode("ascii").strip()
    return oid, data


def replace_tree_entries(
    repo: Path,
    base_ref: str,
    replacements: dict[str, tuple[str, str] | None],
) -> str:
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(repo / ".git" / f"index.synthetic.{hashlib.sha256(os.urandom(12)).hexdigest()}")
    subprocess.run(["git", "read-tree", base_ref], cwd=repo, env=env, check=True)
    for path, value in replacements.items():
        if value is None:
            subprocess.run(
                ["git", "update-index", "--force-remove", "--", path],
                cwd=repo,
                env=env,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            mode, oid = value
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo", mode, oid, path],
                cwd=repo,
                env=env,
                check=True,
            )
    generated = subprocess.check_output(["git", "write-tree"], cwd=repo, env=env).decode("ascii").strip()
    Path(env["GIT_INDEX_FILE"]).unlink(missing_ok=True)
    return generated


def expected_post_merge(
    repo: Path,
    previous_main: str,
    source: str,
    control: str,
    manifest_bytes: bytes,
) -> tuple[dict[str, tuple[str, str]], list[str]]:
    base = text(repo, "merge-base", previous_main, source)
    base_inventory = inventory(repo, base)
    previous_inventory = inventory(repo, previous_main)
    integrated = inventory(repo, source)
    control_inventory = inventory(repo, control)
    for path in CONTROLLED_PATHS:
        integrated[path] = control_inventory[path]
    manifest_oid = run(repo, "hash-object", "-w", "--stdin", input_bytes=manifest_bytes).decode("ascii").strip()
    integrated[MANIFEST_PATH] = ("100644", manifest_oid)
    approved = sorted(
        path
        for path in set(base_inventory) | set(integrated)
        if base_inventory.get(path) != integrated.get(path)
    )
    expected = dict(previous_inventory)
    for path in approved:
        if path in integrated:
            expected[path] = integrated[path]
        else:
            expected.pop(path, None)
    return expected, approved


def validate_retained(
    repo: Path,
    source: str,
    control: str,
    manifest_head: str,
    retained: str,
    manifest_bytes: bytes,
) -> list[str]:
    errors: list[str] = []
    if parents(repo, control) != [source]:
        errors.append("control-parent")
    if changed_paths(repo, source, control) != sorted(CONTROLLED_PATHS):
        errors.append("control-paths")
    if parents(repo, manifest_head) != [control]:
        errors.append("manifest-parent")
    if changed_paths(repo, control, manifest_head) != [MANIFEST_PATH]:
        errors.append("manifest-path")
    if run(repo, "show", f"{manifest_head}:{MANIFEST_PATH}") != manifest_bytes:
        errors.append("manifest-bytes")
    if parents(repo, retained) != [source, manifest_head]:
        errors.append("retained-parents")
    if tree(repo, retained) != tree(repo, manifest_head):
        errors.append("retained-tree")
    if changed_paths(repo, manifest_head, retained):
        errors.append("retained-delta")
    if run(repo, "show", f"{retained}:{MANIFEST_PATH}") != manifest_bytes:
        errors.append("retained-manifest")
    return errors


def detect_method(repo: Path, previous_main: str, head: str) -> tuple[str, list[str]]:
    head_parents = parents(repo, head)
    commits = [
        item
        for item in text(repo, "rev-list", "--first-parent", "--reverse", f"{previous_main}..{head}").splitlines()
        if item
    ]
    if len(head_parents) == 2 and head_parents[0] == previous_main:
        return "merge", commits
    if len(commits) == 1 and head_parents == [previous_main]:
        return "squash", commits
    return "rebase", commits


def validate_post_merge(
    repo: Path,
    previous_main: str,
    source: str,
    control: str,
    manifest_head: str,
    retained: str,
    head: str,
    manifest_bytes: bytes,
    requested_method: str,
) -> list[str]:
    errors: list[str] = []
    expected, _approved = expected_post_merge(repo, previous_main, source, control, manifest_bytes)
    detected, commits = detect_method(repo, previous_main, head)
    if requested_method not in ALLOWED_METHODS:
        errors.append("method-unsupported")
    if requested_method != detected:
        errors.append("method-detection")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", previous_main, head],
        cwd=repo,
        check=False,
    ).returncode == 0
    if not ancestor:
        errors.append("main-ancestry")
    if not commits:
        errors.append("empty-range")
    if requested_method in {"squash", "rebase"} and any(len(parents(repo, item)) != 1 for item in commits):
        errors.append("linear-history")
    if requested_method == "merge":
        if parents(repo, head) != [previous_main, retained]:
            errors.append("merge-provenance")
        errors.extend(
            f"retained-{item}"
            for item in validate_retained(repo, source, control, manifest_head, retained, manifest_bytes)
        )
    if inventory(repo, head) != expected:
        errors.append("main-inventory")
    if run(repo, "show", f"{head}:{MANIFEST_PATH}") != manifest_bytes:
        errors.append("main-manifest")
    previous_inventory = inventory(repo, previous_main)
    expected_changed = sorted(
        path
        for path in set(previous_inventory) | set(expected)
        if previous_inventory.get(path) != expected.get(path)
    )
    if changed_paths(repo, previous_main, head) != expected_changed:
        errors.append("main-changed-paths")
    return errors


class Generation8ControlReproducer(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        run(self.repo, "init", "-b", "main")
        run(self.repo, "config", "user.name", "Generation 8 Reproducer")
        run(self.repo, "config", "user.email", "reproducer@example.invalid")

        write(self.repo, "app/source.txt", "base\n")
        write(self.repo, ".github/workflows/ci.yml", "base workflow\n")
        write(self.repo, "scripts/generate_source_manifest.py", "base generator\n")
        write(self.repo, "scripts/implementation_manifest_core.py", "base core\n")
        write(self.repo, "scripts/validate_implementation_source_manifest.py", "base validator\n")
        write(self.repo, MANIFEST_PATH, "{\"state\":\"previous\"}\n")
        self.base = commit_worktree(self.repo, "base")

        run(self.repo, "switch", "-c", "source")
        write(self.repo, "app/source.txt", "generation8 source\n")
        write(self.repo, "app/new_source.txt", "bounded source addition\n")
        self.source = commit_worktree(self.repo, "source")

        run(self.repo, "switch", "-c", "control")
        for index, path in enumerate(CONTROLLED_PATHS, start=1):
            write(self.repo, path, f"generation8 control {index}\n")
        self.control = commit_worktree(self.repo, "control")

        self.manifest_payload = {
            "schema_version": 8,
            "state": "R1_SECURITY_GENERATION_8_REMEDIATION_MANIFEST_CONTROL",
            "source": "synthetic",
            "control": "synthetic",
            "allowed_merge_methods": list(ALLOWED_METHODS),
        }
        _oid, self.manifest_bytes = hash_manifest(self.repo, self.manifest_payload)
        write(self.repo, MANIFEST_PATH, self.manifest_bytes.decode("utf-8"))
        self.manifest_head = commit_worktree(self.repo, "manifest")

        self.retained = commit_tree(
            self.repo,
            tree(self.repo, self.manifest_head),
            "retained",
            [self.source, self.manifest_head],
        )

        run(self.repo, "branch", "previous-main", self.base)
        run(self.repo, "switch", "previous-main")
        write(self.repo, "main-only.txt", "preserve current-main-only content\n")
        self.previous_main = commit_worktree(self.repo, "previous main")

        self.expected, self.approved = expected_post_merge(
            self.repo,
            self.previous_main,
            self.source,
            self.control,
            self.manifest_bytes,
        )
        previous_inventory = inventory(self.repo, self.previous_main)
        replacements = {
            path: self.expected.get(path)
            for path in set(previous_inventory) | set(self.expected)
            if previous_inventory.get(path) != self.expected.get(path)
        }
        self.expected_tree = replace_tree_entries(self.repo, self.previous_main, replacements)
        self.merge_head = commit_tree(
            self.repo,
            self.expected_tree,
            "merge integration",
            [self.previous_main, self.retained],
        )
        self.squash_head = commit_tree(
            self.repo,
            self.expected_tree,
            "squash integration",
            [self.previous_main],
        )

        source_inventory = inventory(self.repo, self.source)
        base_inventory = inventory(self.repo, self.base)
        source_paths = sorted(
            path
            for path in set(base_inventory) | set(source_inventory)
            if base_inventory.get(path) != source_inventory.get(path)
        )
        source_replacements: dict[str, tuple[str, str] | None] = {}
        for path in source_paths:
            source_replacements[path] = source_inventory.get(path)
        source_step_tree = replace_tree_entries(self.repo, self.previous_main, source_replacements)
        rebase_step = commit_tree(self.repo, source_step_tree, "rebase source", [self.previous_main])
        self.rebase_head = commit_tree(self.repo, self.expected_tree, "rebase control manifest", [rebase_step])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_public_payload_guard(self) -> None:
        payload_root = Path(__file__).resolve().parent
        allowed = {"test_reproducer.py"}
        self.assertEqual({p.name for p in payload_root.iterdir() if p.is_file()}, allowed)
        content = Path(__file__).read_text(encoding="utf-8")
        prohibited = (
            "bf46" + "1164",
            "bulletproofmedic/" + "animal-tracking",
            "SENSITIVE_" + "LOCATION",
            "RECOVERY_" + "SENSITIVE",
        )
        self.assertFalse(any(item.lower() in content.lower() for item in prohibited))

    def test_positive_retained_chain(self) -> None:
        self.assertEqual(
            validate_retained(
                self.repo,
                self.source,
                self.control,
                self.manifest_head,
                self.retained,
                self.manifest_bytes,
            ),
            [],
        )

    def test_positive_post_merge_methods(self) -> None:
        for method, head in (
            ("merge", self.merge_head),
            ("squash", self.squash_head),
            ("rebase", self.rebase_head),
        ):
            with self.subTest(method=method):
                self.assertEqual(
                    validate_post_merge(
                        self.repo,
                        self.previous_main,
                        self.source,
                        self.control,
                        self.manifest_head,
                        self.retained,
                        head,
                        self.manifest_bytes,
                        method,
                    ),
                    [],
                )

    def test_retained_mutations_fail(self) -> None:
        wrong_order = commit_tree(
            self.repo,
            tree(self.repo, self.manifest_head),
            "wrong order",
            [self.manifest_head, self.source],
        )
        wrong_identity = commit_tree(
            self.repo,
            tree(self.repo, self.manifest_head),
            "wrong identity",
            [self.base, self.manifest_head],
        )
        wrong_tree = commit_tree(
            self.repo,
            tree(self.repo, self.source),
            "wrong tree",
            [self.source, self.manifest_head],
        )
        for label, candidate in (
            ("parent-order", wrong_order),
            ("parent-identity", wrong_identity),
            ("tree", wrong_tree),
        ):
            with self.subTest(label=label):
                self.assertTrue(
                    validate_retained(
                        self.repo,
                        self.source,
                        self.control,
                        self.manifest_head,
                        candidate,
                        self.manifest_bytes,
                    )
                )

    def test_post_merge_mutations_fail(self) -> None:
        main_inventory = inventory(self.repo, self.merge_head)
        bad_manifest_oid = run(
            self.repo,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b'{"state":"tampered"}\n',
        ).decode("ascii").strip()
        bad_manifest_tree = replace_tree_entries(
            self.repo,
            self.merge_head,
            {MANIFEST_PATH: ("100644", bad_manifest_oid)},
        )
        bad_manifest = commit_tree(
            self.repo,
            bad_manifest_tree,
            "bad manifest",
            [self.previous_main, self.retained],
        )
        extra_oid = run(
            self.repo,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b"unapproved\n",
        ).decode("ascii").strip()
        bad_inventory_tree = replace_tree_entries(
            self.repo,
            self.merge_head,
            {"unapproved.txt": ("100644", extra_oid)},
        )
        bad_inventory = commit_tree(
            self.repo,
            bad_inventory_tree,
            "bad inventory",
            [self.previous_main, self.retained],
        )
        wrong_parent = commit_tree(
            self.repo,
            self.expected_tree,
            "wrong parent",
            [self.base, self.retained],
        )
        non_linear = commit_tree(
            self.repo,
            self.expected_tree,
            "nonlinear rebase",
            [self.previous_main, self.retained],
        )
        cases = (
            ("manifest", bad_manifest, "merge"),
            ("inventory", bad_inventory, "merge"),
            ("provenance", wrong_parent, "merge"),
            ("method", self.squash_head, "rebase"),
            ("linearity", non_linear, "rebase"),
        )
        self.assertIn(MANIFEST_PATH, main_inventory)
        for label, candidate, method in cases:
            with self.subTest(label=label):
                self.assertTrue(
                    validate_post_merge(
                        self.repo,
                        self.previous_main,
                        self.source,
                        self.control,
                        self.manifest_head,
                        self.retained,
                        candidate,
                        self.manifest_bytes,
                        method,
                    )
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
