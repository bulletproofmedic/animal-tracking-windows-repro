from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IDENTITIES = ROOT / "private_identities.json"

CONTROL_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/generate_source_manifest.py",
    "scripts/implementation_manifest_core.py",
    "scripts/validate_implementation_source_manifest.py",
)
MANIFEST_PATH = "IMPLEMENTATION_SOURCE_MANIFEST.json"
COORDINATION_PATHS = (
    "docs/coordination/Animal_Tracking_Control_Plane_Write_Lock_1.json",
    "docs/coordination/conversation_succession/activations/CHAT-057.json",
    "docs/coordination/conversation_succession/ownership_transfers/AT-OWN-075.json",
    "docs/coordination/multi_router_claims/claims/AT-ORDINARY-SUCCESSION.json",
    "docs/coordination/multi_router_claims/results/AT-ORDINARY-SUCCESSION.json",
)


class TopologyError(RuntimeError):
    pass


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "--all")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def commit_tree(repo: Path, tree: str, first: str, second: str, message: str) -> str:
    return git(
        repo,
        "commit-tree",
        tree,
        "-p",
        first,
        "-p",
        second,
        "-m",
        message,
    )


def parents(repo: Path, commit: str) -> list[str]:
    return git(repo, "rev-list", "--parents", "-n", "1", commit).split()[1:]


def tree(repo: Path, commit: str) -> str:
    return git(repo, "rev-parse", f"{commit}^{{tree}}")


def changed_paths(repo: Path, parent: str, child: str) -> list[str]:
    output = git(repo, "diff", "--name-only", "--no-renames", parent, child)
    return sorted(output.splitlines()) if output else []


def blob_entry(repo: Path, commit: str, path: str) -> tuple[str, str]:
    output = git(repo, "ls-tree", commit, "--", path)
    if not output:
        raise TopologyError(f"missing path {path} at {commit}")
    metadata, returned_path = output.split("\t", 1)
    if returned_path != path:
        raise TopologyError(f"unexpected path {returned_path}")
    mode, object_type, blob = metadata.split()
    if object_type != "blob":
        raise TopologyError(f"{path} is not a blob")
    return mode, blob


def overlay_paths(repo: Path, base_commit: str, source_commit: str, paths: tuple[str, ...]) -> str:
    with tempfile.TemporaryDirectory(prefix="gen11-index-") as temporary:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
        git(repo, "read-tree", base_commit, env=env)
        for path in paths:
            mode, blob = blob_entry(repo, source_commit, path)
            git(repo, "update-index", "--add", "--cacheinfo", mode, blob, path, env=env)
        return git(repo, "write-tree", env=env)


def tree_with_blob(repo: Path, base_commit: str, path: str, blob: str) -> str:
    with tempfile.TemporaryDirectory(prefix="gen11-mutation-index-") as temporary:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
        git(repo, "read-tree", base_commit, env=env)
        git(repo, "update-index", "--add", "--cacheinfo", "100644", blob, path, env=env)
        return git(repo, "write-tree", env=env)


def validate_topology(repo: Path, topology: dict[str, str]) -> None:
    base = topology["base"]
    source = topology["source"]
    control = topology["control"]
    manifest = topology["manifest"]
    retained = topology["retained"]
    stable_main = topology["stable_main"]
    candidate = topology["candidate"]

    if parents(repo, source) != [base]:
        raise TopologyError("source parent mismatch")
    if parents(repo, control) != [source]:
        raise TopologyError("control parent mismatch")
    if changed_paths(repo, source, control) != list(CONTROL_PATHS):
        raise TopologyError("control path mismatch")
    if parents(repo, manifest) != [control]:
        raise TopologyError("manifest parent mismatch")
    if changed_paths(repo, control, manifest) != [MANIFEST_PATH]:
        raise TopologyError("manifest path mismatch")
    if parents(repo, retained) != [source, manifest]:
        raise TopologyError("retained parent mismatch")
    if tree(repo, retained) != tree(repo, manifest):
        raise TopologyError("retained tree mismatch")
    if changed_paths(repo, manifest, retained):
        raise TopologyError("retained delta is non-zero")
    if changed_paths(repo, base, stable_main) != list(COORDINATION_PATHS):
        raise TopologyError("stable-main coordination delta mismatch")
    if parents(repo, candidate) != [stable_main, retained]:
        raise TopologyError("candidate parent mismatch")

    expected_tree = overlay_paths(repo, retained, stable_main, COORDINATION_PATHS)
    if tree(repo, candidate) != expected_tree:
        raise TopologyError("candidate reconstructed tree mismatch")


def build_topology(repo: Path) -> dict[str, str]:
    git(repo, "init")
    git(repo, "config", "user.name", "Animal Tracking Diagnostic")
    git(repo, "config", "user.email", "diagnostic@example.invalid")

    write(repo, "src/security.py", "SECURITY = 'base'\n")
    write(repo, CONTROL_PATHS[0], "name: base\n")
    write(repo, CONTROL_PATHS[1], "GENERATOR = 0\n")
    write(repo, CONTROL_PATHS[2], "CORE = 0\n")
    write(repo, CONTROL_PATHS[3], "VALIDATOR = 0\n")
    write(repo, MANIFEST_PATH, "{}\n")
    write(repo, COORDINATION_PATHS[0], '{"generation":167,"state":"FREE"}\n')
    base = commit_all(repo, "base")

    write(repo, "src/security.py", "SECURITY = 'generation-11'\n")
    source = commit_all(repo, "source")

    for index, path in enumerate(CONTROL_PATHS, start=1):
        write(repo, path, f"CONTROL = {index}\n")
    control = commit_all(repo, "control")

    write(repo, MANIFEST_PATH, '{"schema_version":10}\n')
    manifest = commit_all(repo, "manifest")
    retained = commit_tree(repo, tree(repo, manifest), source, manifest, "retained")

    git(repo, "checkout", "--detach", base)
    write(repo, COORDINATION_PATHS[0], '{"generation":169,"state":"FREE"}\n')
    for index, path in enumerate(COORDINATION_PATHS[1:], start=1):
        write(repo, path, json.dumps({"record": index}, sort_keys=True) + "\n")
    stable_main = commit_all(repo, "stable main")

    candidate_tree = overlay_paths(repo, retained, stable_main, COORDINATION_PATHS)
    candidate = commit_tree(repo, candidate_tree, stable_main, retained, "candidate")

    return {
        "base": base,
        "source": source,
        "control": control,
        "manifest": manifest,
        "retained": retained,
        "stable_main": stable_main,
        "candidate": candidate,
    }


class Generation11PostMergeCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="gen11-candidate-")
        self.repo = Path(self.temporary.name)
        self.topology = build_topology(self.repo)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_positive_exact_two_parent_candidate(self) -> None:
        validate_topology(self.repo, self.topology)

    def test_five_mutations_fail_closed(self) -> None:
        mutations: list[str] = []
        valid = self.topology
        valid_tree = tree(self.repo, valid["candidate"])

        mutations.append(
            commit_tree(
                self.repo,
                valid_tree,
                valid["base"],
                valid["retained"],
                "wrong first parent",
            )
        )
        mutations.append(
            commit_tree(
                self.repo,
                valid_tree,
                valid["stable_main"],
                valid["source"],
                "wrong second parent",
            )
        )
        mutations.append(
            commit_tree(
                self.repo,
                tree(self.repo, valid["retained"]),
                valid["stable_main"],
                valid["retained"],
                "missing coordination overlay",
            )
        )

        write(self.repo, "mutation.txt", "unexpected\n")
        extra_blob = git(self.repo, "hash-object", "-w", "mutation.txt")
        extra_tree = tree_with_blob(self.repo, valid["candidate"], "unexpected.txt", extra_blob)
        mutations.append(
            commit_tree(
                self.repo,
                extra_tree,
                valid["stable_main"],
                valid["retained"],
                "unexpected path",
            )
        )

        write(self.repo, "altered.txt", "altered retained content\n")
        altered_blob = git(self.repo, "hash-object", "-w", "altered.txt")
        altered_tree = tree_with_blob(
            self.repo,
            valid["candidate"],
            "src/security.py",
            altered_blob,
        )
        mutations.append(
            commit_tree(
                self.repo,
                altered_tree,
                valid["stable_main"],
                valid["retained"],
                "altered retained path",
            )
        )

        for candidate in mutations:
            mutated = dict(valid)
            mutated["candidate"] = candidate
            with self.assertRaises(TopologyError):
                validate_topology(self.repo, mutated)

        self.assertEqual(len(mutations), 5)

    def test_private_identity_binding(self) -> None:
        observed = json.loads(IDENTITIES.read_text(encoding="utf-8"))
        expected = {
            "source_base_commit": "877ab6f30e06ccb85c3490984acf550f1f3b7080",
            "source_commit": "05f8ff277ea84be769b99b52e4cb60751429ac46",
            "control_commit": "7fa6dedfbd1bd7f41c68c0895816c2018424dd97",
            "manifest_commit": "b8001b6eaa5497063776978c01a2051e1c73618e",
            "retained_target": "6e5649c68080c27d407d20f17fc8632cfe332666",
            "stable_main": "534851a70d6707d0b1b7409207cf22b19ea06cda",
            "candidate_commit": "4c45883f4ea4c00c9ed670ce9d46bbcfd19a017e",
            "candidate_tree": "62969daf508d5e0ea29fe4decfdb47c464f28819",
            "source_delta_path_count": 59,
            "control_delta_path_count": 4,
            "stable_main_coordination_path_count": 5,
        }
        for key, value in expected.items():
            self.assertEqual(observed[key], value)


if __name__ == "__main__":
    unittest.main()
