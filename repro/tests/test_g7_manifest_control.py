from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from g7_manifest_control import (  # noqa: E402
    CONTROLLED,
    MANIFEST,
    commit_all,
    commit_tree,
    create_chain,
    generate,
    git,
    tree,
    validate,
    write,
)


class Generation7RetainedManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.refs = create_chain(self.repo)
        self.manifest = json.loads(
            git(self.repo, "show", f"{self.refs['retained']}:{MANIFEST}")
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_invalid(self, head: str | None = None, manifest: dict | None = None) -> None:
        with self.assertRaises(ValueError):
            validate(
                self.repo,
                manifest or self.manifest,
                head or self.refs["retained"],
                head or self.refs["retained"],
                "exact-head",
            )

    def test_exact_retained_head_passes(self) -> None:
        validate(
            self.repo,
            self.manifest,
            self.refs["retained"],
            self.refs["retained"],
            "exact-head",
        )

    def test_merge_ref_passes(self) -> None:
        validate(
            self.repo,
            self.manifest,
            self.refs["retained"],
            self.refs["merge_ref"],
            "merge-ref",
        )

    def test_parent_order_mutation_fails(self) -> None:
        bad = commit_tree(
            self.repo,
            tree(self.repo, self.refs["manifest_head"]),
            [self.refs["manifest_head"], self.refs["source"]],
            "bad parent order",
        )
        self.assert_invalid(bad)

    def test_parent_identity_mutation_fails(self) -> None:
        bad = commit_tree(
            self.repo,
            tree(self.repo, self.refs["manifest_head"]),
            [self.refs["control"], self.refs["manifest_head"]],
            "bad parent identity",
        )
        self.assert_invalid(bad)

    def test_tree_and_retained_delta_mutation_fails(self) -> None:
        git(self.repo, "checkout", "-B", "bad-tree", self.refs["manifest_head"])
        write(self.repo, "unexpected.txt", "unexpected\n")
        bad_tree_head = commit_all(self.repo, "bad tree")
        bad = commit_tree(
            self.repo,
            tree(self.repo, bad_tree_head),
            [self.refs["source"], self.refs["manifest_head"]],
            "bad retained tree",
        )
        self.assert_invalid(bad)

    def test_manifest_bytes_mutation_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["summary"]["total_file_count"] += 1
        self.assert_invalid(manifest=mutated)

    def test_controlled_paths_mutation_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["controlled_paths"] = list(sorted(CONTROLLED[:-1]))
        self.assert_invalid(manifest=mutated)

    def test_control_extra_path_is_rejected(self) -> None:
        git(self.repo, "checkout", "-B", "bad-control", self.refs["source"])
        for index, path in enumerate(CONTROLLED, start=1):
            write(self.repo, path, f"GENERATION = {index}\n")
        write(self.repo, "unexpected.txt", "not authorized\n")
        bad_control = commit_all(self.repo, "bad control")
        with self.assertRaises(ValueError):
            generate(self.repo, self.refs["source"], self.refs["base"], bad_control)


if __name__ == "__main__":
    unittest.main()
