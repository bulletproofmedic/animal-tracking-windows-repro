from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from g6_manifest_control import (  # noqa: E402
    CONTROLLED,
    MANIFEST,
    commit_all,
    create_chain,
    generate,
    git,
    validate,
    write,
)


class ManifestControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.refs = create_chain(self.repo)
        self.manifest = json.loads(git(self.repo, "show", f"{self.refs['head']}:{MANIFEST}"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_invalid(self, manifest: dict, *, checkout: str | None = None, context: str = "exact-head") -> None:
        with self.assertRaises(ValueError):
            validate(
                self.repo,
                manifest,
                self.refs["head"],
                checkout or self.refs["head"],
                context,
            )

    def test_exact_head_passes(self) -> None:
        validate(self.repo, self.manifest, self.refs["head"], self.refs["head"], "exact-head")

    def test_merge_ref_passes(self) -> None:
        validate(self.repo, self.manifest, self.refs["head"], self.refs["merge_ref"], "merge-ref")

    def test_wrong_exact_checkout_fails(self) -> None:
        self.assert_invalid(self.manifest, checkout=self.refs["control"])

    def test_exact_head_rejected_as_merge_ref(self) -> None:
        self.assert_invalid(self.manifest, context="merge-ref")

    def test_stale_source_tree_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["source_tree"] = "0" * 40
        self.assert_invalid(mutated)

    def test_stale_control_tree_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["control_tree"] = "1" * 40
        self.assert_invalid(mutated)

    def test_missing_inventory_entry_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["path_inventory"][0]["entries"].pop()
        self.assert_invalid(mutated)

    def test_extra_inventory_entry_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["path_inventory"][0]["entries"].append("unexpected.txt")
        self.assert_invalid(mutated)

    def test_summary_mismatch_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["summary"]["total_file_count"] += 1
        self.assert_invalid(mutated)

    def test_generator_version_mismatch_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["generator_version"] = "5.0.0"
        self.assert_invalid(mutated)

    def test_manifest_byte_mismatch_fails(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["verification"]["missing_tracked_file_count"] = 1
        self.assert_invalid(mutated)

    def test_control_extra_path_is_rejected(self) -> None:
        git(self.repo, "checkout", "-B", "bad-control", self.refs["source"])
        for index, path in enumerate(CONTROLLED, start=1):
            write(self.repo, path, f"GENERATION = {index}\n")
        write(self.repo, "unexpected.txt", "not authorized\n")
        bad_control = commit_all(self.repo, "bad control")
        with self.assertRaises(ValueError):
            generate(self.repo, self.refs["source"], self.refs["base"], bad_control)

    def test_non_direct_control_is_rejected(self) -> None:
        git(self.repo, "checkout", "-B", "indirect", self.refs["source"])
        write(self.repo, "intermediate.txt", "intermediate\n")
        commit_all(self.repo, "intermediate")
        for index, path in enumerate(CONTROLLED, start=1):
            write(self.repo, path, f"GENERATION = {index}\n")
        indirect = commit_all(self.repo, "indirect control")
        with self.assertRaises(ValueError):
            generate(self.repo, self.refs["source"], self.refs["base"], indirect)

    def test_head_with_extra_path_is_rejected(self) -> None:
        git(self.repo, "checkout", "-B", "bad-head", self.refs["control"])
        write(self.repo, MANIFEST, json.dumps(self.manifest, separators=(",", ":"), sort_keys=True) + "\n")
        write(self.repo, "extra.txt", "extra\n")
        bad_head = commit_all(self.repo, "bad head")
        with self.assertRaises(ValueError):
            validate(self.repo, self.manifest, bad_head, bad_head, "exact-head")


if __name__ == "__main__":
    unittest.main()
