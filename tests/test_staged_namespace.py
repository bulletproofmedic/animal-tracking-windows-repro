from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from repro.staged_namespace import verify_exact_namespace

MEMBERS = ["data/database.bin", "config/settings.json"]


def make_fixture(root: Path) -> Path:
    staged = root / "staged"
    (staged / "data").mkdir(parents=True)
    (staged / "config").mkdir(parents=True)
    (staged / "data/database.bin").write_bytes(b"database")
    (staged / "config/settings.json").write_bytes(b"settings")
    return staged


class StagedNamespaceTests(unittest.TestCase):
    def test_exact_implied_directories_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = make_fixture(Path(directory))
            verify_exact_namespace(staged, MEMBERS, lambda: None)

    def test_extra_empty_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = make_fixture(Path(directory))
            (staged / "unexpected/empty").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "directory namespace is not exact"):
                verify_exact_namespace(staged, MEMBERS, lambda: None)

    def test_missing_file_and_parent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = make_fixture(Path(directory))
            (staged / "config/settings.json").unlink()
            (staged / "config").rmdir()
            with self.assertRaisesRegex(ValueError, "file namespace is not exact"):
                verify_exact_namespace(staged, MEMBERS, lambda: None)

    def test_mutation_between_snapshots_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            staged = make_fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, "changed during verification"):
                verify_exact_namespace(staged, MEMBERS, lambda: (staged / "late-empty").mkdir())

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_root_junction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = make_fixture(root)
            target = root / "real-staged"
            staged.rename(target)
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(staged), str(target)], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                self.skipTest(f"junction creation unavailable: {result.stderr}")
            with self.assertRaisesRegex(ValueError, "root is a link or reparse"):
                verify_exact_namespace(staged, MEMBERS, lambda: None)

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_component_junction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = make_fixture(root)
            config = staged / "config"
            target = root / "real-config"
            config.rename(target)
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(config), str(target)], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                self.skipTest(f"junction creation unavailable: {result.stderr}")
            with self.assertRaisesRegex(ValueError, "link, junction, or reparse"):
                verify_exact_namespace(staged, MEMBERS, lambda: None)


if __name__ == "__main__":
    unittest.main()
