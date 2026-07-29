from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from repro.g4_secret_scan import scan


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    )


def initialize(root: Path) -> None:
    git(root, "init")
    git(root, "config", "user.email", "diagnostic@example.invalid")
    git(root, "config", "user.name", "Diagnostic")
    (root / "README.md").write_text("clean\n", encoding="utf-8")
    git(root, "add", "README.md")
    git(root, "commit", "-m", "clean")


class SecretScannerTests(unittest.TestCase):
    def test_non_utf8_current_blob_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            jwt = "A" * 16 + "." + "B" * 8 + "." + "C" * 8
            (root / "binary.dat").write_bytes(b"\xff\xfe" + jwt.encode("ascii") + b"\x00")
            git(root, "add", "binary.dat")
            findings = scan(root)
            self.assertTrue(
                any(
                    finding.rule == "jwt"
                    and finding.source == "current_tracked_content"
                    for finding in findings
                )
            )
            self.assertNotIn(jwt, repr(findings))

    def test_deleted_secret_in_history_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            token = "sk-" + "Z" * 24
            (root / "temporary.txt").write_text(token, encoding="utf-8")
            git(root, "add", "temporary.txt")
            git(root, "commit", "-m", "temporary")
            git(root, "rm", "temporary.txt")
            git(root, "commit", "-m", "delete")
            findings = scan(root)
            self.assertTrue(
                any(
                    finding.rule == "service_key"
                    and finding.source == "reachable_git_history"
                    for finding in findings
                )
            )
            self.assertNotIn(token, repr(findings))


if __name__ == "__main__":
    unittest.main()
