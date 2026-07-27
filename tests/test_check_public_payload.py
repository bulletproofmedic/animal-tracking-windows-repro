from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import check_public_payload as checker


class PublicPayloadUnitTests(unittest.TestCase):
    def test_public_reproducer_url_is_not_private_repo_match(self) -> None:
        public_url = (
            "https://github.com/"
            + "bulletproofmedic/"
            + "animal-tracking-windows-repro"
        )
        findings = checker.content_findings("README.md", public_url.encode())
        self.assertFalse(any("private repository URL" in item for item in findings), findings)

    def test_private_repository_url_is_blocked(self) -> None:
        private_url = "https://github.com/" + "bulletproofmedic/" + "animal-" + "tracking"
        findings = checker.content_findings("notes.txt", private_url.encode())
        self.assertTrue(any("private repository URL" in item for item in findings), findings)

    def test_patch_file_is_blocked(self) -> None:
        findings = checker.validate_named_bytes("repro/fix.patch", b"diff --git a/a b/a\n")
        self.assertTrue(any("forbidden binary/archive/data suffix" in item for item in findings))

    def test_sensitive_filename_separator_variants_are_blocked(self) -> None:
        findings = checker.validate_named_bytes("fixtures/Property-Boundary.txt", b"synthetic")
        self.assertTrue(any("private or sensitive project data" in item for item in findings))

    def test_renamed_zip_is_detected_by_magic(self) -> None:
        findings = checker.validate_named_bytes("repro/payload.txt", b"PK\x03\x04" + b"x" * 20)
        self.assertTrue(any("ZIP-compatible archive" in item for item in findings))

    def test_git_lfs_pointer_is_blocked(self) -> None:
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "a" * 64 + "\n"
            "size 1234\n"
        )
        findings = checker.content_findings("fixture.dat", pointer.encode())
        self.assertTrue(any("Git LFS pointer" in item for item in findings))

    def test_long_encoded_payload_is_blocked(self) -> None:
        encoded = ("QUJD" * 300).encode()
        findings = checker.content_findings("payload.txt", encoded)
        self.assertTrue(any("base64 payload" in item for item in findings))

    def test_github_token_is_blocked(self) -> None:
        token = "gh" + "p_" + ("A" * 36)
        findings = checker.content_findings("notes.txt", token.encode())
        self.assertTrue(any("GitHub classic token" in item for item in findings))


class PublicPayloadHistoryTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_deleted_secret_remains_detected_in_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.name", "Payload Test")
            self.git(root, "config", "user.email", "payload-test@example.invalid")

            (root / "README.md").write_text("safe\n", encoding="utf-8")
            self.git(root, "add", "README.md")
            self.git(root, "commit", "-m", "safe baseline")

            token = "gh" + "p_" + ("B" * 36)
            (root / "leak.txt").write_text(token + "\n", encoding="utf-8")
            self.git(root, "add", "leak.txt")
            self.git(root, "commit", "-m", "temporary leak")

            (root / "leak.txt").unlink()
            self.git(root, "add", "-u")
            self.git(root, "commit", "-m", "remove current leak")

            self.assertEqual(checker.scan_working_tree(root), [])
            history_findings = checker.scan_git_history(root)
            self.assertTrue(
                any("GitHub classic token" in item for item in history_findings),
                history_findings,
            )


if __name__ == "__main__":
    unittest.main()
