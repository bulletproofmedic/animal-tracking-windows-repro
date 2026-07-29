from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import unittest
from pathlib import Path

from security_logging_windows import (
    ProtectedRotatingFileHandler,
    ReproducerValidationError,
    activate_no_clobber,
    copy_strict_utf8,
    open_source,
    protect_private_directory,
    protect_private_file,
    read_windows_acl,
    verify_open_source,
)


@unittest.skipUnless(os.name == "nt", "Windows-only security logging reproducer")
class WindowsSecurityLoggingReproducerTests(unittest.TestCase):
    def assert_exact_acl(self, path: Path, *, directory: bool) -> None:
        acl = read_windows_acl(path)
        self.assertTrue(acl["protected"], acl)
        self.assertEqual(acl["owner"], acl["current"], acl)
        rules = acl["rules"]
        self.assertIsInstance(rules, list, acl)
        self.assertEqual(len(rules), 2, acl)
        by_sid = {entry["sid"]: entry for entry in rules}
        self.assertEqual(set(by_sid), {acl["current"], "S-1-5-18"}, acl)
        expected_inheritance = "ContainerInherit, ObjectInherit" if directory else "None"
        for entry in by_sid.values():
            self.assertFalse(entry["inherited"], entry)
            self.assertEqual(entry["access"], "Allow", entry)
            self.assertEqual(entry["rights"], "FullControl", entry)
            self.assertEqual(entry["inheritance"], expected_inheritance, entry)
            self.assertEqual(entry["propagation"], "None", entry)

    def test_file_and_directory_acl_postconditions_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "secured"
            protect_private_directory(root)
            self.assert_exact_acl(root, directory=True)

            source = root / "active.txt"
            source.write_text("synthetic\n", encoding="utf-8")
            protect_private_file(source)
            self.assert_exact_acl(source, directory=False)

    def test_rollover_reprotects_active_and_backup_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rotating"
            protect_private_directory(root)
            log_path = root / "events.txt"

            class CountingHandler(ProtectedRotatingFileHandler):
                rollover_count = 0

                def doRollover(self) -> None:
                    self.rollover_count += 1
                    super().doRollover()

            handler = CountingHandler(
                log_path,
                maxBytes=1,
                backupCount=9,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger = logging.getLogger("sanitized.windows.rollover")
            logger.handlers.clear()
            logger.propagate = False
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            try:
                for index in range(25):
                    logger.info("synthetic event %03d", index)
                handler.flush()
            finally:
                logger.removeHandler(handler)
                handler.close()

            self.assertGreaterEqual(handler.rollover_count, 11)
            paths = sorted(root.glob("events.txt*"))
            self.assertGreaterEqual(len(paths), 2)
            self.assertLessEqual(len(paths), 10)
            for path in paths:
                self.assert_exact_acl(path, directory=False)

    def test_same_size_raw_byte_mutation_with_restored_mtime_is_blocked_or_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_path = Path(temporary) / "mutable.txt"
            source_path.write_bytes(b'{"event":"AAAA"}\n{"event":"BBBB"}\n')
            original = source_path.stat()
            opened = open_source(source_path)
            try:
                mutated = source_path.read_bytes().replace(b"BBBB", b"CCCC")
                try:
                    source_path.write_bytes(mutated)
                except PermissionError:
                    return
                os.utime(
                    source_path,
                    ns=(original.st_atime_ns, original.st_mtime_ns),
                )
                with self.assertRaisesRegex(ReproducerValidationError, "raw bytes changed"):
                    verify_open_source(opened)
            finally:
                opened.stream.close()

    def test_open_source_path_replacement_is_blocked_or_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "selected.txt"
            renamed_path = root / "held.txt"
            source_path.write_text("original\n", encoding="utf-8")
            opened = open_source(source_path)
            try:
                try:
                    source_path.rename(renamed_path)
                except PermissionError:
                    return
                source_path.write_text("replacement\n", encoding="utf-8")
                with self.assertRaisesRegex(ReproducerValidationError, "path identity changed"):
                    verify_open_source(opened)
            finally:
                opened.stream.close()

    def test_strict_utf8_copy_rejects_invalid_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "invalid.txt"
            destination = root / "copied.txt"
            source_path.write_bytes(b'{"event":"safe"}\n\xff\n')
            opened = open_source(source_path)
            try:
                with self.assertRaisesRegex(ReproducerValidationError, "not strict UTF-8"):
                    copy_strict_utf8(opened, destination)
            finally:
                opened.stream.close()

    def test_no_clobber_preserves_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged.txt"
            destination = root / "existing.txt"
            staged.write_bytes(b"candidate")
            destination.write_bytes(b"concurrent")
            protect_private_file(staged)

            with self.assertRaisesRegex(ReproducerValidationError, "already exists"):
                activate_no_clobber(staged, destination)
            self.assertEqual(destination.read_bytes(), b"concurrent")
            self.assertEqual(staged.read_bytes(), b"candidate")

    def test_successful_activation_preserves_hash_size_and_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged.txt"
            destination = root / "activated.txt"
            content = b"synthetic activated output\n"
            staged.write_bytes(content)
            protect_private_file(staged)

            result_hash, result_size = activate_no_clobber(staged, destination)

            self.assertEqual(result_hash, hashlib.sha256(content).hexdigest())
            self.assertEqual(result_size, len(content))
            self.assertEqual(destination.read_bytes(), content)
            self.assert_exact_acl(destination, directory=False)

    def test_failed_post_activation_validation_removes_only_owned_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged.txt"
            destination = root / "activated.txt"
            staged.write_bytes(b"synthetic")
            protect_private_file(staged)

            def fail_validation(_path: Path) -> None:
                raise RuntimeError("synthetic validation failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic validation failure"):
                activate_no_clobber(staged, destination, validator=fail_validation)

            self.assertFalse(destination.exists())
            self.assertEqual(staged.read_bytes(), b"synthetic")


if __name__ == "__main__":
    unittest.main()
