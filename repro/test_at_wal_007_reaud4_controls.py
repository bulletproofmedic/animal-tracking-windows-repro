from __future__ import annotations

import inspect
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from at_wal_007_reaud4_controls import (
    ControlError,
    TerminalState,
    archive_recorded_with_readback,
    compression_only_repack,
    legacy_apply_pending,
    legacy_finalize,
    legacy_recover_failure,
    register_with_readback,
    sha256_path,
)


class TerminalAuthorityTests(unittest.TestCase):
    def make_state(self, root: Path, phase: str) -> TerminalState:
        active = root / "active"
        rollback = root / "rollback"
        staged = root / "staged"
        active.mkdir()
        rollback.mkdir()
        (active / "candidate.txt").write_text("candidate", encoding="utf-8")
        (rollback / "authority.txt").write_text("previous", encoding="utf-8")
        journal = root / "journal.json"
        journal.write_text(json.dumps({"phase": phase}), encoding="utf-8")
        return TerminalState(active, rollback, staged, journal)

    def assert_authority_retained(self, state: TerminalState) -> None:
        self.assertEqual(
            (state.rollback_root / "authority.txt").read_text(encoding="utf-8"),
            "previous",
        )
        self.assertEqual(
            (state.active_root / "candidate.txt").read_text(encoding="utf-8"),
            "candidate",
        )

    def test_legacy_finalize_enters_pending_without_deleting_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self.make_state(Path(directory), "READY")
            self.assertEqual(legacy_finalize(state), "FINALIZE_PENDING")
            self.assert_authority_retained(state)

    def test_legacy_startup_reconciliation_preserves_pending_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self.make_state(Path(directory), "FINALIZE_PENDING")
            self.assertEqual(legacy_apply_pending(state), "FINALIZE_PENDING")
            self.assert_authority_retained(state)

    def test_legacy_failure_routing_preserves_pending_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self.make_state(Path(directory), "FINALIZE_PENDING")
            self.assertEqual(legacy_recover_failure(state), "FINALIZE_PENDING")
            self.assert_authority_retained(state)

    def test_legacy_entry_points_have_no_delete_operation(self) -> None:
        source = "\n".join(
            inspect.getsource(function)
            for function in (legacy_finalize, legacy_apply_pending, legacy_recover_failure)
        )
        self.assertNotIn("rmtree", source)
        self.assertNotIn("unlink", source)
        self.assertNotIn("replace(state.rollback_root", source)


class PublicationReadbackTests(unittest.TestCase):
    def make_publication(
        self,
        root: Path,
    ) -> tuple[Path, dict[str, object], dict[str, object], Path]:
        destination = root / "backup.atbackup"
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data/example.txt", b"synthetic data")
        digest, size = sha256_path(destination)
        journal: dict[str, object] = {
            "phase": "PUBLISHED",
            "archive_sha256": digest,
            "archive_bytes": size,
        }
        row: dict[str, object] = {
            "status": "CREATING",
            "validation_status": "NOT_VALIDATED",
        }
        return destination, journal, row, root / "history.json"

    def finish(
        self,
        destination: Path,
        journal: dict[str, object],
        row: dict[str, object],
        history: Path,
    ) -> None:
        register_with_readback(destination, journal, row)
        journal["phase"] = "RECORDED"
        archive_recorded_with_readback(destination, journal, row, history)

    def test_normal_publication_binds_file_row_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination, journal, row, history = self.make_publication(Path(directory))
            self.finish(destination, journal, row, history)
            digest, size = sha256_path(destination)
            self.assertEqual(row["status"], "COMPLETE")
            self.assertEqual(journal["archive_sha256"], digest)
            self.assertEqual(journal["archive_bytes"], size)
            recorded = json.loads(history.read_text(encoding="utf-8"))
            self.assertEqual(recorded["phase"], "RECORDED")

    def assert_post_registration_mutation_rejected(self, mutation) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination, journal, row, history = self.make_publication(Path(directory))
            with self.assertRaises(ControlError):
                register_with_readback(
                    destination,
                    journal,
                    row,
                    after_registration=mutation,
                )
            self.assertEqual(row["status"], "INVALID")
            self.assertFalse(history.exists())

    def test_replacement_after_registration_is_rejected(self) -> None:
        self.assert_post_registration_mutation_rejected(
            lambda path: path.write_bytes(b"replacement")
        )

    def test_truncation_after_registration_is_rejected(self) -> None:
        def truncate(path: Path) -> None:
            with path.open("r+b") as handle:
                handle.truncate(max(1, path.stat().st_size // 2))

        self.assert_post_registration_mutation_rejected(truncate)

    def test_compression_only_repack_after_registration_is_rejected(self) -> None:
        self.assert_post_registration_mutation_rejected(compression_only_repack)

    def test_change_before_history_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination, journal, row, history = self.make_publication(Path(directory))
            register_with_readback(destination, journal, row)
            journal["phase"] = "RECORDED"
            with self.assertRaises(ControlError):
                archive_recorded_with_readback(
                    destination,
                    journal,
                    row,
                    history,
                    before_history=lambda path: path.write_bytes(b"late replacement"),
                )
            self.assertEqual(row["status"], "INVALID")
            self.assertFalse(history.exists())

    def test_interruption_after_registration_is_restart_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination, journal, row, history = self.make_publication(Path(directory))

            def interrupt(_path: Path) -> None:
                raise KeyboardInterrupt("synthetic interruption")

            with self.assertRaises(KeyboardInterrupt):
                register_with_readback(
                    destination,
                    journal,
                    row,
                    after_registration=interrupt,
                )
            self.assertEqual(row["status"], "COMPLETE")
            self.assertEqual(journal["phase"], "PUBLISHED")
            self.finish(destination, journal, row, history)
            self.assertEqual(row["status"], "COMPLETE")
            self.assertTrue(history.is_file())


if __name__ == "__main__":
    unittest.main()
