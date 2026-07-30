from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from repro.path_identity_model import (
    ControlError,
    Pin,
    extract_member,
    pin_chain,
    publish_new,
    reconcile,
    write_journal,
)


def attempt_swap(directory: Path, external: Path) -> bool:
    parked = directory.with_name(f"{directory.name}.parked")
    try:
        directory.rename(parked)
    except OSError:
        return False
    os.symlink(external, directory, target_is_directory=True)
    return True


class PathIdentityControls(unittest.TestCase):
    def test_pinned_directory_blocks_or_detects_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            external = root / "external"
            selected.mkdir()
            external.mkdir()
            with Pin(selected) as pin:
                swapped = attempt_swap(selected, external)
                if swapped:
                    with self.assertRaises(ControlError):
                        pin.verify()
                else:
                    pin.verify()

    def test_backup_publication_cannot_escape_selected_directory(self) -> None:
        self._publication_swap_case("backup.atbackup")

    def test_failed_root_export_cannot_escape_selected_directory(self) -> None:
        self._publication_swap_case("failed-root.zip")

    def _publication_swap_case(self, name: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            external = root / "external"
            selected.mkdir()
            external.mkdir()
            source = selected / f"{name}.part"
            destination = selected / name
            source.write_bytes(b"synthetic-private-bytes")
            if os.name == "nt":
                with pin_chain(selected) as chain:
                    swapped = attempt_swap(selected, external)
                    self.assertFalse(swapped)
                    publish_new(source, destination, chain)
            else:
                with self.assertRaises(ControlError):
                    with pin_chain(selected) as chain:
                        swapped = attempt_swap(selected, external)
                        self.assertTrue(swapped)
                        publish_new(source, destination, chain)
            self.assertFalse((external / name).exists())

    def test_restart_reconciliation_rejects_replaced_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            selected.mkdir()
            destination = selected / "backup.atbackup"
            journal = root / "journal.json"
            with Pin(selected) as pin:
                write_journal(journal, destination, pin.identity)
            original = root / "original"
            selected.rename(original)
            selected.mkdir()
            temporary = selected / "backup.atbackup.part"
            temporary.write_bytes(b"synthetic")
            with self.assertRaises(ControlError):
                reconcile(journal, temporary)
            self.assertFalse(destination.exists())

    def test_journal_records_all_directory_identity_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            selected.mkdir()
            journal = root / "journal.json"
            with Pin(selected) as pin:
                write_journal(journal, selected / "backup.atbackup", pin.identity)
            value = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(
                set(value["destination_directory_identity"]),
                {"device", "inode", "volume_serial", "file_index"},
            )

    def test_publication_never_replaces_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.part"
            destination = root / "target.zip"
            source.write_bytes(b"new")
            destination.write_bytes(b"existing")
            with pin_chain(root) as chain:
                with self.assertRaises(ControlError):
                    publish_new(source, destination, chain)
            self.assertEqual(destination.read_bytes(), b"existing")

    def test_restore_boundaries_cover_database_media_maps_and_nested_files(self) -> None:
        for relative in (
            "data/database.bin",
            "media/item.bin",
            "maps/source/item.bin",
            "contributors/nested/item.bin",
        ):
            for boundary in ("before_temporary_open", "before_final_publication"):
                with self.subTest(relative=relative, boundary=boundary):
                    self._restore_swap_case(relative, boundary)

    def _restore_swap_case(self, relative: str, boundary: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / "staged"
            external = root / "external"
            staged.mkdir()
            external.mkdir()
            state = {"attempted": False, "succeeded": False}

            def probe(observed: str, path: Path) -> None:
                if observed != boundary or state["attempted"]:
                    return
                state["attempted"] = True
                state["succeeded"] = attempt_swap(path.parent, external)

            if os.name == "nt":
                target = extract_member(b"synthetic", staged, relative, probe=probe)
                self.assertEqual(target.read_bytes(), b"synthetic")
                self.assertFalse(state["succeeded"])
            else:
                with self.assertRaises(ControlError):
                    extract_member(b"synthetic", staged, relative, probe=probe)
                self.assertTrue(state["succeeded"])
            self.assertTrue(state["attempted"])
            self.assertFalse((external / Path(relative).name).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
