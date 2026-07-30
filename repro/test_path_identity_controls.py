from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import repro.path_identity_model as model
from repro.path_identity_model import ControlError


def attempt_swap(directory: Path, external: Path) -> tuple[bool, Path]:
    parked = directory.with_name(f"{directory.name}.parked")
    try:
        directory.rename(parked)
    except OSError:
        return False, parked
    os.symlink(external, directory, target_is_directory=True)
    return True, parked


class PathIdentityControls(unittest.TestCase):
    def tearDown(self) -> None:
        model.PROBE = lambda _boundary, _path: None

    def test_happy_path_publication_uses_recorded_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            selected.mkdir()
            identity = model.publish_payload(
                selected,
                "backup.atbackup",
                b"synthetic-backup",
            )
            self.assertEqual(
                (selected / "backup.atbackup").read_bytes(),
                b"synthetic-backup",
            )
            self.assertEqual(
                set(identity.as_dict()),
                {"device", "inode", "volume_serial", "file_index"},
            )

    def test_backup_publication_after_check_swap_never_writes_external(self) -> None:
        self._publication_swap_case("backup.atbackup")

    def test_failed_root_export_after_check_swap_never_writes_external(self) -> None:
        self._publication_swap_case("failed-root.zip")

    def _publication_swap_case(self, name: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            external = root / "external"
            selected.mkdir()
            external.mkdir()
            state: dict[str, object] = {"attempted": False, "parked": None}

            def probe(boundary: str, _path: Path) -> None:
                if boundary != "after_final_parent_identity_check":
                    return
                if state["attempted"]:
                    return
                state["attempted"] = True
                swapped, parked = attempt_swap(selected, external)
                state["swapped"] = swapped
                state["parked"] = parked

            model.PROBE = probe
            with self.assertRaises(ControlError):
                model.publish_payload(selected, name, b"synthetic-private-bytes")
            self.assertTrue(state["attempted"])
            self.assertTrue(state.get("swapped"))
            self.assertFalse((external / name).exists())
            self.assertEqual(list(external.iterdir()), [])

    def test_temporary_creation_after_check_swap_never_writes_external(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            external = root / "external"
            selected.mkdir()
            external.mkdir()
            state = {"attempted": False}

            def probe(boundary: str, _path: Path) -> None:
                if boundary != "after_temporary_parent_identity_check":
                    return
                if state["attempted"]:
                    return
                state["attempted"] = True
                state["swapped"], state["parked"] = attempt_swap(
                    selected,
                    external,
                )

            model.PROBE = probe
            with self.assertRaises(ControlError):
                model.publish_payload(selected, "backup.atbackup", b"payload")
            self.assertTrue(state["attempted"])
            self.assertTrue(state.get("swapped"))
            self.assertEqual(list(external.iterdir()), [])

    def test_restart_reconciliation_rejects_replaced_directory_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            selected.mkdir()
            destination = selected / "backup.atbackup"
            temporary = destination.with_suffix(destination.suffix + ".part")
            payload = b"synthetic"
            with model.pin_chain(selected) as chain:
                with chain.final.open_file(
                    temporary.name,
                    create=True,
                    mutable=True,
                    deletable=True,
                ) as file:
                    file.write(payload)
                journal = root / "journal.json"
                model.write_journal(
                    journal,
                    destination,
                    chain.final.identity,
                    payload,
                )
            selected.rename(root / "original")
            selected.mkdir()
            with self.assertRaises(ControlError):
                model.reconcile(journal)
            self.assertFalse(destination.exists())

    def test_restart_records_final_identity_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            selected.mkdir()
            destination = selected / "backup.atbackup"
            temporary = destination.with_suffix(destination.suffix + ".part")
            payload = b"synthetic"
            with model.pin_chain(selected) as chain:
                with chain.final.open_file(
                    temporary.name,
                    create=True,
                    mutable=True,
                    deletable=True,
                ) as file:
                    file.write(payload)
                journal = root / "journal.json"
                model.write_journal(
                    journal,
                    destination,
                    chain.final.identity,
                    payload,
                )
            model.reconcile(journal)
            value = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(value["phase"], "PUBLISHED")
            self.assertEqual(
                value["directory_identity_at_selection"],
                value["directory_identity_at_final_publication"],
            )
            self.assertEqual(destination.read_bytes(), payload)

    def test_restore_all_member_classes_resist_post_check_parent_swap(self) -> None:
        for relative in (
            "data/database.bin",
            "media/item.bin",
            "maps/source/item.bin",
            "contributors/nested/item.bin",
        ):
            with self.subTest(relative=relative):
                self._restore_swap_case(relative)

    def _restore_swap_case(self, relative: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / "staged"
            external = root / "external"
            staged.mkdir()
            external.mkdir()
            state = {"attempted": False}

            def probe(boundary: str, path: Path) -> None:
                if boundary != "after_final_parent_identity_check":
                    return
                if state["attempted"]:
                    return
                state["attempted"] = True
                state["swapped"], state["parked"] = attempt_swap(
                    path.parent,
                    external,
                )

            model.PROBE = probe
            with self.assertRaises(ControlError):
                model.extract_payload(staged, relative, b"synthetic")
            self.assertTrue(state["attempted"])
            self.assertTrue(state.get("swapped"))
            self.assertFalse((external / Path(relative).name).exists())
            self.assertEqual(list(external.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "Windows ACL test")
    def test_staging_root_dacl_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / "staged"
            staged.mkdir()
            model.extract_payload(staged, "data/item.bin", b"synthetic")
            escaped = str(staged).replace("'", "''")
            command = (
                f"(Get-Acl -LiteralPath '{escaped}')."
                "AreAccessRulesProtected"
            )
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip().casefold(), "true")

    def test_existing_destination_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected"
            selected.mkdir()
            destination = selected / "backup.atbackup"
            destination.write_bytes(b"existing")
            with self.assertRaises((ControlError, OSError)):
                model.publish_payload(selected, destination.name, b"new")
            self.assertEqual(destination.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
