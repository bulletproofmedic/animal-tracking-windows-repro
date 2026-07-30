from __future__ import annotations

import types
import unittest
from typing import Any, Callable

ArchiveHook = Callable[[dict[str, object]], None]
ResolverHook = Callable[[dict[str, object]], tuple[str, str, str]]


def _original_archive(journal: dict[str, object]) -> None:
    events = journal.setdefault("events", [])
    assert isinstance(events, list)
    events.append("ARCHIVE")


_original_archive.__module__ = "synthetic.backup_publication"


def _original_resolver(journal: dict[str, object]) -> tuple[str, str, str]:
    del journal
    return "original", "", "original"


_original_resolver.__module__ = "synthetic.restore_lineage_manifest"


class HookModel:
    def __init__(self) -> None:
        self.publication = types.SimpleNamespace(archive_journal=_original_archive)
        self.lineage = types.SimpleNamespace(resolve_source_manifest=_original_resolver)
        self.original_archive: ArchiveHook | None = None
        self.approved_archive: ArchiveHook = self.composed_archive
        self.approved_resolver: ResolverHook = self.resolve_source_manifest
        self.readback_installed = False
        self.identity_installed = False

    def composed_archive(self, journal: dict[str, object]) -> None:
        if self.original_archive is None:
            raise RuntimeError("Composed history pipeline is not initialized.")
        events = journal.setdefault("events", [])
        assert isinstance(events, list)
        events.extend(
            [
                "BEFORE_HISTORY_READBACK",
                "VERIFY_REGISTRATION",
                "CANONICAL_MANIFEST_BINDING",
                "AFTER_FINAL_READBACK",
            ]
        )
        journal["canonical_manifest_sha256"] = "a" * 64
        self.original_archive(journal)

    def install_readback(self) -> None:
        current: Any = self.publication.archive_journal
        if current is self.approved_archive:
            self.readback_installed = True
            return
        if self.readback_installed:
            raise RuntimeError("Readback hook ownership changed unexpectedly.")
        if current.__module__ != "synthetic.backup_publication":
            raise RuntimeError("Another component already owns backup history.")
        self.original_archive = current
        self.publication.archive_journal = self.approved_archive
        self.readback_installed = True

    def install_identity(self) -> None:
        if self.publication.archive_journal is not self.approved_archive:
            raise RuntimeError("History is not owned by the approved composed pipeline.")
        current: Any = self.lineage.resolve_source_manifest
        if current is self.approved_resolver:
            self.identity_installed = True
            return
        if self.identity_installed:
            raise RuntimeError("Identity resolver ownership changed unexpectedly.")
        if current.__module__ != "synthetic.restore_lineage_manifest":
            raise RuntimeError("Another component already owns identity resolution.")
        self.lineage.resolve_source_manifest = self.approved_resolver
        self.identity_installed = True

    def resolve_source_manifest(self, journal: dict[str, object]) -> tuple[str, str, str]:
        assert journal.get("canonical_manifest_sha256") == "a" * 64
        return "supplied", "property", "SUPPLIED"

    def app_ready(self) -> None:
        self.install_readback()
        self.install_identity()


class HookCompositionTests(unittest.TestCase):
    def test_clean_startup_and_repeated_ready_are_idempotent(self) -> None:
        model = HookModel()
        model.app_ready()
        model.app_ready()
        self.assertIs(model.publication.archive_journal, model.approved_archive)
        self.assertIs(model.lineage.resolve_source_manifest, model.approved_resolver)

    def test_composed_history_executes_both_controls_in_order(self) -> None:
        model = HookModel()
        model.app_ready()
        journal: dict[str, object] = {}
        model.publication.archive_journal(journal)
        self.assertEqual(
            journal["events"],
            [
                "BEFORE_HISTORY_READBACK",
                "VERIFY_REGISTRATION",
                "CANONICAL_MANIFEST_BINDING",
                "AFTER_FINAL_READBACK",
                "ARCHIVE",
            ],
        )
        self.assertEqual(model.lineage.resolve_source_manifest(journal)[2], "SUPPLIED")

    def test_unapproved_history_owner_fails_closed(self) -> None:
        model = HookModel()
        model.app_ready()

        def unapproved(journal: dict[str, object]) -> None:
            del journal

        model.publication.archive_journal = unapproved
        with self.assertRaisesRegex(RuntimeError, "approved composed pipeline"):
            model.install_identity()


if __name__ == "__main__":
    unittest.main()
