from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "repro" / "f008_target"

parser_spec = importlib.util.spec_from_file_location("target_journal_json_extra", TARGET / "journal_json.py")
assert parser_spec and parser_spec.loader
parser = importlib.util.module_from_spec(parser_spec)
parser_spec.loader.exec_module(parser)

entry_spec = importlib.util.spec_from_file_location("additional_entrypoints", TARGET / "additional_entrypoints.py")
assert entry_spec and entry_spec.loader
entrypoints = importlib.util.module_from_spec(entry_spec)
entry_spec.loader.exec_module(entrypoints)


class AdditionalLifecycleNoMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.temp, ignore_errors=True))
        self.path = self.temp / "journal.json"
        self.path.write_text('{"phase":"READY","phase":"ROLLBACK_PENDING"}', encoding="utf-8")
        self.mutations: list[str] = []

    def assert_rejects_before_mutation(self, function) -> None:
        with self.assertRaises(entrypoints.StartupError):
            function(
                self.path,
                lock_acquired=True,
                strict_reader=parser.read_strict_json_object,
                mutation=self.mutations.append,
            )
        self.assertEqual([], self.mutations)

    def test_all_remaining_startup_reread_entrypoints(self) -> None:
        for function in (
            entrypoints.rollback_activation,
            entrypoints.finalize_activation,
            entrypoints.persist_activation_outcome,
            entrypoints.close_recovery_journal,
            entrypoints.recover_startup_failure,
        ):
            with self.subTest(function=function.__name__):
                self.assert_rejects_before_mutation(function)

    def test_additional_snapshot_identity(self) -> None:
        self.assertEqual("42c72f37d3e17f2ad51ec16c867acdfdf1458dc9", entrypoints.TARGET_COMMIT)
        self.assertEqual(
            {
                "startup.py": "dc685898513e989acef7114bc2e1eaf4adbc7e8c",
                "failure_recovery.py": "fab82ea1a31587f8d384f8b36e47d6989a02aff5",
            },
            entrypoints.SOURCE_BLOBS,
        )


if __name__ == "__main__":
    unittest.main()
