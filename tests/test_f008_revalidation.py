from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "repro" / "f008_target"

spec = importlib.util.spec_from_file_location("target_journal_json", TARGET / "journal_json.py")
assert spec and spec.loader
journal_json = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal_json)

extract_spec = importlib.util.spec_from_file_location("source_extracts", TARGET / "source_extracts.py")
assert extract_spec and extract_spec.loader
extracts = importlib.util.module_from_spec(extract_spec)
extract_spec.loader.exec_module(extracts)
extracts.read_strict_json_object = journal_json.read_strict_json_object


@dataclass
class Lock:
    acquired: bool = True


@dataclass
class Paths:
    journal: Path
    legacy: Path


@dataclass
class Settings:
    paths: Paths


@dataclass
class Activation:
    journal_path: Path
    phase: str = "ACTIVATED_PENDING_PREFLIGHT"


class Instance:
    def __init__(self, journal: Path) -> None:
        self.id = "00000000-0000-0000-0000-000000000001"
        self.validation_result = {"journal_phase": "FINALIZED"}
        self.journal = journal


TOP_LEVEL_KEYS = [
    "phase",
    "operation_id",
    "archive_path",
    "archive_sha256",
    "archive_bytes",
    "active_root",
    "staged_root",
    "rollback_root",
    "safety_snapshot",
    "safety_snapshot_sha256",
]


def duplicate_document(key: str, first: str = "first", last: str = "last") -> str:
    return "{" + json.dumps(key) + ":" + json.dumps(first) + "," + json.dumps(key) + ":" + json.dumps(last) + "}"


class StrictParserMatrixTests(unittest.TestCase):
    def write(self, raw: bytes) -> Path:
        path = Path(tempfile.mkdtemp()) / "journal.json"
        path.write_bytes(raw)
        self.addCleanup(lambda: path.parent.exists() and __import__("shutil").rmtree(path.parent))
        return path

    def assert_rejected(self, raw: bytes, exc_type: type[BaseException] = ValueError) -> None:
        with self.assertRaises(exc_type):
            journal_json.read_strict_json_object(self.write(raw))

    def test_all_required_top_level_duplicate_keys(self) -> None:
        for key in TOP_LEVEL_KEYS:
            with self.subTest(key=key):
                self.assert_rejected(duplicate_document(key).encode())

    def test_nested_and_array_duplicate_matrix(self) -> None:
        hostile = [
            b'{"phase_history":[{"phase":"READY","phase":"ROLLED_BACK"}]}',
            b'{"phase_history":[{"operation_id":"a","operation_id":"b"}]}',
            b'{"post_restore_finalizers":[{"finalizer_id":"a","finalizer_id":"b"}]}',
            b'{"post_restore_finalizers":[{"outcome":"SUCCESS","outcome":"FAILED"}]}',
            b'{"backup_lineage":{"archive_path":"a","archive_path":"b"}}',
            b'{"backup_lineage":{"archive_sha256":"a","archive_sha256":"b"}}',
            b'{"records":[{"active_root":"safe","active_root":"attacker"}]}',
            b'{"outer":{"items":[{"phase":"READY","phase":"ROLLBACK_PENDING"}]}}',
        ]
        for raw in hostile:
            with self.subTest(raw=raw):
                self.assert_rejected(raw)

    def test_first_last_authority_divergence(self) -> None:
        self.assert_rejected(b'{"phase":"READY","phase":"ROLLBACK_PENDING"}')
        self.assert_rejected(b'{"active_root":"C:/safe","active_root":"C:/other"}')
        self.assert_rejected(b'{"operation_id":"trusted","operation_id":"forged"}')

    def test_malformed_utf8_json_and_non_object_documents(self) -> None:
        with self.assertRaises(UnicodeDecodeError):
            journal_json.read_strict_json_object(self.write(b'{"phase":"READY","x":"\xff"}'))
        self.assert_rejected(b'{"phase":')
        for raw in (b'[]', b'[{}]', b'"READY"', b'1', b'true', b'null'):
            with self.subTest(raw=raw):
                self.assert_rejected(raw)


class LifecycleNoMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        extracts.read_strict_json_object = journal_json.read_strict_json_object
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.temp, ignore_errors=True))
        self.journal = self.temp / "journal.json"
        self.legacy = self.temp / "legacy.json"
        self.mutations: list[str] = []
        self.settings = Settings(Paths(self.journal, self.legacy))
        extracts.stable_restore_journal_path = lambda paths: paths.journal
        extracts.legacy_pending_marker_path = lambda paths: paths.legacy
        extracts._require_lock = lambda lock: None if lock.acquired else (_ for _ in ()).throw(extracts.StartupError())
        extracts._PREACTIVATION_PHASES = {"STAGED", "ACTIVE_RENAME_PENDING", "ACTIVE_MOVED", "STAGED_RENAME_PENDING"}
        extracts._PREPARING_PHASE = "PREPARING"
        extracts.TERMINAL_STATUSES = {"FINALIZED", "ROLLED_BACK"}
        extracts.atomic_write_json = lambda *args, **kwargs: self.mutations.append("atomic_write_json")
        extracts.durable_replace = lambda *args, **kwargs: self.mutations.append("durable_replace")
        extracts.fsync_directory = lambda *args, **kwargs: self.mutations.append("fsync_directory")
        extracts._write_transition = lambda *args, **kwargs: self.mutations.append("write_transition") or args[1]
        extracts._resume_rollback = lambda *args, **kwargs: self.mutations.append("resume_rollback")
        extracts._complete_pending_finalization = lambda *args, **kwargs: self.mutations.append("finalize") or args[1]
        extracts._validated_activation = lambda *args, **kwargs: self.mutations.append("validated_activation")
        extracts._verify_archive_identity = lambda *args, **kwargs: self.mutations.append("archive_verify")
        extracts._verify_snapshot_identity = lambda *args, **kwargs: self.mutations.append("snapshot_verify")
        extracts._verify_staged_identity = lambda *args, **kwargs: self.mutations.append("staged_verify")
        extracts._records = lambda journal: self.mutations.append("records") or []
        extracts.get_post_restore_finalizers = lambda: ()
        extracts.build_lineage = lambda journal: self.mutations.append("build_lineage") or {}
        extracts.stable_journal_history_path = lambda *args: self.temp / "history.json"
        extracts.stable_failed_root = lambda *args: self.temp / "failed"
        extracts._append_terminal_transition = lambda journal, **kwargs: self.mutations.append("append_transition") or journal
        extracts._validated_preparing_paths = lambda *args: self.mutations.append("validate_paths")
        extracts._journal_path_for_operation = lambda instance: instance.journal
        extracts._validate_terminal_lineage = lambda lineage: self.mutations.append("validate_lineage")
        extracts.mutation_boundary = lambda: self.mutations.append("orm_mutation")

    def write_duplicate(self, content: str = '{"phase":"READY","phase":"ROLLBACK_PENDING"}') -> None:
        self.journal.write_text(content, encoding="utf-8")

    def assert_no_mutation(self, callable_) -> None:
        self.write_duplicate()
        with self.assertRaises(extracts.StartupError):
            callable_()
        self.assertEqual([], self.mutations)

    def test_startup_entrypoints_reject_before_mutation(self) -> None:
        self.assert_no_mutation(lambda: extracts.startup_apply_pending_restore(self.settings, recovery_lock=Lock()))
        activation = Activation(self.journal)
        self.assert_no_mutation(lambda: extracts.startup_mark_preflight_passed(activation, recovery_lock=Lock()))
        self.assert_no_mutation(lambda: extracts.startup_mark_ready(activation, recovery_lock=Lock()))

    def test_staging_entrypoints_reject_before_mutation(self) -> None:
        self.assert_no_mutation(lambda: extracts.staging_reconcile_interrupted_staging(self.settings, recovery_lock=Lock()))
        self.assert_no_mutation(lambda: extracts.staging_archive_failed_preparing_journal(self.settings.paths, operation_id="op", error_code="x"))

    def test_post_restore_rejects_before_finalizer_or_record_write(self) -> None:
        called: list[str] = []
        finalizer = types.SimpleNamespace(
            finalizer_id="f",
            finalizer_version="1",
            finalize_post_restore=lambda context: called.append("finalizer"),
        )
        self.write_duplicate('{"phase":"ACTIVATED_PENDING_PREFLIGHT","phase":"READY"}')
        with self.assertRaises(extracts.StartupError):
            extracts.post_restore_run(Activation(self.journal), settings=self.settings, recovery_lock=Lock(), finalizers=[finalizer])
        self.assertEqual([], called)
        self.assertEqual([], self.mutations)

    def test_lineage_read_and_materialization_reject_before_mutation(self) -> None:
        self.write_duplicate('{"operation_id":"trusted","operation_id":"forged","phase":"FINALIZED"}')
        instance = Instance(self.journal)
        with self.assertRaises(extracts.StartupError):
            extracts.lineage_read_terminal_journal(instance)
        self.assertEqual([], self.mutations)
        with self.assertRaises(extracts.StartupError):
            extracts.materialize_terminal_lineage(instance)
        self.assertEqual([], self.mutations)

    def test_parser_bypass_is_mutation_effective(self) -> None:
        content = '{"phase":"READY","phase":"PREPARING","operation_id":"op"}'
        self.journal.write_text(content, encoding="utf-8")
        extracts.read_strict_json_object = lambda path: json.loads(path.read_text(encoding="utf-8"))
        active = self.temp / "active"
        staged = self.temp / "staged"
        rollback = self.temp / "rollback"
        active.mkdir()
        staged.mkdir()
        snapshot = self.temp / "snapshot"
        extracts._validated_preparing_paths = lambda *args: ("op", active, staged, rollback, snapshot)
        extracts.stable_failed_root = lambda *args: self.temp / "failed"
        result = extracts.staging_reconcile_interrupted_staging(self.settings, recovery_lock=Lock())
        self.assertTrue(result)
        self.assertIn("durable_replace", self.mutations)
        self.assertIn("atomic_write_json", self.mutations)


class SnapshotIdentityTests(unittest.TestCase):
    def test_target_identity_and_blob_set(self) -> None:
        snapshot = json.loads((TARGET / "SOURCE_SNAPSHOT.json").read_text(encoding="utf-8"))
        self.assertEqual("42c72f37d3e17f2ad51ec16c867acdfdf1458dc9", snapshot["target_commit"])
        self.assertEqual(7, len(snapshot["git_blobs"]))
        for blob in snapshot["git_blobs"].values():
            self.assertRegex(blob, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
