from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from repro.failed_root_lifecycle import Lifecycle, Policy


class FailedRootLifecycleTests(unittest.TestCase):
    def test_count_byte_and_age_quotas_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Lifecycle(Path(directory))
            now = datetime(2026, 7, 29, tzinfo=UTC)
            ids = [str(uuid.uuid4()) for _ in range(4)]
            for operation_id, days, size in zip(ids, (20, 10, 2, 1), (7, 7, 7, 7), strict=True):
                lifecycle.create(operation_id, now - timedelta(days=days), size, "sensitive-location.bin")
            retained, disposed = lifecycle.reconcile(Policy(minimum=1, max_count=3, max_bytes=15, max_age_days=5), now)
            self.assertEqual(retained, set(ids[-2:]))
            self.assertEqual(disposed, set(ids[:2]))
            self.assertLessEqual(sum((lifecycle.failed / item / "sensitive-location.bin").stat().st_size for item in retained), 15)

    def test_current_authority_and_newest_forensic_root_are_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Lifecycle(Path(directory))
            now = datetime(2026, 7, 29, tzinfo=UTC)
            current, middle, newest = (str(uuid.uuid4()) for _ in range(3))
            lifecycle.create(current, now - timedelta(days=20), 5, "current.bin")
            lifecycle.create(middle, now - timedelta(days=10), 5, "middle.bin")
            lifecycle.create(newest, now - timedelta(days=1), 5, "newest.bin")
            retained, disposed = lifecycle.reconcile(Policy(minimum=1, max_count=1, max_bytes=5, max_age_days=1), now, protected={current})
            self.assertEqual(retained, {current, newest})
            self.assertEqual(disposed, {middle})

    def test_authority_guard_prevents_all_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Lifecycle(Path(directory))
            now = datetime(2026, 7, 29, tzinfo=UTC)
            ids = [str(uuid.uuid4()), str(uuid.uuid4())]
            for operation_id in ids:
                lifecycle.create(operation_id, now - timedelta(days=30), 20, "root.bin")
            retained, disposed = lifecycle.reconcile(Policy(minimum=1, max_count=1, max_bytes=1, max_age_days=1), now, authority_guarded=True)
            self.assertEqual(retained, set(ids))
            self.assertEqual(disposed, set())

    def test_restart_resumes_before_and_after_disposal_rename(self) -> None:
        for moved in (False, True):
            with self.subTest(moved=moved), tempfile.TemporaryDirectory() as directory:
                lifecycle = Lifecycle(Path(directory))
                now = datetime(2026, 7, 29, tzinfo=UTC)
                operation_id = str(uuid.uuid4())
                source = lifecycle.create(operation_id, now - timedelta(days=10), 9, "root.bin")
                metadata = lifecycle._read(operation_id)
                metadata["state"] = "DISPOSING"
                lifecycle._write(operation_id, metadata)
                if moved:
                    os.replace(source, lifecycle.disposal / operation_id)
                self.assertEqual(lifecycle.resume(now), 1)
                self.assertEqual(lifecycle.resume(now), 0)
                self.assertFalse(source.exists())
                self.assertFalse((lifecycle.disposal / operation_id).exists())
                self.assertEqual(lifecycle._read(operation_id)["state"], "DISPOSED")

    def test_export_requires_approval_and_metadata_is_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Lifecycle(Path(directory))
            now = datetime(2026, 7, 29, tzinfo=UTC)
            operation_id = str(uuid.uuid4())
            sensitive_name = "exact-coordinate-44.1234-media-secret.bin"
            lifecycle.create(operation_id, now, 11, sensitive_name)
            destination = Path(directory) / "approved.zip"
            with self.assertRaisesRegex(RuntimeError, "approval required"):
                lifecycle.export(operation_id, destination, approved=False)
            digest = lifecycle.export(operation_id, destination, approved=True)
            self.assertEqual(len(digest), 64)
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(archive.namelist(), [sensitive_name])
            metadata_text = lifecycle.metadata_path(operation_id).read_text(encoding="utf-8")
            self.assertNotIn(sensitive_name, metadata_text)
            self.assertNotIn("44.1234", metadata_text)
            metadata = json.loads(metadata_text)
            self.assertEqual(metadata["export_count"], 1)
            self.assertEqual(metadata["last_export_sha256"], digest)

    def test_reconciliation_is_idempotent_after_quota_disposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Lifecycle(Path(directory))
            now = datetime(2026, 7, 29, tzinfo=UTC)
            first = str(uuid.uuid4())
            second = str(uuid.uuid4())
            lifecycle.create(first, now - timedelta(days=2), 5, "one.bin")
            lifecycle.create(second, now - timedelta(days=1), 5, "two.bin")
            policy = Policy(minimum=1, max_count=1, max_bytes=5, max_age_days=365)
            retained_one, disposed_one = lifecycle.reconcile(policy, now)
            retained_two, disposed_two = lifecycle.reconcile(policy, now)
            self.assertEqual(retained_one, {second})
            self.assertEqual(disposed_one, {first})
            self.assertEqual(retained_two, {second})
            self.assertEqual(disposed_two, set())


if __name__ == "__main__":
    unittest.main()
