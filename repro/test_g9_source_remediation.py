from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from repro import g9_source_remediation as model


class PublicPayloadGuard(unittest.TestCase):
    def test_public_payload_is_bounded_and_synthetic(self) -> None:
        root = Path(__file__).resolve().parent
        self.assertEqual(
            {path.name for path in root.iterdir() if path.is_file()},
            {
                "__init__.py",
                "g9_source_remediation.py",
                "test_g9_source_remediation.py",
            },
        )
        content = "\n".join(
            path.read_text(encoding="utf-8")
            for path in root.iterdir()
            if path.is_file()
        )
        prohibited = (
            "1055" + "aeee",
            "bulletproofmedic/" + "animal-tracking",
            "SENSITIVE_" + "LOCATION",
            "RECOVERY_" + "SENSITIVE",
        )
        self.assertFalse(any(value.lower() in content.lower() for value in prohibited))


class CleanupBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="g9-cleanup-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_cleanup_uses_handle_or_fails_closed(self) -> None:
        destination = self.root / "support.zip"
        payload = b"exact archive"
        destination.write_bytes(payload)
        result = model.result_for(destination, payload)
        claim = model.cleanup_claim_path(result)

        if os.name == "nt":
            model.unlink_exact_result(result)
            self.assertFalse(destination.exists())
            self.assertFalse(claim.exists())
        else:
            with self.assertRaisesRegex(RuntimeError, "unavailable on this platform"):
                model.unlink_exact_result(result)
            self.assertFalse(destination.exists())
            self.assertEqual(claim.read_bytes(), payload)

    def test_replacement_before_open_is_preserved_without_restoration(self) -> None:
        destination = self.root / "support.zip"
        displaced = self.root / "displaced.zip"
        exact_payload = b"exact archive"
        replacement_payload = b"replacement archive"
        destination.write_bytes(exact_payload)
        result = model.result_for(destination, exact_payload)
        claim = model.cleanup_claim_path(result)

        def replace_before_open(path: Path) -> None:
            os.replace(path, displaced)
            path.write_bytes(replacement_payload)

        with self.assertRaisesRegex(RuntimeError, "exact identity"):
            model.unlink_exact_result(result, before_open=replace_before_open)

        self.assertFalse(destination.exists())
        self.assertEqual(claim.read_bytes(), replacement_payload)
        self.assertEqual(displaced.read_bytes(), exact_payload)

    def test_replacement_before_delete_is_never_deleted(self) -> None:
        destination = self.root / "support.zip"
        displaced = self.root / "displaced.zip"
        exact_payload = b"exact archive"
        replacement_payload = b"replacement archive"
        destination.write_bytes(exact_payload)
        result = model.result_for(destination, exact_payload)
        claim = model.cleanup_claim_path(result)

        def replace_before_delete(path: Path) -> None:
            os.replace(path, displaced)
            path.write_bytes(replacement_payload)

        if os.name == "nt":
            model.unlink_exact_result(result, before_delete=replace_before_delete)
            self.assertFalse(displaced.exists())
        else:
            with self.assertRaisesRegex(RuntimeError, "path changed"):
                model.unlink_exact_result(result, before_delete=replace_before_delete)
            self.assertEqual(displaced.read_bytes(), exact_payload)

        self.assertFalse(destination.exists())
        self.assertEqual(claim.read_bytes(), replacement_payload)

    def test_marker_replacement_is_never_deleted(self) -> None:
        marker = self.root / "cleanup-marker.json"
        displaced = self.root / "displaced-marker.json"
        exact = b'{"state":"exact"}\n'
        replacement = b'{"state":"replacement"}\n'
        marker.write_bytes(exact)

        def replace_before_delete(path: Path) -> None:
            os.replace(path, displaced)
            path.write_bytes(replacement)

        if os.name == "nt":
            model.delete_exact_marker(
                marker,
                exact,
                before_delete=replace_before_delete,
            )
            self.assertFalse(displaced.exists())
        else:
            with self.assertRaisesRegex(RuntimeError, "path changed"):
                model.delete_exact_marker(
                    marker,
                    exact,
                    before_delete=replace_before_delete,
                )
            self.assertEqual(displaced.read_bytes(), exact)

        self.assertEqual(marker.read_bytes(), replacement)


@unittest.skipUnless(os.name == "nt", "Supported-Windows exact-code diagnostic")
class WindowsAcknowledgementTests(unittest.TestCase):
    def setUp(self) -> None:
        model.POWERSHELL_INVOCATIONS = 0
        model._PROTECTED_IDENTITIES.clear()
        self.temporary = tempfile.TemporaryDirectory(prefix="g9-events-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _percentile(values: list[float], proportion: float) -> float:
        ordered = sorted(values)
        return ordered[max(0, int(len(ordered) * proportion) - 1)]

    def test_complete_path_meets_budget_without_event_loss(self) -> None:
        path = self.root / "events.log"
        logger = model.SyntheticEventLogger(
            path,
            max_bytes=10 * 1024 * 1024,
            backup_count=9,
        )
        setup_process_starts = model.POWERSHELL_INVOCATIONS
        workers = model.ACKNOWLEDGEMENT_BUDGETS[
            "supported_windows_concurrent_workers"
        ]
        calls = 800

        def emit(index: int) -> float:
            started = time.perf_counter()
            logger.emit(f"{index:032x}")
            return (time.perf_counter() - started) * 1000.0

        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                latencies = list(executor.map(emit, range(calls)))
            paths = model.log_paths(path)
            records = model.read_event_records(paths)
            p95 = self._percentile(latencies, 0.95)
            p99 = self._percentile(latencies, 0.99)
            self.assertEqual(model.POWERSHELL_INVOCATIONS, setup_process_starts)
            self.assertEqual(len(records), calls)
            self.assertEqual(
                len({str(record["correlation_id"]) for record in records}),
                calls,
            )
            self.assertEqual(len({str(record["record_id"]) for record in records}), calls)
            self.assertLessEqual(
                p95,
                model.ACKNOWLEDGEMENT_BUDGETS[
                    "supported_windows_p95_latency_ms"
                ],
            )
            self.assertLessEqual(
                p99,
                model.ACKNOWLEDGEMENT_BUDGETS[
                    "supported_windows_p99_latency_ms"
                ],
            )
            print(
                json.dumps(
                    {
                        "scenario": "complete_acknowledgement_load",
                        "workers": workers,
                        "calls": calls,
                        "failures": 0,
                        "event_count": len(records),
                        "median_ms": round(statistics.median(latencies), 3),
                        "p95_ms": round(p95, 3),
                        "p99_ms": round(p99, 3),
                        "bytes_read": sum(item.stat().st_size for item in paths),
                        "setup_process_starts": setup_process_starts,
                        "steady_state_process_starts": (
                            model.POWERSHELL_INVOCATIONS - setup_process_starts
                        ),
                    },
                    sort_keys=True,
                )
            )
        finally:
            logger.close()

    def test_near_limit_rollover_preserves_exact_acknowledgement(self) -> None:
        path = self.root / "events.log"
        logger = model.SyntheticEventLogger(
            path,
            max_bytes=10 * 1024 * 1024,
            backup_count=9,
        )
        try:
            stream = logger.handler.stream
            self.assertIsNotNone(stream)
            assert stream is not None
            logger.handler.flush()
            current_size = os.fstat(stream.fileno()).st_size
            filler_size = logger.handler.maxBytes - current_size - 64
            prefix = '{"padding":"'
            suffix = '"}\n'
            self.assertGreater(filler_size, len(prefix) + len(suffix))
            stream.write(
                prefix
                + "x" * (filler_size - len(prefix) - len(suffix))
                + suffix
            )
            logger.handler.flush()
            os.fsync(stream.fileno())

            logger.emit("f" * 32)

            paths = model.log_paths(path)
            records = model.read_event_records(paths)
            matching = [
                record
                for record in records
                if record.get("correlation_id") == "f" * 32
            ]
            self.assertTrue(path.with_name("events.log.1").is_file())
            self.assertEqual(len(matching), 1)
            print(
                json.dumps(
                    {
                        "scenario": "near_limit_rollover",
                        "event_count": len(matching),
                        "bytes_read": sum(item.stat().st_size for item in paths),
                        "rollover": True,
                    },
                    sort_keys=True,
                )
            )
        finally:
            logger.close()

    def test_acl_drift_fails_closed(self) -> None:
        path = self.root / "events.log"
        logger = model.SyntheticEventLogger(
            path,
            max_bytes=10 * 1024 * 1024,
            backup_count=9,
        )
        try:
            model.drift_windows_acl(path)
            with self.assertRaisesRegex(PermissionError, "ACL drift"):
                logger.emit("e" * 32)
        finally:
            logger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
