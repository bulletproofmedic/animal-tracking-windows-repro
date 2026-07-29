from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repro.g4_security_controls import (
    SECURITY_BUNDLE_MAX_LOG_FILES,
    SECURITY_BUNDLE_MAX_TOTAL_LOG_BYTES,
    DurableEventSink,
    SinkError,
    SinkStage,
    is_loopback_origin,
    mutation_allowed,
)


class OriginBoundaryTests(unittest.TestCase):
    def test_same_origin_values_pass(self) -> None:
        for value in (
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://[::1]:8765/form",
        ):
            with self.subTest(value=value):
                self.assertTrue(is_loopback_origin(value, expected_port=8765))

    def test_missing_empty_malformed_and_out_of_range_values_fail(self) -> None:
        for value in (
            "",
            "   ",
            "http://127.0.0.1:bad",
            "http://127.0.0.1:99999",
            "http://user@127.0.0.1:8765",
            "https://127.0.0.1:8765",
            "http://example.invalid:8765",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_loopback_origin(value, expected_port=8765))

    def test_every_mutation_requires_valid_provenance(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertFalse(
                    mutation_allowed(
                        method,
                        origin=None,
                        referer=None,
                        expected_port=8765,
                    )
                )
                self.assertTrue(
                    mutation_allowed(
                        method,
                        origin="http://127.0.0.1:8765",
                        referer=None,
                        expected_port=8765,
                    )
                )


class DurableSinkTests(unittest.TestCase):
    def test_successful_related_events_share_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sink = DurableEventSink(Path(temporary) / "events.jsonl")
            correlation_id = "a" * 32
            first = sink.emit("SEC_RECOVERY_ACTIVATION_FAILED", correlation_id=correlation_id)
            second = sink.emit("SEC_STARTUP_FAILED", correlation_id=correlation_id)
            self.assertNotEqual(first, second)
            text = sink.path.read_text(encoding="utf-8")
            self.assertEqual(text.count(correlation_id), 2)
            self.assertEqual(sink.stage, SinkStage.COMPLETE)

    def test_write_flush_fsync_path_and_acl_failures_fail_closed(self) -> None:
        for failure in ("write", "flush", "fsync", "path_replacement", "acl"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                sink = DurableEventSink(Path(temporary) / "events.jsonl")
                with self.assertRaises(SinkError):
                    sink.emit("SEC_INTEGRITY_FAILED", correlation_id="b" * 32, fail=failure)
                self.assertEqual(sink.stage, SinkStage.UNAVAILABLE)
                with self.assertRaises(SinkError):
                    sink.emit("SEC_STARTUP_FAILED", correlation_id="b" * 32)


class CapacityTests(unittest.TestCase):
    def test_complete_and_bootstrap_population_fits(self) -> None:
        self.assertEqual(SECURITY_BUNDLE_MAX_LOG_FILES, 10 + 2)
        self.assertEqual(SECURITY_BUNDLE_MAX_TOTAL_LOG_BYTES, (100 + 2) * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
