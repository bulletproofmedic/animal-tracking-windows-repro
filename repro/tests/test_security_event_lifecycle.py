from __future__ import annotations

import json
import logging
import math
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_event_lifecycle import (  # noqa: E402
    BOOTSTRAP_BACKUP_COUNT,
    Details,
    EventCode,
    Operation,
    Outcome,
    ReasonCode,
    SecurityLifecycle,
    Stage,
    create_support_candidate,
    reject_csrf,
    reject_host,
    reject_origin,
    run_startup,
)


def read_events(*paths: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line:
                events.append(json.loads(line))
    return events


class SecurityEventLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-security-events-")
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(logging.shutdown)
        self.root = Path(self.temporary.name) / "synthetic-data"
        self.lifecycle = SecurityLifecycle(self.root)

    def test_minimum_logger_precedes_settings_and_recovery(self) -> None:
        calls: list[str] = []

        def settings() -> None:
            self.assertEqual(self.lifecycle.stage, Stage.MINIMUM)
            self.assertTrue(self.lifecycle.bootstrap_path.is_file())
            calls.append("settings")

        def recovery() -> None:
            self.assertEqual(self.lifecycle.stage, Stage.MINIMUM)
            calls.append("recovery")

        run_startup(self.lifecycle, load_settings=settings, apply_recovery=recovery)

        self.assertEqual(calls, ["settings", "recovery"])
        self.assertEqual(self.lifecycle.stage, Stage.COMPLETE)
        self.assertTrue(self.lifecycle.complete_path.is_file())

    def test_transition_retains_bootstrap_events_without_replay(self) -> None:
        self.lifecycle.initialize_minimum()
        reject_host(self.lifecycle, "synthetic.invalid:8765")
        self.lifecycle.transition_complete()

        bootstrap = read_events(*self.lifecycle.bootstrap_paths())
        complete = read_events(self.lifecycle.complete_path)
        bootstrap_codes = [event["event_code"] for event in bootstrap]
        complete_codes = [event["event_code"] for event in complete]

        self.assertEqual(
            bootstrap_codes,
            [EventCode.LOGGER_MINIMUM_READY.value, EventCode.HOST_REJECTED.value],
        )
        self.assertEqual(complete_codes, [EventCode.LOGGER_COMPLETE_READY.value])
        self.assertTrue(set(bootstrap_codes).isdisjoint(complete_codes))

    def test_rejection_events_discard_request_controlled_values(self) -> None:
        self.lifecycle.initialize_minimum()
        reject_host(self.lifecycle, "private-host.invalid:8765")
        reject_origin(self.lifecycle, "https://private-origin.invalid/sensitive")
        reject_csrf(self.lifecycle, "token=private-value from C:/synthetic/private.txt")

        text = "\n".join(path.read_text(encoding="utf-8") for path in self.lifecycle.bootstrap_paths())
        for forbidden in (
            "private-host.invalid",
            "private-origin.invalid",
            "private-value",
            "C:/synthetic/private.txt",
        ):
            self.assertNotIn(forbidden, text)

        codes = [event["event_code"] for event in read_events(*self.lifecycle.bootstrap_paths())]
        self.assertEqual(
            codes,
            [
                EventCode.LOGGER_MINIMUM_READY.value,
                EventCode.HOST_REJECTED.value,
                EventCode.ORIGIN_REJECTED.value,
                EventCode.CSRF_REJECTED.value,
            ],
        )

    def test_failed_complete_transition_records_unavailable_control_in_minimum_journal(self) -> None:
        self.lifecycle.initialize_minimum()

        with self.assertRaisesRegex(RuntimeError, "synthetic complete logger failure"):
            self.lifecycle.transition_complete(fail=True)

        self.assertEqual(self.lifecycle.stage, Stage.MINIMUM)
        codes = [event["event_code"] for event in read_events(*self.lifecycle.bootstrap_paths())]
        self.assertEqual(
            codes,
            [EventCode.LOGGER_MINIMUM_READY.value, EventCode.CONTROL_UNAVAILABLE.value],
        )
        self.assertFalse(self.lifecycle.complete_path.exists())

    def test_support_candidate_requires_complete_logger(self) -> None:
        self.lifecycle.initialize_minimum()

        with self.assertRaisesRegex(RuntimeError, "complete logger is required"):
            create_support_candidate(
                self.lifecycle,
                source_count=1,
                member_count=4,
                byte_count=1024,
            )

        codes = [event["event_code"] for event in read_events(*self.lifecycle.bootstrap_paths())]
        self.assertEqual(codes[-1], EventCode.CONTROL_UNAVAILABLE.value)

    def test_support_success_includes_bootstrap_journal_and_bounded_events(self) -> None:
        self.lifecycle.initialize_minimum()
        reject_host(self.lifecycle, "synthetic.invalid")
        self.lifecycle.transition_complete()

        bootstrap = create_support_candidate(
            self.lifecycle,
            source_count=2,
            member_count=4,
            byte_count=4096,
        )

        self.assertEqual(bootstrap, self.lifecycle.bootstrap_paths())
        self.assertGreaterEqual(len(bootstrap), 1)
        complete = read_events(self.lifecycle.complete_path)
        codes = [event["event_code"] for event in complete]
        self.assertEqual(
            codes,
            [
                EventCode.LOGGER_COMPLETE_READY.value,
                EventCode.SUPPORT_CREATE_STARTED.value,
                EventCode.SUPPORT_DISCLOSURE_RECORDED.value,
                EventCode.CONTROL_DEGRADED.value,
                EventCode.SUPPORT_CREATE_SUCCEEDED.value,
            ],
        )
        success_fields = complete[-1]["fields"]
        self.assertEqual(success_fields["member_count"], 4 + len(bootstrap))
        self.assertEqual(success_fields["byte_count"], 4096)
        self.assertNotIn("path", success_fields)
        self.assertNotIn("reviewer", success_fields)

    def test_support_rejection_records_fixed_events_without_raw_details(self) -> None:
        self.lifecycle.initialize_minimum()
        self.lifecycle.transition_complete()

        with self.assertRaisesRegex(ValueError, "synthetic disclosure rejection"):
            create_support_candidate(
                self.lifecycle,
                source_count=1,
                member_count=2,
                byte_count=512,
                reject=True,
            )

        complete = read_events(self.lifecycle.complete_path)
        self.assertEqual(
            [event["event_code"] for event in complete[-3:]],
            [
                EventCode.SUPPORT_CREATE_STARTED.value,
                EventCode.SUPPORT_DISCLOSURE_REJECTED.value,
                EventCode.SUPPORT_CREATE_FAILED.value,
            ],
        )

    def test_permission_failure_is_bounded_and_recorded_once_per_category(self) -> None:
        def fail_settings() -> None:
            raise PermissionError("C:/synthetic/private-settings.json")

        with self.assertRaises(PermissionError):
            run_startup(
                self.lifecycle,
                load_settings=fail_settings,
                apply_recovery=lambda: None,
            )

        text = "\n".join(path.read_text(encoding="utf-8") for path in self.lifecycle.bootstrap_paths())
        self.assertNotIn("private-settings.json", text)
        codes = [event["event_code"] for event in read_events(*self.lifecycle.bootstrap_paths())]
        self.assertEqual(codes.count(EventCode.PERMISSION_FAILED.value), 1)
        self.assertEqual(codes.count(EventCode.STARTUP_FAILED.value), 1)

    def test_details_reject_negative_and_non_finite_values(self) -> None:
        with self.assertRaises(ValueError):
            Details(Operation.SUPPORT, Outcome.SUCCEEDED, byte_count=-1).as_fields()
        with self.assertRaises(ValueError):
            Details(Operation.SUPPORT, Outcome.SUCCEEDED, duration_ms=math.inf).as_fields()
        with self.assertRaises(ValueError):
            Details(Operation.SUPPORT, Outcome.SUCCEEDED, duration_ms=math.nan).as_fields()

    def test_bootstrap_rotation_is_bounded(self) -> None:
        self.lifecycle.initialize_minimum()
        for _ in range(300):
            reject_host(self.lifecycle, "ignored.invalid")

        paths = self.lifecycle.bootstrap_paths()
        self.assertLessEqual(len(paths), BOOTSTRAP_BACKUP_COUNT + 1)
        self.assertTrue(all(path.stat().st_size > 0 for path in paths))

    def test_event_schema_is_closed(self) -> None:
        self.lifecycle.initialize_minimum()
        reject_host(self.lifecycle, "ignored.invalid")

        allowed_top = {
            "timestamp",
            "severity",
            "event_code",
            "component",
            "message",
            "record_id",
            "fields",
        }
        allowed_fields = {
            "operation",
            "outcome",
            "reason_code",
            "status",
            "file_count",
            "member_count",
            "byte_count",
            "duration_ms",
            "enabled",
        }
        for event in read_events(*self.lifecycle.bootstrap_paths()):
            self.assertEqual(set(event), allowed_top)
            self.assertLessEqual(set(event["fields"]), allowed_fields)


if __name__ == "__main__":
    unittest.main()
