from __future__ import annotations

import inspect
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

ROSTER_VERSION = 1
RECORD_KEYS = {
    "finalizer_id",
    "finalizer_version",
    "attempt",
    "outcome",
    "restart_result",
    "stable_error_code",
    "safe_error_detail",
    "recorded_at",
}
OUTCOMES = {"RUNNING", "SUCCESS", "FAILED", "SKIPPED_ALREADY_SUCCESSFUL"}
RECORDED_AT = "2026-07-29T12:00:00Z"


class ControlError(RuntimeError):
    pass


@dataclass
class Finalizer:
    finalizer_id: str
    finalizer_version: str
    fail: bool = False
    calls: list[tuple[int, str]] = field(default_factory=list)

    def run(self, attempt: int, restart_result: str) -> None:
        self.calls.append((attempt, restart_result))
        if self.fail:
            raise RuntimeError("synthetic failure")


def record(
    *,
    finalizer_id: str = "analysis-source-state",
    finalizer_version: str = "1.0",
    attempt: object = 1,
    outcome: str = "RUNNING",
    restart_result: str = "FIRST_ATTEMPT",
    stable_error_code: str = "",
    safe_error_detail: str = "",
) -> dict[str, object]:
    return {
        "finalizer_id": finalizer_id,
        "finalizer_version": finalizer_version,
        "attempt": attempt,
        "outcome": outcome,
        "restart_result": restart_result,
        "stable_error_code": stable_error_code,
        "safe_error_detail": safe_error_detail,
        "recorded_at": RECORDED_AT,
    }


def canonical_roster(registry: tuple[Finalizer, ...]) -> tuple[tuple[str, str], ...]:
    roster = tuple(sorted((row.finalizer_id, row.finalizer_version) for row in registry))
    if any(not identity or not version for identity, version in roster):
        raise ControlError("empty identity")
    if len({identity for identity, _version in roster}) != len(roster):
        raise ControlError("duplicate identity")
    return roster


def stage_restore(registry: tuple[Finalizer, ...]) -> dict[str, object]:
    roster = canonical_roster(registry)
    return {
        "phase": "ACTIVATED_PENDING_PREFLIGHT",
        "post_restore_finalizer_roster_version": ROSTER_VERSION,
        "required_post_restore_finalizers": [
            {"finalizer_id": identity, "finalizer_version": version}
            for identity, version in roster
        ],
        "post_restore_finalizers": [],
    }


def required_roster(journal: dict[str, object]) -> tuple[tuple[str, str], ...]:
    version = journal.get("post_restore_finalizer_roster_version")
    if type(version) is not int or version != ROSTER_VERSION:
        raise ControlError("unsupported roster version")
    raw = journal.get("required_post_restore_finalizers")
    if not isinstance(raw, list):
        raise ControlError("malformed roster")
    roster: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in raw:
        if not isinstance(row, dict) or set(row) != {"finalizer_id", "finalizer_version"}:
            raise ControlError("malformed roster row")
        identity = row["finalizer_id"]
        version_text = row["finalizer_version"]
        if not isinstance(identity, str) or not identity:
            raise ControlError("malformed roster identity")
        if not isinstance(version_text, str) or not version_text:
            raise ControlError("malformed roster version")
        if identity in seen:
            raise ControlError("duplicate roster identity")
        seen.add(identity)
        roster.append((identity, version_text))
    if roster != sorted(roster):
        raise ControlError("noncanonical roster")
    return tuple(roster)


def validate_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ControlError("malformed timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ControlError("malformed timestamp")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ControlError("noncanonical timestamp")


def validate_history(
    roster: tuple[tuple[str, str], ...],
    history: object,
) -> list[dict[str, object]]:
    if not isinstance(history, list):
        raise ControlError("malformed history")
    roster_set = set(roster)
    last_attempt = {identity: 0 for identity in roster}
    last_outcome: dict[tuple[str, str], str | None] = {identity: None for identity in roster}
    open_attempt: dict[tuple[str, str], int | None] = {identity: None for identity in roster}
    success_attempt: dict[tuple[str, str], int | None] = {identity: None for identity in roster}
    restart_by_attempt: dict[tuple[tuple[str, str], int], str] = {}
    validated: list[dict[str, object]] = []

    for raw in history:
        if not isinstance(raw, dict) or set(raw) != RECORD_KEYS:
            raise ControlError("malformed record schema")
        identity_value = raw["finalizer_id"]
        version_value = raw["finalizer_version"]
        if not isinstance(identity_value, str) or not isinstance(version_value, str):
            raise ControlError("malformed record identity")
        identity = (identity_value, version_value)
        if identity not in roster_set:
            raise ControlError("record outside staged roster")
        attempt_value = raw["attempt"]
        if type(attempt_value) is not int or attempt_value < 1:
            raise ControlError("malformed attempt")
        attempt = attempt_value
        outcome = raw["outcome"]
        restart_result = raw["restart_result"]
        stable_error = raw["stable_error_code"]
        safe_detail = raw["safe_error_detail"]
        if outcome not in OUTCOMES:
            raise ControlError("unknown outcome")
        if not isinstance(restart_result, str) or not restart_result:
            raise ControlError("malformed restart result")
        if not isinstance(stable_error, str) or not isinstance(safe_detail, str):
            raise ControlError("malformed error fields")
        validate_timestamp(raw["recorded_at"])

        if outcome == "RUNNING":
            if success_attempt[identity] is not None:
                raise ControlError("new attempt after success")
            if attempt != last_attempt[identity] + 1:
                raise ControlError("attempt not monotonic")
            previous = last_outcome[identity]
            expected = "FIRST_ATTEMPT" if previous is None else f"RETRY_AFTER_{previous}"
            if restart_result != expected:
                raise ControlError("contradictory restart result")
            if stable_error or safe_detail:
                raise ControlError("running record has error data")
            last_attempt[identity] = attempt
            last_outcome[identity] = "RUNNING"
            open_attempt[identity] = attempt
            restart_by_attempt[(identity, attempt)] = restart_result
        elif outcome in {"SUCCESS", "FAILED"}:
            if open_attempt[identity] != attempt:
                raise ControlError("terminal without matching running")
            if restart_result != restart_by_attempt[(identity, attempt)]:
                raise ControlError("terminal restart mismatch")
            if outcome == "SUCCESS":
                if stable_error or safe_detail:
                    raise ControlError("success has error data")
                success_attempt[identity] = attempt
            elif not stable_error:
                raise ControlError("failure lacks stable code")
            open_attempt[identity] = None
            last_outcome[identity] = str(outcome)
        else:
            if success_attempt[identity] != attempt:
                raise ControlError("skip without success")
            if restart_result != "REPLAY_AFTER_SUCCESS" or stable_error or safe_detail:
                raise ControlError("malformed skip")
        validated.append(dict(raw))
    return validated


def append_record(
    history: list[dict[str, object]],
    finalizer: Finalizer,
    *,
    attempt: int,
    outcome: str,
    restart_result: str,
    stable_error_code: str = "",
    safe_error_detail: str = "",
) -> None:
    history.append(
        record(
            finalizer_id=finalizer.finalizer_id,
            finalizer_version=finalizer.finalizer_version,
            attempt=attempt,
            outcome=outcome,
            restart_result=restart_result,
            stable_error_code=stable_error_code,
            safe_error_detail=safe_error_detail,
        )
    )


def run_post_restore_finalizers(
    journal: dict[str, object],
    *,
    registry: tuple[Finalizer, ...],
) -> None:
    staged = required_roster(journal)
    actual = canonical_roster(registry)
    if actual != staged:
        raise ControlError("roster changed after staging")
    history = validate_history(staged, journal.get("post_restore_finalizers", []))
    for finalizer in sorted(registry, key=lambda row: (row.finalizer_id, row.finalizer_version)):
        matching = [
            row
            for row in history
            if row["finalizer_id"] == finalizer.finalizer_id
            and row["finalizer_version"] == finalizer.finalizer_version
        ]
        success = next((row for row in reversed(matching) if row["outcome"] == "SUCCESS"), None)
        if success is not None:
            append_record(
                history,
                finalizer,
                attempt=int(success["attempt"]),
                outcome="SKIPPED_ALREADY_SUCCESSFUL",
                restart_result="REPLAY_AFTER_SUCCESS",
            )
            continue
        previous_attempt = max((int(row["attempt"]) for row in matching), default=0)
        attempt = previous_attempt + 1
        restart_result = "FIRST_ATTEMPT"
        if matching:
            restart_result = f"RETRY_AFTER_{matching[-1]['outcome']}"
        append_record(
            history,
            finalizer,
            attempt=attempt,
            outcome="RUNNING",
            restart_result=restart_result,
        )
        try:
            finalizer.run(attempt, restart_result)
        except RuntimeError:
            append_record(
                history,
                finalizer,
                attempt=attempt,
                outcome="FAILED",
                restart_result=restart_result,
                stable_error_code="POST_RESTORE_FINALIZER_FAILED",
                safe_error_detail="RuntimeError",
            )
            journal["post_restore_finalizers"] = history
            raise ControlError("finalizer failed")
        append_record(
            history,
            finalizer,
            attempt=attempt,
            outcome="SUCCESS",
            restart_result=restart_result,
        )
    journal["post_restore_finalizers"] = history


def normal_launcher(journal: dict[str, object], registry: tuple[Finalizer, ...]) -> None:
    run_post_restore_finalizers(journal, registry=registry)


class PostRestoreHistoryControls(unittest.TestCase):
    def setUp(self) -> None:
        self.finalizer = Finalizer("analysis-source-state", "1.0")
        self.registry = (self.finalizer,)
        self.journal = stage_restore(self.registry)

    def assertRejected(self, history: list[dict[str, object]]) -> None:
        self.journal["post_restore_finalizers"] = history
        with self.assertRaises(ControlError):
            normal_launcher(self.journal, self.registry)
        self.assertEqual(self.finalizer.calls, [])

    def test_normal_launcher_executes_exact_staged_roster(self) -> None:
        normal_launcher(self.journal, self.registry)
        self.assertEqual(self.finalizer.calls, [(1, "FIRST_ATTEMPT")])
        self.assertEqual(
            [row["outcome"] for row in self.journal["post_restore_finalizers"]],
            ["RUNNING", "SUCCESS"],
        )

    def test_replay_skips_after_legal_success(self) -> None:
        normal_launcher(self.journal, self.registry)
        normal_launcher(self.journal, self.registry)
        self.assertEqual(len(self.finalizer.calls), 1)
        self.assertEqual(self.journal["post_restore_finalizers"][-1]["outcome"], "SKIPPED_ALREADY_SUCCESSFUL")

    def test_interrupted_running_attempt_retries(self) -> None:
        self.journal["post_restore_finalizers"] = [record()]
        normal_launcher(self.journal, self.registry)
        self.assertEqual(self.finalizer.calls, [(2, "RETRY_AFTER_RUNNING")])

    def test_failed_attempt_retries(self) -> None:
        self.journal["post_restore_finalizers"] = [
            record(),
            record(
                outcome="FAILED",
                stable_error_code="POST_RESTORE_FINALIZER_FAILED",
                safe_error_detail="RuntimeError",
            ),
        ]
        normal_launcher(self.journal, self.registry)
        self.assertEqual(self.finalizer.calls, [(2, "RETRY_AFTER_FAILED")])

    def test_runtime_roster_drift_fails_before_execution(self) -> None:
        drifted = (Finalizer("analysis-source-state", "2.0"),)
        with self.assertRaises(ControlError):
            normal_launcher(self.journal, drifted)
        self.assertEqual(drifted[0].calls, [])

    def test_public_interface_has_no_finalizer_override(self) -> None:
        self.assertNotIn("finalizers", inspect.signature(run_post_restore_finalizers).parameters)

    def test_roster_version_rejects_noncanonical_scalars(self) -> None:
        for value in (True, False, 1.0, 0, "1", None, 2, 2**63):
            with self.subTest(value=value):
                journal = stage_restore(())
                journal["post_restore_finalizer_roster_version"] = value
                with self.assertRaises(ControlError):
                    normal_launcher(journal, ())

    def test_orphan_success_rejected(self) -> None:
        self.assertRejected([record(outcome="SUCCESS")])

    def test_success_after_failed_rejected(self) -> None:
        self.assertRejected([
            record(),
            record(
                outcome="FAILED",
                stable_error_code="POST_RESTORE_FINALIZER_FAILED",
                safe_error_detail="RuntimeError",
            ),
            record(outcome="SUCCESS"),
        ])

    def test_duplicate_terminal_rejected(self) -> None:
        self.assertRejected([record(), record(outcome="SUCCESS"), record(outcome="SUCCESS")])

    def test_attempt_zero_rejected(self) -> None:
        self.assertRejected([record(attempt=0)])

    def test_missing_field_rejected(self) -> None:
        malformed = record()
        malformed.pop("recorded_at")
        self.assertRejected([malformed])

    def test_unknown_outcome_rejected(self) -> None:
        self.assertRejected([record(outcome="UNKNOWN")])

    def test_cross_version_record_rejected(self) -> None:
        self.assertRejected([record(finalizer_version="2.0")])

    def test_attempt_after_success_rejected(self) -> None:
        self.assertRejected([
            record(),
            record(outcome="SUCCESS"),
            record(attempt=2, outcome="RUNNING", restart_result="RETRY_AFTER_SUCCESS"),
        ])

    def test_record_outside_roster_rejected(self) -> None:
        self.assertRejected([record(finalizer_id="unexpected")])

    def test_attempt_gap_rejected(self) -> None:
        self.assertRejected([record(attempt=2)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
