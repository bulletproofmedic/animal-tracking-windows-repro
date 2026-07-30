from __future__ import annotations

import copy
import unittest
from dataclasses import dataclass, field

_MAX_ATTEMPTS = 3
_MAX_RECORDS = 7
_RETRY_LIMIT_CODE = "POST_RESTORE_FINALIZER_RETRY_LIMIT_EXCEEDED"


class RetryStateError(RuntimeError):
    pass


@dataclass(slots=True)
class RetryModel:
    records: list[dict[str, object]] = field(default_factory=list)
    block: dict[str, object] | None = None
    calls: list[int] = field(default_factory=list)

    def _validate(self) -> None:
        if len(self.records) > _MAX_RECORDS:
            raise RetryStateError("history exceeds bounded limit")
        for row in self.records:
            attempt = row.get("attempt")
            if type(attempt) is not int or not 1 <= attempt <= _MAX_ATTEMPTS:
                raise RetryStateError("attempt exceeds retry ceiling")
        if self.block is not None:
            if self.block != {
                "attempt_count": 3,
                "stable_error_code": _RETRY_LIMIT_CODE,
            }:
                raise RetryStateError("malformed retry block")

    def run(self, *, fail: bool) -> str:
        self._validate()
        if self.block is not None:
            raise RetryStateError("explicit intervention required")

        success = next(
            (row for row in reversed(self.records) if row["outcome"] == "SUCCESS"),
            None,
        )
        if success is not None:
            if not any(row["outcome"] == "SKIPPED_ALREADY_SUCCESSFUL" for row in self.records):
                self.records.append(
                    {
                        "attempt": success["attempt"],
                        "outcome": "SKIPPED_ALREADY_SUCCESSFUL",
                    }
                )
            self._validate()
            return "SKIPPED"

        attempts = [int(row["attempt"]) for row in self.records]
        previous_attempt = max(attempts, default=0)
        if previous_attempt >= _MAX_ATTEMPTS:
            self.block = {
                "attempt_count": _MAX_ATTEMPTS,
                "stable_error_code": _RETRY_LIMIT_CODE,
            }
            raise RetryStateError("explicit intervention required")

        attempt = previous_attempt + 1
        self.records.append({"attempt": attempt, "outcome": "RUNNING"})
        self.calls.append(attempt)
        if fail:
            self.records.append({"attempt": attempt, "outcome": "FAILED"})
            raise RetryStateError("finalizer failed")
        self.records.append({"attempt": attempt, "outcome": "SUCCESS"})
        self._validate()
        return "SUCCESS"


class RetryBoundTests(unittest.TestCase):
    def test_three_failures_then_durable_block(self) -> None:
        model = RetryModel()
        for expected in (1, 2, 3):
            with self.assertRaisesRegex(RetryStateError, "finalizer failed"):
                model.run(fail=True)
            self.assertEqual(model.calls[-1], expected)
        self.assertEqual(len(model.records), 6)

        with self.assertRaisesRegex(RetryStateError, "explicit intervention"):
            model.run(fail=True)
        self.assertEqual(
            model.block,
            {"attempt_count": 3, "stable_error_code": _RETRY_LIMIT_CODE},
        )
        frozen = copy.deepcopy((model.records, model.block, model.calls))
        with self.assertRaisesRegex(RetryStateError, "explicit intervention"):
            model.run(fail=False)
        self.assertEqual((model.records, model.block, model.calls), frozen)

    def test_success_on_third_attempt_and_single_replay_marker(self) -> None:
        model = RetryModel()
        for _ in range(2):
            with self.assertRaisesRegex(RetryStateError, "finalizer failed"):
                model.run(fail=True)
        self.assertEqual(model.run(fail=False), "SUCCESS")
        self.assertEqual(model.calls, [1, 2, 3])
        self.assertIsNone(model.block)
        self.assertEqual(model.run(fail=False), "SKIPPED")
        frozen = copy.deepcopy(model.records)
        self.assertEqual(model.run(fail=False), "SKIPPED")
        self.assertEqual(model.records, frozen)
        self.assertEqual(len(model.records), 7)

    def test_oversized_history_is_rejected_before_execution(self) -> None:
        model = RetryModel(
            records=[{"attempt": 1, "outcome": "RUNNING"} for _ in range(8)]
        )
        with self.assertRaisesRegex(RetryStateError, "bounded limit"):
            model.run(fail=False)
        self.assertEqual(model.calls, [])

    def test_malformed_block_is_rejected_before_execution(self) -> None:
        model = RetryModel(
            block={"attempt_count": 2, "stable_error_code": _RETRY_LIMIT_CODE}
        )
        with self.assertRaisesRegex(RetryStateError, "malformed retry block"):
            model.run(fail=False)
        self.assertEqual(model.calls, [])


if __name__ == "__main__":
    unittest.main()
