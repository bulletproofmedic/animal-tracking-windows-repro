from __future__ import annotations

import unittest

from repro.analysis_reproducer import (
    CHECKPOINT_INTERVAL,
    Checkpoints,
    Event,
    Measure,
    Observation,
    candidate_observation_index,
    candidate_rate_numerator,
    legacy_observation_index,
    legacy_rate_numerator,
    normalized_rate,
)


class NeverCancel:
    def raise_if_cancelled(self) -> None:
        return


class CancelOnCall:
    def __init__(self, call_number: int) -> None:
        self.call_number = call_number
        self.calls = 0

    def raise_if_cancelled(self) -> None:
        self.calls += 1
        if self.calls >= self.call_number:
            raise RuntimeError("synthetic cancellation")


class RatePermissionTests(unittest.TestCase):
    def test_negative_control_exposes_rate_only_defect(self) -> None:
        events = (Event(1, (Measure.RATE,)),)
        checkpoints = Checkpoints(NeverCancel())
        self.assertEqual(legacy_rate_numerator(events, checkpoints), 0)

    def test_candidate_counts_rate_only_event(self) -> None:
        events = (Event(1, (Measure.RATE,)),)
        checkpoints = Checkpoints(NeverCancel())
        self.assertEqual(candidate_rate_numerator(events, checkpoints), 1)
        self.assertEqual(normalized_rate(events, 86_400, Checkpoints(NeverCancel())), 100)

    def test_candidate_does_not_promote_event_only_permission(self) -> None:
        events = (Event(1, (Measure.EVENT,)),)
        checkpoints = Checkpoints(NeverCancel())
        self.assertEqual(candidate_rate_numerator(events, checkpoints), 0)

    def test_mixed_permissions_use_only_rate_eligible_events(self) -> None:
        events = (
            Event(1, (Measure.EVENT,)),
            Event(2, (Measure.RATE,)),
            Event(3, (Measure.EVENT, Measure.RATE)),
        )
        self.assertEqual(
            normalized_rate(events, 2 * 86_400, Checkpoints(NeverCancel())),
            100,
        )


class CancellationTests(unittest.TestCase):
    @staticmethod
    def observations(count: int = 300) -> tuple[Observation, ...]:
        return tuple(
            Observation(observation_id=index, event_id=index % 7)
            for index in range(count, 0, -1)
        )

    def test_negative_control_finishes_without_inner_checkpoint(self) -> None:
        token = CancelOnCall(2)
        checkpoints = Checkpoints(token)
        checkpoints.check()
        result = legacy_observation_index(self.observations(), checkpoints)
        self.assertEqual(token.calls, 1)
        self.assertEqual(checkpoints.processed_rows, 300)
        self.assertEqual(sum(len(rows) for rows in result.values()), 300)

    def test_candidate_cancels_during_observation_preprocessing(self) -> None:
        token = CancelOnCall(2)
        checkpoints = Checkpoints(token)
        checkpoints.check()
        with self.assertRaisesRegex(RuntimeError, "synthetic cancellation"):
            candidate_observation_index(self.observations(), checkpoints)
        self.assertEqual(token.calls, 2)
        self.assertEqual(checkpoints.processed_rows, CHECKPOINT_INTERVAL)

    def test_candidate_cancels_during_bounded_sorting(self) -> None:
        token = CancelOnCall(3)
        checkpoints = Checkpoints(token)
        checkpoints.check()
        with self.assertRaisesRegex(RuntimeError, "synthetic cancellation"):
            checkpoints.sorted_values(range(300, 0, -1), key=lambda value: value)
        self.assertEqual(token.calls, 3)
        self.assertLess(checkpoints.processed_rows, 300)

    def test_candidate_index_is_deterministic_and_sorted(self) -> None:
        first = candidate_observation_index(
            self.observations(),
            Checkpoints(NeverCancel()),
        )
        second = candidate_observation_index(
            tuple(reversed(self.observations())),
            Checkpoints(NeverCancel()),
        )
        self.assertEqual(first, second)
        self.assertEqual(tuple(first), tuple(sorted(first)))
        for rows in first.values():
            self.assertEqual(
                tuple(row.observation_id for row in rows),
                tuple(sorted(row.observation_id for row in rows)),
            )


if __name__ == "__main__":
    unittest.main()
