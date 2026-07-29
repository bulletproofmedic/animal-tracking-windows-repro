from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID

from repro.core_hardening_reproducer import (
    CHECKPOINT_INTERVAL,
    Cancelled,
    Checkpoints,
    Dataset,
    Disposition,
    Event,
    Exposure,
    ExposureDisposition,
    Measure,
    Observation,
    Repository,
    ResultColumn,
    ResultTable,
    RevisionedDimension,
    SelectionCounts,
    SourceState,
    Temporal,
    ValidationError,
    canonical_hash,
    normalized_rate,
)


def uid(value: int) -> UUID:
    return UUID(f"00000000-0000-7000-8000-{value:012d}")


def exact(day: int = 25, hour: int = 8) -> Temporal:
    return Temporal(
        "PARSED",
        "EXACT",
        datetime(2026, 7, day, hour),
        datetime(2026, 7, day, hour + 4, tzinfo=UTC),
        -14400,
    )


def dataset(*, reverse: bool = False) -> Dataset:
    deployment = RevisionedDimension(uid(30), 1)
    species = (
        RevisionedDimension(uid(60), 1),
        RevisionedDimension(uid(61), 1),
    )
    events = (
        Event(uid(10), 1, deployment.record_id, (Measure.RATE,)),
        Event(uid(11), 1, deployment.record_id, (Measure.RATE,)),
    )
    observations = (
        Observation(uid(50), 1, events[0].event_id, 1, species[0].record_id, 1),
        Observation(uid(51), 1, events[1].event_id, 1, species[1].record_id, 1),
    )
    exposure = Exposure(
        deployment.record_id,
        deployment.revision,
        exact(),
        exact(26),
        86400,
        0,
        0,
        0,
        86400,
        ExposureDisposition.USABLE,
    )
    if reverse:
        events = tuple(reversed(events))
        observations = tuple(reversed(observations))
        species = tuple(reversed(species))
    return Dataset(
        {"deployment_ids": [str(deployment.record_id)]},
        events,
        observations,
        (deployment,),
        species,
        (exposure,),
        SelectionCounts(4, 4, 0, 0),
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
            raise Cancelled("synthetic cancellation")


class ContractIdentityTests(unittest.TestCase):
    def test_legacy_mutable_alias_changes_hash(self) -> None:
        source = {"deployment_ids": [str(uid(30))]}
        before = canonical_hash(source)
        source["deployment_ids"].append(str(uid(31)))
        self.assertNotEqual(before, canonical_hash(source))

    def test_candidate_defensively_freezes_nested_values(self) -> None:
        source = {"deployment_ids": [str(uid(30))]}
        data = Dataset(
            source,
            dataset().events,
            dataset().observations,
            dataset().deployments,
            dataset().species,
            dataset().exposures,
            SelectionCounts(4, 4, 0, 0),
        )
        source["deployment_ids"].append(str(uid(31)))
        self.assertIsInstance(data.request_filter, MappingProxyType)
        self.assertEqual(tuple(data.request_filter["deployment_ids"]), (str(uid(30)),))
        with self.assertRaises(TypeError):
            data.request_filter["other"] = True

    def test_permutations_have_one_canonical_hash(self) -> None:
        first = dataset(reverse=False)
        second = dataset(reverse=True)
        self.assertEqual(first, second)
        self.assertEqual(canonical_hash(first), canonical_hash(second))

    def test_unknown_filter_key_is_rejected(self) -> None:
        baseline = dataset()
        with self.assertRaisesRegex(ValidationError, "unknown filter"):
            replace(baseline, request_filter={"invented": True})


class GraphValidationTests(unittest.TestCase):
    def test_wrong_event_revision_is_rejected(self) -> None:
        baseline = dataset()
        bad = replace(baseline.observations[0], event_revision=2)
        with self.assertRaisesRegex(ValidationError, "wrong event revision"):
            replace(baseline, observations=(bad, baseline.observations[1]))

    def test_missing_species_dimension_is_rejected(self) -> None:
        baseline = dataset()
        with self.assertRaisesRegex(ValidationError, "wrong species revision"):
            replace(baseline, species=baseline.species[1:])

    def test_missing_deployment_is_rejected(self) -> None:
        baseline = dataset()
        with self.assertRaisesRegex(ValidationError, "missing deployment"):
            replace(baseline, deployments=())

    def test_selection_count_mismatch_is_rejected(self) -> None:
        baseline = dataset()
        with self.assertRaisesRegex(ValidationError, "selection counts"):
            replace(baseline, counts=SelectionCounts(4, 3, 0, 1))


class TemporalExposureTests(unittest.TestCase):
    def test_exact_unresolved_time_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "parsed or corrected"):
            Temporal("UNRESOLVED", "EXACT")

    def test_offset_and_utc_must_reconcile(self) -> None:
        with self.assertRaisesRegex(ValidationError, "disagree"):
            Temporal(
                "PARSED",
                "EXACT",
                datetime(2026, 7, 25, 8),
                datetime(2026, 7, 25, 13, tzinfo=UTC),
                -14400,
            )

    def test_reversed_window_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "half-open"):
            Exposure(uid(30), 1, exact(26), exact(), 0, 0, 0, 0, 0, ExposureDisposition.UNUSABLE)

    def test_duration_components_must_reconcile(self) -> None:
        with self.assertRaisesRegex(ValidationError, "do not reconcile"):
            Exposure(uid(30), 1, exact(), exact(26), 1, 0, 0, 0, 1, ExposureDisposition.USABLE)

    def test_unusable_exposure_has_zero_denominator(self) -> None:
        with self.assertRaisesRegex(ValidationError, "zero denominator"):
            Exposure(uid(30), 1, exact(), exact(26), 86400, 0, 0, 0, 1, ExposureDisposition.UNUSABLE)


class CalculationCancellationTests(unittest.TestCase):
    def test_legacy_event_permission_misses_rate_only_event(self) -> None:
        events = (Event(uid(10), 1, uid(30), (Measure.RATE,)),)
        legacy = sum(Measure.EVENT in event.included_measures for event in events)
        self.assertEqual(legacy, 0)

    def test_rate_only_event_produces_100_for_one_active_day(self) -> None:
        events = (Event(uid(10), 1, uid(30), (Measure.RATE,)),)
        self.assertEqual(normalized_rate(events, 86400, Checkpoints(NeverCancel())), "100")

    def test_bounded_preprocessing_cancels_at_checkpoint(self) -> None:
        token = CancelOnCall(2)
        checkpoints = Checkpoints(token)
        checkpoints.check()
        with self.assertRaises(Cancelled):
            tuple(checkpoints.rows(range(10000)))
        self.assertEqual(checkpoints.rows_seen, CHECKPOINT_INTERVAL)

    def test_bounded_sorting_cancels_before_full_consumption(self) -> None:
        token = CancelOnCall(3)
        checkpoints = Checkpoints(token)
        checkpoints.check()
        with self.assertRaises(Cancelled):
            checkpoints.sorted_values(range(10000, 0, -1), key=lambda value: value)
        self.assertLess(checkpoints.rows_seen, 10000)


class ResultProtocolTests(unittest.TestCase):
    def test_prohibited_table_identity_is_rejected(self) -> None:
        column = ResultColumn("value", "MEASURE", "integer", False, "measure.event", "events")
        with self.assertRaisesRegex(ValidationError, "prohibited table"):
            ResultTable("confirmed_route_table", (), (column,), (({}, (1,)),))

    def test_result_value_must_match_logical_type(self) -> None:
        column = ResultColumn("value", "MEASURE", "integer", False, "measure.event", "events")
        with self.assertRaisesRegex(ValidationError, "integer type"):
            ResultTable("measure_event", (), (column,), (({}, ("1",)),))

    def test_measure_requires_unit(self) -> None:
        with self.assertRaisesRegex(ValidationError, "unit required"):
            ResultColumn("value", "MEASURE", "integer", False, "measure.event")

    def test_source_state_comparison_is_qualified(self) -> None:
        state = SourceState(uid(1), uid(2), uid(3))
        self.assertTrue(state.is_current_against(SourceState(uid(1), uid(2), uid(3))))
        self.assertFalse(state.is_current_against(SourceState(uid(1), uid(9), uid(3))))
        with self.assertRaisesRegex(ValidationError, "qualified"):
            state.is_current_against(uid(3))

    def test_repository_protocol_exposes_snapshot_factory_only(self) -> None:
        self.assertIn("open_snapshot", Repository.__dict__)
        self.assertNotIn("events", Repository.__dict__)


if __name__ == "__main__":
    unittest.main()
