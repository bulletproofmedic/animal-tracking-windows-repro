from __future__ import annotations

import unittest
import warnings
from datetime import UTC, datetime
from uuid import UUID

from repro.reaudit_remediation_reproducer import (
    Cancelled,
    Checkpoints,
    Configuration,
    ContractModule,
    Dataset,
    EventStatus,
    ResultRow,
    ResultTable,
    SourceState,
    TypedRef,
    ValidationError,
    WarningRef,
    assert_installed,
    build_from_snapshot,
    cancellable_hash,
    install,
    validate_filter,
    validate_resolved_time,
)


def uid(value: int) -> UUID:
    return UUID(f"00000000-0000-7000-8000-{value:012d}")


class ReauditControls(unittest.TestCase):
    def test_filter_types_and_bounds(self) -> None:
        invalid = (
            {"event_statuses": "ACCEPTED"},
            {"include_unresolved": "yes"},
            {"event_ids": []},
            {"start_date": "2026-07-26", "end_date": "2026-07-25"},
            {
                "start_date": "2026-07-25",
                "end_date": "2026-07-26",
                "start_instant": "2026-07-25T00:00:00Z",
                "end_instant": "2026-07-26T00:00:00Z",
            },
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_filter(value)
        accepted = validate_filter(
            {
                "event_ids": [str(uid(1)), str(uid(2))],
                "event_statuses": [EventStatus.ACCEPTED.value],
                "include_unresolved": False,
                "start_date": "2026-07-25",
                "end_date": "2026-07-26",
            }
        )
        self.assertEqual(tuple(accepted["event_ids"]), (str(uid(1)), str(uid(2))))

    def test_nonexistent_dst_time_rejected(self) -> None:
        for offset, utc_hour in ((-18000, 7), (-14400, 6)):
            with self.subTest(offset=offset), self.assertRaises(ValidationError):
                validate_resolved_time(
                    datetime(2026, 3, 8, 2, 30),
                    "America/Toronto",
                    offset,
                    datetime(2026, 3, 8, utc_hour, 30, tzinfo=UTC),
                )

    def test_valid_ambiguous_fold_accepted(self) -> None:
        validate_resolved_time(
            datetime(2026, 11, 1, 1, 30),
            "America/Toronto",
            -14400,
            datetime(2026, 11, 1, 5, 30, tzinfo=UTC),
        )

    def test_open_ended_configuration_is_terminal(self) -> None:
        configurations = (
            Configuration(uid(20), 1, uid(10), datetime(2026, 1, 1), None),
            Configuration(uid(21), 1, uid(10), datetime(2026, 2, 1), None),
        )
        with self.assertRaises(ValidationError):
            Dataset((), (), configurations, ())

    def test_typed_warning_reference_rejects_entity_confusion(self) -> None:
        event = TypedRef("EVENT", uid(1), 1)
        species = TypedRef("SPECIES", uid(2), 1)
        with self.assertRaises(ValidationError):
            Dataset(
                (event,),
                (species,),
                (),
                (WarningRef((TypedRef("SPECIES", event.record_id, 1),)),),
            )

    def test_result_values_are_defensively_frozen(self) -> None:
        alias = {"nested": {"value": 1}}
        row = ResultRow({"group": "a"}, (alias,))
        alias["nested"]["value"] = 2
        self.assertEqual(row.values[0]["nested"]["value"], 1)
        with self.assertRaises(TypeError):
            row.values[0]["nested"]["value"] = 3

    def test_result_schema_is_exact_allowlist(self) -> None:
        ResultTable("measure_event", "analysis.table.event", "integer", False, "events")
        with self.assertRaises(ValidationError):
            ResultTable("measure_future", "analysis.table.future", "integer", False, "events")
        with self.assertRaises(ValidationError):
            ResultTable("measure_event", "analysis.table.other", "integer", False, "events")

    def test_qualified_currentness_and_deprecation(self) -> None:
        state = SourceState(uid(1), uid(2), uid(3))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertTrue(state.is_current_against(uid(3)))
        self.assertEqual(caught[0].category, DeprecationWarning)
        self.assertTrue(state.is_current_against_ref(SourceState(uid(1), uid(2), uid(3))))
        self.assertFalse(state.is_current_against_ref(SourceState(uid(1), uid(9), uid(3))))

    def test_snapshot_closes_and_detects_change(self) -> None:
        class Snapshot:
            def __init__(self, change: bool = False) -> None:
                self.change = change
                self.reads = 0
                self.closed = False

            @property
            def source_state(self):
                self.reads += 1
                return SourceState(uid(1), uid(2), uid(4 if self.change and self.reads > 1 else 3))

            def rows(self):
                return iter((TypedRef("EVENT", uid(5), 1),))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                self.closed = True
                return False

        class Repository:
            def __init__(self, snapshot):
                self.snapshot = snapshot
                self.opens = 0

            def open_snapshot(self):
                self.opens += 1
                return self.snapshot

        snapshot = Snapshot()
        repository = Repository(snapshot)
        _, rows = build_from_snapshot(repository)
        self.assertEqual(repository.opens, 1)
        self.assertTrue(snapshot.closed)
        self.assertEqual(len(rows), 1)
        changed = Snapshot(change=True)
        with self.assertRaises(ValidationError):
            build_from_snapshot(Repository(changed))
        self.assertTrue(changed.closed)

    def test_cancellable_hash_has_bounded_work(self) -> None:
        class Token:
            def __init__(self) -> None:
                self.calls = 0

            def raise_if_cancelled(self):
                self.calls += 1
                if self.calls >= 4:
                    raise Cancelled("cancelled")

        with self.assertRaises(Cancelled):
            cancellable_hash(
                {"large": ["x" * 70000 for _ in range(8)]},
                Checkpoints(Token()),
            )

    def test_reload_installs_exact_current_class(self) -> None:
        module = ContractModule()
        install(module)
        first = module.Request
        assert_installed(module)
        module.reload()
        self.assertIsNot(module.Request, first)
        assert_installed(module)


if __name__ == "__main__":
    unittest.main()
