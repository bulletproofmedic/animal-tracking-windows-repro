from __future__ import annotations

import csv
import io
import os
import subprocess
import sys
import unittest

from at_wal_006_controls import (
    EVENT_SCHEMA,
    MAX_EXPORT_EVENTS,
    MAX_REPORT_EVENTS,
    OBSERVATION_SCHEMA,
    CountBreakdown,
    Event,
    InvalidQuery,
    Observation,
    PopulationLimitExceeded,
    SourceSnapshot,
    SourceStateChanged,
    UnsupportedComparison,
    accepted_matching_observations,
    bind_snapshot,
    canonical_result_payload,
    classified_counts,
    enforce_population_limit,
    event_matches,
    event_report,
    export_csv,
    exposure_comparison,
    paginate,
    project_event,
    validate_query,
)


SNAPSHOT = SourceSnapshot("state-synthetic-4", 4)


def observation(
    identity: str,
    *,
    status: str = "ACCEPTED",
    species: str = "DEER",
    direction: str = "N",
    count: int = 1,
    classification: str = "EXACT",
) -> Observation:
    return Observation(
        observation_id=identity,
        status=status,
        species=species,
        direction=direction,
        count_value=count,
        count_classification=classification,
    )


def event(identity: str, *rows: Observation, site: str = "SITE-A") -> Event:
    return Event(identity, "ACCEPTED", site, tuple(rows))


class AtWal006ControlTests(unittest.TestCase):
    def test_invalid_query_is_not_a_zero_result(self) -> None:
        with self.assertRaisesRegex(InvalidQuery, "not run"):
            validate_query(start=9, end=4)
        validate_query(start=4, end=9)

    def test_species_and_direction_must_match_the_same_accepted_child(self) -> None:
        source = event(
            "event-1",
            observation("obs-1", species="DEER", direction="N"),
            observation("obs-2", species="COYOTE", direction="E"),
        )
        self.assertFalse(
            event_matches(
                source,
                species=frozenset({"COYOTE"}),
                directions=frozenset({"N"}),
            )
        )

    def test_nonaccepted_children_are_excluded_everywhere(self) -> None:
        source = event(
            "event-1",
            observation("obs-1", species="DEER", count=2),
            observation("obs-2", status="DRAFT", species="COYOTE", count=99),
        )
        matching = accepted_matching_observations(source)
        self.assertEqual([row.observation_id for row in matching], ["obs-1"])
        projection = project_event(source)
        self.assertEqual(projection.species, ("DEER",))
        self.assertEqual(projection.counts.exact, 2)
        self.assertEqual(projection.excluded_nonaccepted_rows, 1)
        _events_csv, observations_csv = export_csv(
            (source,), snapshot_before=SNAPSHOT, snapshot_after=SNAPSHOT
        )
        exported = list(csv.DictReader(io.StringIO(observations_csv.decode("utf-8"))))
        self.assertEqual([row["observation_id"] for row in exported], ["obs-1"])

    def test_filtered_projection_contains_only_matching_children(self) -> None:
        source = event(
            "event-1",
            observation("obs-1", species="DEER", direction="N", count=2),
            observation("obs-2", species="COYOTE", direction="E", count=7),
        )
        result = project_event(source, species=frozenset({"COYOTE"}))
        self.assertEqual(result.species, ("COYOTE",))
        self.assertEqual(result.directions, ("E",))
        self.assertEqual(result.counts.exact, 7)

    def test_count_classifications_are_not_collapsed(self) -> None:
        counts = classified_counts(
            (
                observation("a", count=2, classification="EXACT"),
                observation("b", count=3, classification="MINIMUM"),
                observation("c", count=4, classification="ESTIMATED"),
                observation("d", count=5, classification="UNSUPPORTED"),
            )
        )
        self.assertEqual(counts, CountBreakdown(2, 3, 4, 5))

    def test_empty_and_populated_exports_use_identical_schemas(self) -> None:
        empty_event_csv, empty_observation_csv = export_csv(
            (), snapshot_before=SNAPSHOT, snapshot_after=SNAPSHOT
        )
        populated_event_csv, populated_observation_csv = export_csv(
            (event("event-1", observation("obs-1")),),
            snapshot_before=SNAPSHOT,
            snapshot_after=SNAPSHOT,
        )
        self.assertEqual(
            empty_event_csv.decode().splitlines()[0],
            populated_event_csv.decode().splitlines()[0],
        )
        self.assertEqual(
            empty_observation_csv.decode().splitlines()[0],
            populated_observation_csv.decode().splitlines()[0],
        )
        self.assertEqual(tuple(empty_event_csv.decode().splitlines()[0].split(",")), EVENT_SCHEMA)
        self.assertEqual(
            tuple(empty_observation_csv.decode().splitlines()[0].split(",")),
            OBSERVATION_SCHEMA,
        )

    def test_source_state_change_fails_closed(self) -> None:
        changed = SourceSnapshot("state-synthetic-5", 5)
        with self.assertRaises(SourceStateChanged):
            bind_snapshot(SNAPSHOT, changed)
        with self.assertRaises(SourceStateChanged):
            export_csv(
                (event("event-1", observation("obs-1")),),
                snapshot_before=SNAPSHOT,
                snapshot_after=changed,
            )

    def test_event_level_child_grouping_is_prohibited(self) -> None:
        source = (event("event-1", observation("obs-1")),)
        for group_by in ("species", "direction"):
            with self.subTest(group_by=group_by), self.assertRaises(UnsupportedComparison):
                event_report(
                    source,
                    group_by=group_by,
                    snapshot_before=SNAPSHOT,
                    snapshot_after=SNAPSHOT,
                )

    def test_site_report_is_deterministic_across_input_order(self) -> None:
        first = event("event-b", observation("obs-2"), site="RIDGE")
        second = event("event-a", observation("obs-1"), site="CREEK")
        report_a = event_report(
            (first, second),
            group_by="site",
            snapshot_before=SNAPSHOT,
            snapshot_after=SNAPSHOT,
        )
        report_b = event_report(
            (second, first),
            group_by="site",
            snapshot_before=SNAPSHOT,
            snapshot_after=SNAPSHOT,
        )
        self.assertEqual(report_a, report_b)

    def test_report_hash_is_stable_across_python_hash_seeds(self) -> None:
        script = """
from at_wal_006_controls import Event, Observation, SourceSnapshot, event_report
s=SourceSnapshot('state-synthetic-4',4)
o=Observation('obs-1','ACCEPTED','DEER','N',1,'EXACT')
e=Event('event-1','ACCEPTED','SITE-A',(o,))
print(event_report((e,),group_by='site',snapshot_before=s,snapshot_after=s)[1])
""".strip()
        digests: set[str] = set()
        for seed in ("1", "2", "7", "101"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            process = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            digests.add(process.stdout.strip())
        self.assertEqual(len(digests), 1)

    def test_report_and_export_population_limits_fail_closed(self) -> None:
        enforce_population_limit(MAX_REPORT_EVENTS, operation="report")
        enforce_population_limit(MAX_EXPORT_EVENTS, operation="export")
        with self.assertRaises(PopulationLimitExceeded):
            enforce_population_limit(MAX_REPORT_EVENTS + 1, operation="report")
        with self.assertRaises(PopulationLimitExceeded):
            enforce_population_limit(MAX_EXPORT_EVENTS + 1, operation="export")

    def test_database_style_pagination_projects_only_one_page(self) -> None:
        rows = tuple(event(f"event-{index:03d}") for index in range(125))
        page = paginate(rows, page=2, page_size=50)
        self.assertEqual(len(page), 50)
        self.assertEqual(page[0].event_id, "event-050")
        self.assertEqual(page[-1].event_id, "event-099")

    def test_exposure_comparison_is_blocked_without_denominator(self) -> None:
        with self.assertRaisesRegex(UnsupportedComparison, "denominators"):
            exposure_comparison(normalized_exposure_available=False)
        exposure_comparison(normalized_exposure_available=True)

    def test_export_order_is_stable(self) -> None:
        one = event("event-b", observation("obs-b"), site="RIDGE")
        two = event("event-a", observation("obs-a"), site="CREEK")
        export_a = export_csv(
            (one, two), snapshot_before=SNAPSHOT, snapshot_after=SNAPSHOT
        )
        export_b = export_csv(
            (two, one), snapshot_before=SNAPSHOT, snapshot_after=SNAPSHOT
        )
        self.assertEqual(export_a, export_b)

    def test_canonical_projection_payload_is_stable(self) -> None:
        source = event(
            "event-1",
            observation("obs-b", species="COYOTE", direction="E"),
            observation("obs-a", species="DEER", direction="N"),
        )
        first = canonical_result_payload(project_event(source))
        second = canonical_result_payload(
            project_event(event("event-1", *reversed(source.observations)))
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
