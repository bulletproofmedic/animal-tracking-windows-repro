from __future__ import annotations

import os
import subprocess
import sys
import unittest

from at_wal_006_reaudit_controls import (
    ACCEPTED,
    MAX_EVENTS,
    MAX_OBSERVATIONS,
    ConstructionFailed,
    Event,
    Observation,
    PopulationLimitExceeded,
    SourceSnapshot,
    SourceStateChanged,
    accepted_matching,
    bound_snapshot,
    csv_spool,
    enforce_bounds,
    exact_blob_manifest_rejects,
    normalize_statuses,
    report_input_sha256,
    selected_events,
    staged_snapshot_validation,
)

SNAPSHOT = SourceSnapshot("state-1", 1)


def observation(
    identity: str,
    *,
    status: str = ACCEPTED,
    species_id: str = "species-deer",
    species_code: str = "DEER",
    species_label: str = "White-tailed Deer",
    species_unknown: bool = False,
    direction: str = "N",
    count: int = 1,
) -> Observation:
    return Observation(
        identity,
        status,
        species_id,
        species_code,
        species_label,
        species_unknown,
        direction,
        "OWNER",
        count,
        "EXACT",
    )


def event(identity: str, status: str = ACCEPTED, *rows: Observation) -> Event:
    return Event(identity, status, "2026-07-29T06:00:00-04:00", tuple(rows))


class AtWal006ReauditSuccessorTests(unittest.TestCase):
    def test_empty_statuses_fail_closed_to_accepted(self) -> None:
        accepted = event("accepted", ACCEPTED, observation("a"))
        draft = event("draft", "DRAFT", observation("d"))
        void = event("void", "VOID", observation("v"))
        self.assertEqual(normalize_statuses(()), (ACCEPTED,))
        self.assertEqual(selected_events((accepted, draft, void), ()), (accepted,))
        self.assertEqual(
            selected_events((accepted, draft, void), ("DRAFT", "VOID")),
            (draft, void),
        )

    def test_nonaccepted_children_and_mixed_filters_use_one_population(self) -> None:
        source = event(
            "event-1",
            ACCEPTED,
            observation("a", species_id="deer", direction="N", count=2),
            observation("b", species_id="deer", direction="E", count=3),
            observation("c", species_id="coyote", direction="N", count=4),
            observation("d", status="VOID", species_id="deer", direction="N", count=99),
        )
        rows = accepted_matching(
            source,
            species_ids=frozenset({"deer"}),
            directions=frozenset({"N"}),
        )
        self.assertEqual([row.observation_id for row in rows], ["a"])
        self.assertEqual([row.count_value for row in rows], [2])

    def test_event_and_child_bounds_are_independent_and_fail_closed(self) -> None:
        enforce_bounds(
            tuple(event(str(index)) for index in range(MAX_EVENTS)), MAX_OBSERVATIONS
        )
        with self.assertRaises(PopulationLimitExceeded):
            enforce_bounds(
                tuple(event(str(index)) for index in range(MAX_EVENTS + 1)), 0
            )
        with self.assertRaises(PopulationLimitExceeded):
            enforce_bounds((), MAX_OBSERVATIONS + 1)

    def test_csv_spool_exact_bytes_special_characters_and_stable_hash(self) -> None:
        fieldnames = ("id", "label")
        rows = (
            {"id": "1", "label": 'Deer, "quoted"\nline'},
            {"id": "2", "label": "Coyote"},
        )
        first = csv_spool(fieldnames, rows)
        second = csv_spool(fieldnames, rows)
        self.assertEqual(first, second)
        self.assertEqual(first[1], 2)
        self.assertNotIn(b"\r\n", first[0])
        self.assertIn(b'"Deer, ""quoted""\nline"', first[0])

    def test_csv_spool_disk_allocation_failure_is_safe(self) -> None:
        def fail_spool(**_kwargs: object) -> object:
            raise OSError("disk full")

        with self.assertRaisesRegex(ConstructionFailed, "no partial download"):
            csv_spool(("id",), ({"id": "1"},), spool_factory=fail_spool)

    def test_missing_and_changed_source_state_fail_closed(self) -> None:
        with self.assertRaises(SourceStateChanged):
            bound_snapshot(None, SNAPSHOT)
        with self.assertRaises(SourceStateChanged):
            bound_snapshot(SNAPSHOT, None)
        with self.assertRaises(SourceStateChanged):
            bound_snapshot(SNAPSHOT, SourceSnapshot("state-2", 2))
        self.assertEqual(bound_snapshot(SNAPSHOT, SNAPSHOT), SNAPSHOT)

    def test_every_source_read_boundary_is_checked(self) -> None:
        stable = (SNAPSHOT, SNAPSHOT, SNAPSHOT, SNAPSHOT, SNAPSHOT)
        staged_snapshot_validation(SNAPSHOT, stable)
        for index in range(len(stable)):
            mutated = list(stable)
            mutated[index] = SourceSnapshot("state-2", 2)
            with self.subTest(boundary=index), self.assertRaises(SourceStateChanged):
                staged_snapshot_validation(SNAPSHOT, mutated)

    def test_canonical_input_hash_includes_species_labels_and_unknown_semantics(
        self,
    ) -> None:
        original = event("event-1", ACCEPTED, observation("a"))
        renamed = event(
            "event-1",
            ACCEPTED,
            observation(
                "a",
                species_label="Renamed deer",
                species_unknown=True,
            ),
        )
        original_hash = report_input_sha256(
            (original,), statuses=(), before=SNAPSHOT, after=SNAPSHOT
        )
        renamed_hash = report_input_sha256(
            (renamed,), statuses=(), before=SNAPSHOT, after=SNAPSHOT
        )
        self.assertNotEqual(original_hash, renamed_hash)

    def test_exact_blob_manifest_rejects_each_material_mutation(self) -> None:
        expected = {
            "views": "blob-views",
            "routes": "blob-routes",
            "tests": "blob-tests",
            "templates": "blob-templates",
            "zip": "blob-zip",
            "forms": "blob-forms",
            "pagination": "blob-pagination",
            "population": "blob-population",
            "limits": "blob-limits",
            "source_state": "blob-source-state",
            "ordering": "blob-ordering",
            "comparisons": "blob-comparisons",
        }
        self.assertFalse(exact_blob_manifest_rejects(expected, expected.copy()))
        for key in expected:
            mutated = expected.copy()
            mutated[key] = "mutated"
            with self.subTest(mutation=key):
                self.assertTrue(exact_blob_manifest_rejects(expected, mutated))

    def test_hash_is_stable_across_process_hash_seeds_and_language_environment(
        self,
    ) -> None:
        script = """
from at_wal_006_reaudit_controls import Event, Observation, SourceSnapshot, report_input_sha256
s=SourceSnapshot('state-1',1)
o=Observation('a','ACCEPTED','species-deer','DEER','Same label',False,'N','OWNER',1,'EXACT')
e=Event('event-1','ACCEPTED','2026-07-29T06:00:00-04:00',(o,))
print(report_input_sha256((e,),statuses=(),before=s,after=s))
""".strip()
        outputs: set[str] = set()
        for seed in ("1", "2", "101", "random"):
            for language in ("C", "en_CA.UTF-8", "fr_CA.UTF-8"):
                environment = os.environ.copy()
                environment["PYTHONHASHSEED"] = seed
                environment["LANG"] = language
                process = subprocess.run(
                    [sys.executable, "-c", script],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                outputs.add(process.stdout.strip())
        self.assertEqual(len(outputs), 1)


if __name__ == "__main__":
    unittest.main()
