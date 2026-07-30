from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import unittest

from at_wal_006_generation_2_controls import (
    ConstructionFailed,
    OutputMutationDetected,
    SyntheticBundle,
    build_archive,
    build_two_files,
    csv_file,
    export_input_and_manifest,
    guarded_report,
    replay_report,
    report_input_record,
    semantic_mutation_is_killed,
)
from at_wal_006_reaudit_controls import ACCEPTED, Event, Observation, SourceSnapshot

SNAPSHOT = SourceSnapshot("state-generation-2", 2)


def observation(
    identity: str,
    *,
    species_id: str = "species-a",
    species_label: str = "Same label",
    count: int = 1,
    direction: str = "N",
) -> Observation:
    return Observation(
        identity,
        ACCEPTED,
        species_id,
        species_id.upper(),
        species_label,
        False,
        direction,
        "OWNER",
        count,
        "EXACT",
    )


def event(
    identity: str,
    *rows: Observation,
    capture_time: str = "2026-07-29T12:00:00-04:00",
) -> Event:
    return Event(identity, ACCEPTED, capture_time, tuple(rows))


class AtWal006Generation2Tests(unittest.TestCase):
    def test_partial_file_is_closed_when_second_file_fails(self) -> None:
        first = csv_file("first.csv", ({"id": "1", "label": "one"},))

        def fail_second() -> object:
            raise OSError("simulated second-file failure")

        with self.assertRaises(OSError):
            build_two_files(lambda: first, fail_second)
        self.assertTrue(first.stream.closed)

    def test_bundle_is_closed_when_archive_allocation_fails(self) -> None:
        owned = csv_file("first.csv", ({"id": "1", "label": "one"},))
        bundle = SyntheticBundle((owned,), b"{}", b"{}")

        def fail_archive() -> io.BytesIO:
            raise OSError("simulated archive allocation failure")

        with self.assertRaises(ConstructionFailed):
            build_archive(bundle, fail_archive)
        self.assertTrue(bundle.closed)
        self.assertTrue(owned.stream.closed)

    def test_report_input_replays_exact_result(self) -> None:
        source = (
            event("event-2", observation("obs-2", species_id="species-b", count=2)),
            event("event-1", observation("obs-1", species_id="species-a", count=1)),
        )
        record = report_input_record(source, statuses=(), snapshot=SNAPSHOT)
        buckets = replay_report(record)
        self.assertEqual([bucket.key for bucket in buckets], ["species-a", "species-b"])
        self.assertEqual([bucket.value for bucket in buckets], [1, 2])

    def test_output_mutations_fail_without_snapshot_revision_change(self) -> None:
        baseline = (event("event-1", observation("obs-1", count=1)),)
        changed_count = (event("event-1", observation("obs-1", count=7)),)
        changed_label = (
            event(
                "event-1",
                observation("obs-1", species_label="Renamed label", count=1),
            ),
        )
        changed_time = (
            event(
                "event-1",
                observation("obs-1", count=1),
                capture_time="2026-07-30T12:00:00-04:00",
            ),
        )
        for mutant in (changed_count, changed_label, changed_time):
            with self.subTest(mutant=mutant), self.assertRaises(OutputMutationDetected):
                guarded_report(
                    baseline,
                    mutant,
                    mutant,
                    statuses=(),
                    before=SNAPSHOT,
                    after=SNAPSHOT,
                )

    def test_final_boundary_mutation_is_detected(self) -> None:
        baseline = (event("event-1", observation("obs-1", count=1)),)
        final = (event("event-1", observation("obs-1", count=2)),)
        with self.assertRaises(OutputMutationDetected):
            guarded_report(
                baseline,
                baseline,
                final,
                statuses=(),
                before=SNAPSHOT,
                after=SNAPSHOT,
            )

    def test_export_input_and_manifest_are_replayable(self) -> None:
        source = (event("event-1", observation("obs-1", count=3)),)
        input_record, manifest = export_input_and_manifest(
            source,
            statuses=(),
            snapshot=SNAPSHOT,
        )
        manifest_payload = json.loads(manifest)
        self.assertEqual(
            manifest_payload["input_sha256"],
            hashlib.sha256(input_record).hexdigest(),
        )
        self.assertEqual(replay_report(input_record)[0].value, 3)

    def test_duplicate_label_tiebreaker_is_input_order_independent(self) -> None:
        left = event("event-1", observation("obs-1", species_id="species-a"))
        right = event("event-2", observation("obs-2", species_id="species-b"))
        forward = replay_report(
            report_input_record((left, right), statuses=(), snapshot=SNAPSHOT)
        )
        reverse = replay_report(
            report_input_record((right, left), statuses=(), snapshot=SNAPSHOT)
        )
        self.assertEqual(forward, reverse)
        self.assertEqual([bucket.key for bucket in forward], ["species-a", "species-b"])

    def test_semantic_mutant_is_killed_by_relevant_check(self) -> None:
        source = "def normalize(statuses):\n    return statuses or ('ACCEPTED',)\n"

        def check(candidate: str) -> bool:
            return "or ('ACCEPTED',)" in candidate

        self.assertTrue(
            semantic_mutation_is_killed(
                source,
                marker="or ('ACCEPTED',)",
                replacement="",
                behavioral_check=check,
            )
        )

    def test_actual_cross_process_output_is_stable(self) -> None:
        script = r"""
from at_wal_006_generation_2_controls import report_input_record, replay_report
from at_wal_006_reaudit_controls import ACCEPTED, Event, Observation, SourceSnapshot
snapshot = SourceSnapshot("state-generation-2", 2)
def obs(identity, species):
    return Observation(
        identity, ACCEPTED, species, species.upper(), "Same label", False,
        "N", "OWNER", 1, "EXACT"
    )
events = (
    Event("event-2", ACCEPTED, "2026-07-29T12:01:00-04:00", (obs("o2", "b"),)),
    Event("event-1", ACCEPTED, "2026-07-29T12:00:00-04:00", (obs("o1", "a"),)),
)
record = report_input_record(events, statuses=(), snapshot=snapshot)
print(record.decode())
print(replay_report(record))
"""
        outputs: set[str] = set()
        root = os.path.dirname(os.path.dirname(__file__))
        for seed in ("1", "2", "100", "random"):
            for language in ("C", "en_CA.UTF-8", "fr_CA.UTF-8"):
                env = os.environ.copy()
                env["PYTHONHASHSEED"] = seed
                env["LANG"] = language
                env["LC_ALL"] = language
                completed = subprocess.run(
                    [sys.executable, "-c", script],
                    cwd=root,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                outputs.add(completed.stdout)
        self.assertEqual(len(outputs), 1)


if __name__ == "__main__":
    unittest.main()
