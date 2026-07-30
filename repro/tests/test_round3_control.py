from __future__ import annotations

import sys
import unittest
from pathlib import Path
from uuid import UUID

from repro.round3_control import (
    _POPULATIONS,
    CancelAfter,
    CancelAfterSnapshotClose,
    Cancelled,
    Checkpoints,
    ControlError,
    Exclusion,
    PopulationRow,
    SelectedRow,
    Snapshot,
    build_payload,
    create_shallow_repository,
    ensure_complete_history,
    producer_evidence,
    require_selection_counts,
    selection_counts,
    validate_git_binding,
    validate_stable_population,
)


class RoundFourControls(unittest.TestCase):
    def test_all_stable_id_populations_reject_revision_collisions(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        for entity_type in _POPULATIONS:
            for revisions in ((1, 2), (2, 1)):
                with (
                    self.subTest(
                        entity_type=entity_type,
                        revisions=revisions,
                    ),
                    self.assertRaises(ControlError),
                ):
                    validate_stable_population(
                        (
                            PopulationRow(entity_type, identity, revisions[0]),
                            PopulationRow(entity_type, identity, revisions[1]),
                        )
                    )

    def test_cross_entity_uuid_reuse_remains_legal(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        validate_stable_population(
            (
                PopulationRow("EVENT", identity, 1),
                PopulationRow("SPECIES", identity, 1),
            )
        )

    def test_typed_exclusion_is_not_collapsed(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        result = selection_counts(
            (SelectedRow("EVENT", identity, 1, "included"),),
            (Exclusion("SPECIES", identity, 1, "excluded"),),
            Checkpoints(CancelAfter(100)),
        )
        self.assertEqual(
            result,
            {
                "included": 1,
                "partial": 0,
                "excluded": 1,
                "considered": 2,
            },
        )

    def test_typed_selection_undercount_is_rejected(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        with self.assertRaisesRegex(ControlError, "typed graph"):
            require_selection_counts(
                (SelectedRow("EVENT", identity, 1, "included"),),
                (Exclusion("SPECIES", identity, 1, "excluded"),),
                {
                    "included": 1,
                    "partial": 0,
                    "excluded": 0,
                    "considered": 1,
                },
            )

    def test_materialization_still_cancels(self) -> None:
        checkpoints = Checkpoints(CancelAfter(3))
        with self.assertRaises(Cancelled):
            checkpoints.materialize(range(1000))
        self.assertLess(checkpoints.rows_seen, 1000)

    def test_payload_validation_cancels_after_snapshot_close(self) -> None:
        rows = tuple(
            PopulationRow("EVENT", UUID(int=index + 1), 1)
            for index in range(2000)
        )
        snapshot = Snapshot(rows)
        with self.assertRaisesRegex(Cancelled, "payload validation"):
            build_payload(
                snapshot,
                CancelAfterSnapshotClose(snapshot, calls=3),
            )
        self.assertTrue(snapshot.closed)

    def test_payload_validation_restores_prior_trace(self) -> None:
        previous = sys.gettrace()
        snapshot = Snapshot((PopulationRow("EVENT", UUID(int=1), 1),))
        build_payload(
            snapshot,
            CancelAfterSnapshotClose(snapshot, calls=1000),
        )
        self.assertIs(sys.gettrace(), previous)

    def test_validation_exception_is_not_masked_by_cleanup_check(self) -> None:
        duplicate = PopulationRow("EVENT", UUID(int=1), 1)
        snapshot = Snapshot((duplicate, duplicate))
        with self.assertRaisesRegex(ControlError, "duplicate stable identity"):
            build_payload(
                snapshot,
                CancelAfterSnapshotClose(snapshot, calls=1000),
            )

    def test_fresh_clone_starts_shallow(self) -> None:
        holder, root, _base, _head, _tree = create_shallow_repository()
        try:
            self.assertEqual(
                "true",
                _git_for_test(root, "rev-parse", "--is-shallow-repository"),
            )
        finally:
            holder.cleanup()

    def test_complete_history_restores_merge_base_and_binding(self) -> None:
        holder, root, base, head, tree = create_shallow_repository()
        try:
            ensure_complete_history(
                root,
                expected_base_commit=base,
                expected_source_commit=head,
            )
            self.assertEqual(
                "false",
                _git_for_test(root, "rev-parse", "--is-shallow-repository"),
            )
            result = validate_git_binding(
                root,
                expected_execution_commit=head,
                expected_source_commit=head,
                expected_source_tree=tree,
                expected_base_commit=base,
                expected_changed_paths={"control.txt"},
            )
            self.assertEqual(result["merge_base"], base)
            self.assertTrue(result["tracked_worktree_clean"])
        finally:
            holder.cleanup()

    def test_wrong_changed_path_population_fails_closed(self) -> None:
        holder, root, base, head, tree = create_shallow_repository()
        try:
            ensure_complete_history(
                root,
                expected_base_commit=base,
                expected_source_commit=head,
            )
            with self.assertRaisesRegex(
                ControlError,
                "changed-path population mismatch",
            ):
                validate_git_binding(
                    root,
                    expected_execution_commit=head,
                    expected_source_commit=head,
                    expected_source_tree=tree,
                    expected_base_commit=base,
                    expected_changed_paths={"different.txt"},
                )
        finally:
            holder.cleanup()

    def test_measured_evidence_kills_all_six_controls(self) -> None:
        result = producer_evidence()
        self.assertEqual(result["killed"], 6)
        self.assertEqual(result["total"], 6)
        self.assertEqual(result["score"], 1.0)
        self.assertEqual(
            {item["status"] for item in result["results"]},
            {"KILLED"},
        )


def _git_for_test(root: Path, *args: str) -> str:
    import subprocess

    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
