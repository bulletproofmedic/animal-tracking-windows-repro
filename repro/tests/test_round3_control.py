from __future__ import annotations

import unittest
from pathlib import Path
from uuid import UUID

from repro.round3_control import (
    CancelAfter,
    Cancelled,
    Checkpoints,
    Configuration,
    ControlError,
    Exclusion,
    SelectedRow,
    create_synthetic_repository,
    producer_evidence,
    run_mutation_probes,
    selection_counts,
    validate_configuration_population,
    validate_git_binding,
)


class RoundThreeControls(unittest.TestCase):
    def test_configuration_collision_rejected_in_both_orders(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        for revisions in ((1, 2), (2, 1)):
            with self.subTest(revisions=revisions), self.assertRaises(ControlError):
                validate_configuration_population(
                    Configuration(identity, revision) for revision in revisions
                )

    def test_unique_configuration_identities_are_accepted(self) -> None:
        validate_configuration_population(
            (
                Configuration(UUID(int=1), 1),
                Configuration(UUID(int=2), 2),
            )
        )

    def test_materialization_cancels_before_unbounded_stream_completion(self) -> None:
        checkpoints = Checkpoints(CancelAfter(3))
        with self.assertRaises(Cancelled):
            checkpoints.materialize(range(1000))
        self.assertLess(checkpoints.rows_seen, 1000)

    def test_selection_count_preprocessing_cancels(self) -> None:
        checkpoints = Checkpoints(CancelAfter(2))
        events = (
            SelectedRow("EVENT", UUID(int=index + 1), 1, "included")
            for index in range(1000)
        )
        with self.assertRaises(Cancelled):
            selection_counts(events, (), (), checkpoints)
        self.assertLess(checkpoints.rows_seen, 1000)

    def test_selection_identity_preserves_entity_type(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        result = selection_counts(
            (SelectedRow("EVENT", identity, 1, "included"),),
            (SelectedRow("OBSERVATION", identity, 1, "included"),),
            (),
            Checkpoints(CancelAfter(100)),
        )
        self.assertEqual(result["considered"], 2)
        self.assertEqual(result["included"], 2)

    def test_exclusion_of_different_entity_type_is_not_collapsed(self) -> None:
        identity = UUID("00000000-0000-7000-8000-000000000001")
        result = selection_counts(
            (SelectedRow("EVENT", identity, 1, "included"),),
            (),
            (Exclusion("OBSERVATION", identity, 1, "excluded"),),
            Checkpoints(CancelAfter(100)),
        )
        self.assertEqual(result["considered"], 2)
        self.assertEqual(result["excluded"], 1)

    def test_exact_git_identity_and_path_population_pass(self) -> None:
        holder, root, base, head, tree = create_synthetic_repository()
        try:
            result = validate_git_binding(
                root,
                expected_execution_commit=head,
                expected_source_commit=head,
                expected_source_tree=tree,
                expected_base_commit=base,
                expected_changed_paths={"control.txt"},
            )
            self.assertEqual(result["execution_commit"], head)
            self.assertEqual(result["execution_tree"], tree)
            self.assertTrue(result["tracked_worktree_clean"])
        finally:
            holder.cleanup()

    def test_wrong_git_head_fails_closed(self) -> None:
        holder, root, base, head, tree = create_synthetic_repository()
        try:
            with self.assertRaisesRegex(ControlError, "execution commit mismatch"):
                validate_git_binding(
                    root,
                    expected_execution_commit="0" * 40,
                    expected_source_commit=head,
                    expected_source_tree=tree,
                    expected_base_commit=base,
                    expected_changed_paths={"control.txt"},
                )
        finally:
            holder.cleanup()

    def test_wrong_git_tree_fails_closed(self) -> None:
        holder, root, base, head, _tree = create_synthetic_repository()
        try:
            with self.assertRaisesRegex(ControlError, "source tree mismatch"):
                validate_git_binding(
                    root,
                    expected_execution_commit=head,
                    expected_source_commit=head,
                    expected_source_tree="0" * 40,
                    expected_base_commit=base,
                    expected_changed_paths={"control.txt"},
                )
        finally:
            holder.cleanup()

    def test_changed_path_population_fails_closed(self) -> None:
        holder, root, base, head, tree = create_synthetic_repository()
        try:
            with self.assertRaisesRegex(ControlError, "changed-path population mismatch"):
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

    def test_dirty_tracked_worktree_fails_closed(self) -> None:
        holder, root, base, head, tree = create_synthetic_repository()
        try:
            Path(root, "control.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ControlError, "tracked worktree is not clean"):
                validate_git_binding(
                    root,
                    expected_execution_commit=head,
                    expected_source_commit=head,
                    expected_source_tree=tree,
                    expected_base_commit=base,
                    expected_changed_paths={"control.txt"},
                )
        finally:
            holder.cleanup()

    def test_mutation_score_is_calculated_from_per_mutant_outcomes(self) -> None:
        result = run_mutation_probes(
            {
                "killed": lambda: True,
                "survived": lambda: False,
            }
        )
        self.assertEqual(result["killed"], 1)
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["score"], 0.5)
        self.assertEqual(
            {item["status"] for item in result["results"]},
            {"KILLED", "SURVIVED"},
        )

    def test_public_producer_evidence_kills_all_six_mutants(self) -> None:
        result = producer_evidence()
        self.assertEqual(result["killed"], 6)
        self.assertEqual(result["total"], 6)
        self.assertEqual(result["score"], 1.0)
        self.assertEqual(
            {item["status"] for item in result["results"]},
            {"KILLED"},
        )


if __name__ == "__main__":
    unittest.main()
