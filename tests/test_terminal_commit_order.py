from __future__ import annotations

import unittest

from repro.terminal_commit_order import (
    InjectedInterruption,
    TerminalCommitState,
    run_matrix,
)


class TerminalCommitOrderTests(unittest.TestCase):
    def test_begin_retains_rollback_authority(self) -> None:
        state = TerminalCommitState()
        state.begin()
        self.assertEqual(state.phase, "FINALIZE_PENDING")
        self.assertTrue(state.rollback_exists)

    def test_every_interruption_point_recovers_deterministically(self) -> None:
        result = run_matrix()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(len(result["matrix"]), 7)

    def test_failure_before_archive_never_releases_rollback(self) -> None:
        for point in (
            "persist_outcome",
            "persist_lineage",
            "verify_readback",
            "mark_finalized",
            "archive_journal",
        ):
            with self.subTest(point=point):
                state = TerminalCommitState()
                state.begin()
                with self.assertRaises(InjectedInterruption):
                    state.commit(interrupt_after=point)
                self.assertTrue(state.rollback_exists)

    def test_release_requires_persistence_readback_and_archive(self) -> None:
        state = TerminalCommitState(
            phase="FINALIZED",
            rollback_exists=True,
            outcome_persisted=True,
            lineage_persisted=True,
            readback_verified=True,
            history_archived=True,
        )
        state.commit()
        self.assertFalse(state.rollback_exists)
        self.assertTrue(state.journal_closed)

    def test_restart_rejects_premature_rollback_loss(self) -> None:
        state = TerminalCommitState(
            phase="FINALIZE_PENDING",
            rollback_exists=False,
        )
        with self.assertRaisesRegex(RuntimeError, "premature rollback loss"):
            state.restart()


if __name__ == "__main__":
    unittest.main()
