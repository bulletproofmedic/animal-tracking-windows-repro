from __future__ import annotations

import unittest

from repro.finalizer_roster_repro import (
    FinalizerIdentity,
    RosterError,
    canonical_roster,
    validate_runtime_roster,
)


class FinalizerRosterTests(unittest.TestCase):
    def journal(self, roster: list[dict[str, str]]) -> dict[str, object]:
        return {
            "post_restore_finalizer_roster_version": 1,
            "required_post_restore_finalizers": roster,
        }

    def test_canonical_order_and_exact_match(self) -> None:
        runtime = (
            FinalizerIdentity("zeta", "2.0"),
            FinalizerIdentity("alpha", "1.0"),
        )
        expected = [
            {"finalizer_id": "alpha", "finalizer_version": "1.0"},
            {"finalizer_id": "zeta", "finalizer_version": "2.0"},
        ]
        self.assertEqual(canonical_roster(runtime), expected)
        validate_runtime_roster(self.journal(expected), runtime)

    def test_missing_added_and_version_changed_fail_closed(self) -> None:
        expected = [
            {"finalizer_id": "analysis-source-state", "finalizer_version": "1.0"}
        ]
        cases = (
            (),
            (
                FinalizerIdentity("analysis-source-state", "1.0"),
                FinalizerIdentity("unexpected", "1.0"),
            ),
            (FinalizerIdentity("analysis-source-state", "2.0"),),
        )
        for runtime in cases:
            with self.subTest(runtime=runtime):
                with self.assertRaisesRegex(RosterError, "changed after staging"):
                    validate_runtime_roster(self.journal(expected), runtime)

    def test_duplicate_runtime_identity_is_rejected(self) -> None:
        with self.assertRaisesRegex(RosterError, "duplicate finalizer identity"):
            canonical_roster(
                (
                    FinalizerIdentity("alpha", "1.0"),
                    FinalizerIdentity("alpha", "2.0"),
                )
            )

    def test_malformed_duplicate_and_noncanonical_required_rosters_fail(self) -> None:
        cases = (
            [{"finalizer_id": "alpha"}],
            [
                {"finalizer_id": "alpha", "finalizer_version": "1.0"},
                {"finalizer_id": "alpha", "finalizer_version": "1.0"},
            ],
            [
                {"finalizer_id": "zeta", "finalizer_version": "1.0"},
                {"finalizer_id": "alpha", "finalizer_version": "1.0"},
            ],
        )
        for roster in cases:
            with self.subTest(roster=roster):
                with self.assertRaises(RosterError):
                    validate_runtime_roster(self.journal(roster), ())


if __name__ == "__main__":
    unittest.main()
