from __future__ import annotations

import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from unittest.mock import patch

import repro.reaudit_remediation_reproducer as model


class ReauditMutationGateTests(unittest.TestCase):
    @staticmethod
    def _mutant_is_killed(context, probe) -> bool:
        try:
            with context:
                probe()
        except Exception:
            return True
        return False

    def test_six_targeted_mutants_are_killed(self) -> None:
        killed = 0

        def invalid_filter_probe() -> None:
            with self.assertRaises(model.ValidationError):
                model.validate_filter({"include_unresolved": "yes"})

        killed += self._mutant_is_killed(
            patch.object(model, "validate_filter", lambda value: model.freeze(value)),
            invalid_filter_probe,
        )

        fabricated = ((-18000, datetime(2026, 3, 8, 7, 30, tzinfo=UTC)),)

        def dst_probe() -> None:
            with self.assertRaises(model.ValidationError):
                model.validate_resolved_time(
                    datetime(2026, 3, 8, 2, 30),
                    "America/Toronto",
                    -18000,
                    datetime(2026, 3, 8, 7, 30, tzinfo=UTC),
                )

        killed += self._mutant_is_killed(
            patch.object(model, "zone_candidates", lambda local, zone: fabricated),
            dst_probe,
        )

        def freeze_probe() -> None:
            alias = {"nested": {"value": 1}}
            row = model.ResultRow({"group": "a"}, (alias,))
            alias["nested"]["value"] = 2
            self.assertEqual(row.values[0]["nested"]["value"], 1)

        killed += self._mutant_is_killed(
            patch.object(model, "freeze", lambda value: value),
            freeze_probe,
        )

        mutant_registry = dict(model.RESULT_REGISTRY)
        mutant_registry["measure_future"] = ("EVENT", "integer", False, "events")

        def result_probe() -> None:
            with self.assertRaises(model.ValidationError):
                model.ResultTable(
                    "measure_future",
                    "analysis.table.event",
                    "integer",
                    False,
                    "events",
                )

        killed += self._mutant_is_killed(
            patch.object(model, "RESULT_REGISTRY", mutant_registry),
            result_probe,
        )

        def currentness_probe() -> None:
            state = model.SourceState(model.UUID(int=1), model.UUID(int=2), model.UUID(int=3))
            other = model.SourceState(model.UUID(int=1), model.UUID(int=9), model.UUID(int=3))
            self.assertFalse(state.is_current_against_ref(other))

        killed += self._mutant_is_killed(
            patch.object(
                model.SourceState,
                "is_current_against_ref",
                lambda self, current: self.state_id == current.state_id,
            ),
            currentness_probe,
        )

        def reload_probe() -> None:
            module = model.ContractModule()
            model.install(module)
            module.reload()
            model.assert_installed(module)

        def reload_without_install(self) -> None:
            self.Request = type("Request", (model.ContractClass,), {})

        killed += self._mutant_is_killed(
            patch.object(model.ContractModule, "reload", reload_without_install),
            reload_probe,
        )

        self.assertEqual(killed, 6)
        self.assertEqual(killed / 6, 1.0)


if __name__ == "__main__":
    unittest.main()
