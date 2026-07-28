from __future__ import annotations

import unittest
from dataclasses import dataclass, field

TERMINAL_STATUSES = {"ACTIVATED", "ROLLED_BACK"}


@dataclass
class Operation:
    status: str
    manifest_bound: bool
    validation_result: dict[str, object] = field(default_factory=dict)


def read_terminal_journal(
    journal: dict[str, object],
    *,
    synthesize_missing_lineage: bool = True,
) -> dict[str, object] | None:
    if "lineage" not in journal:
        if not synthesize_missing_lineage:
            return None
        journal["lineage"] = {
            "identity_scheme": "SYNTHETIC",
            "manifest_id": "derived-manifest",
        }
    return journal


def materialize_terminal_lineage(
    operation: Operation,
    journal: dict[str, object],
    *,
    synthesize_missing_lineage: bool = True,
) -> None:
    terminal_journal = read_terminal_journal(
        journal,
        synthesize_missing_lineage=synthesize_missing_lineage,
    )
    if terminal_journal is None:
        return

    lineage = terminal_journal.get("lineage")
    if not isinstance(lineage, dict):
        raise TypeError("The terminal journal lineage must be a dictionary.")

    operation.manifest_bound = True
    operation.validation_result["lineage"] = dict(lineage)


def terminal_save(
    operation: Operation,
    journal: dict[str, object],
    *,
    raw: bool = False,
) -> None:
    if raw or operation.status not in TERMINAL_STATUSES:
        return
    materialize_terminal_lineage(
        operation,
        journal,
        synthesize_missing_lineage=not operation.manifest_bound,
    )


class TerminalLineageTests(unittest.TestCase):
    def test_existing_manifest_without_journaled_lineage_is_preserved(self) -> None:
        operation = Operation(status="ROLLED_BACK", manifest_bound=True)
        journal: dict[str, object] = {"phase": "ROLLED_BACK"}

        terminal_save(operation, journal)

        self.assertTrue(operation.manifest_bound)
        self.assertNotIn("lineage", journal)
        self.assertNotIn("lineage", operation.validation_result)

    def test_existing_manifest_with_journaled_lineage_completes_metadata(self) -> None:
        operation = Operation(status="ROLLED_BACK", manifest_bound=True)
        journal: dict[str, object] = {
            "phase": "ROLLED_BACK",
            "lineage": {
                "identity_scheme": "SUPPLIED",
                "manifest_id": "existing-manifest",
            },
        }

        terminal_save(operation, journal)

        self.assertTrue(operation.manifest_bound)
        self.assertEqual(
            operation.validation_result["lineage"],
            journal["lineage"],
        )

    def test_missing_manifest_synthesizes_lineage(self) -> None:
        operation = Operation(status="ACTIVATED", manifest_bound=False)
        journal: dict[str, object] = {"phase": "ACTIVATED"}

        terminal_save(operation, journal)

        self.assertTrue(operation.manifest_bound)
        self.assertEqual(
            operation.validation_result["lineage"],
            {
                "identity_scheme": "SYNTHETIC",
                "manifest_id": "derived-manifest",
            },
        )

    def test_nonterminal_save_does_not_materialize(self) -> None:
        operation = Operation(status="STAGED", manifest_bound=False)
        journal: dict[str, object] = {"phase": "STAGED"}

        terminal_save(operation, journal)

        self.assertFalse(operation.manifest_bound)
        self.assertNotIn("lineage", journal)
        self.assertEqual(operation.validation_result, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
