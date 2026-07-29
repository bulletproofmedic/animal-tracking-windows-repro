from __future__ import annotations

import unittest

from repro.reaudit_control_registry import CONTROL_IDS, PRIVATE_SUCCESSOR


class ReauditControlRegistryTests(unittest.TestCase):
    def test_exact_finding_identity_and_private_successor_are_frozen(self) -> None:
        self.assertEqual(
            CONTROL_IDS,
            {
                *(f"AT-WAL-008-F-{index:03d}" for index in range(1, 10)),
                "AT-WAL-008-R2-F-010",
            },
        )
        self.assertEqual(
            PRIVATE_SUCCESSOR,
            "ffe1e2b426d40ad7bd212684b326d6758004adaf",
        )


if __name__ == "__main__":
    unittest.main()
