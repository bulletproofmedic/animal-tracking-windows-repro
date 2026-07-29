from __future__ import annotations

import unittest
from pathlib import Path

from scripts.check_public_payload import validate_named_bytes

ROOT = Path(__file__).resolve().parents[1]
DELTA_FILES = (
    "repro/f008_target/journal_json.py",
    "repro/f008_target/source_extracts.py",
    "repro/f008_target/SOURCE_SNAPSHOT.json",
    "repro/run.ps1",
    "tests/test_f008_revalidation.py",
    "tests/test_f008_payload_delta.py",
)


class F008PublicPayloadDeltaTests(unittest.TestCase):
    def test_f008_delta_is_sanitized(self) -> None:
        findings: list[str] = []
        for relative in DELTA_FILES:
            findings.extend(validate_named_bytes(relative, (ROOT / relative).read_bytes()))
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
