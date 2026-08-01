from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from repro.windows_identity import (
    RETAINED_FIELDS,
    IdentityMismatch,
    matches_after_open,
    matches_strictly,
    sha256_bytes,
    snapshot_handle,
    snapshot_path,
    verified_open,
)


class WindowsIdentityTests(unittest.TestCase):
    def test_natural_change_time_variance_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"stable\n")
            before = snapshot_path(path)
            with path.open("rb") as handle:
                after = snapshot_handle(handle)

            varied = before.changed_ns != after.changed_ns
            print(f"NATURAL_CHANGED_NS_VARIANCE={str(varied).upper()}")
            self.assertTrue(matches_after_open(before, after))
            if varied:
                self.assertTrue(
                    all(
                        getattr(before, field) == getattr(after, field)
                        for field in RETAINED_FIELDS
                    )
                )

    def test_synthetic_change_time_copy_is_relaxed_only_at_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"stable\n")
            baseline = snapshot_path(path)
            changed = replace(baseline, changed_ns=baseline.changed_ns + 1)

        self.assertTrue(matches_after_open(baseline, changed, windows=True))
        self.assertFalse(matches_after_open(baseline, changed, windows=False))
        self.assertFalse(matches_strictly(baseline, changed))

    def test_every_retained_field_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"stable\n")
            baseline = snapshot_path(path)

        for field in RETAINED_FIELDS:
            with self.subTest(field=field):
                value = getattr(baseline, field)
                mutated = replace(baseline, **{field: value + 1})
                self.assertFalse(matches_after_open(baseline, mutated, windows=True))
                self.assertFalse(matches_strictly(baseline, mutated))

    def test_post_close_replacement_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample.bin"
            replacement = root / "mutant.bin"
            target.write_bytes(b"original\n")
            baseline = snapshot_path(target)
            original_digest, original_bytes = sha256_bytes(target)
            state = {"closed": False, "mutated": False}

            def replace_after_close(handle: object) -> None:
                state["closed"] = bool(getattr(handle, "closed"))
                replacement.write_bytes(b"mutant\n")
                self.assertEqual(replacement.read_bytes(), b"mutant\n")
                self.assertEqual(replacement.stat().st_size, 7)
                replacement.replace(target)
                state["mutated"] = True

            with self.assertRaises(IdentityMismatch):
                with verified_open(target, after_close=replace_after_close) as handle:
                    self.assertEqual(handle.read(), b"original\n")

            self.assertTrue(state["closed"])
            self.assertTrue(state["mutated"])
            self.assertEqual(target.read_bytes(), b"mutant\n")
            final_digest, final_bytes = sha256_bytes(target)
            self.assertNotEqual(final_digest, original_digest)
            self.assertEqual(original_bytes, len(b"original\n"))
            self.assertEqual(final_bytes, 7)
            self.assertFalse(matches_strictly(baseline, snapshot_path(target)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
