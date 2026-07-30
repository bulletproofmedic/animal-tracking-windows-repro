from __future__ import annotations

import os
import statistics
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from repro import g8_handle_controls as controls


@unittest.skipUnless(os.name == "nt", "Windows-only handle-control diagnostic")
class Generation8HandleControls(unittest.TestCase):
    def test_standard_python_append_descriptor_reopens_and_verifies_acl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="g8-handle-") as temporary:
            path = Path(temporary) / "events.txt"
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write("synthetic-record\n")
                stream.flush()
                os.fsync(stream.fileno())
                controls.establish_private_acl(path)
                self.assertTrue(controls.file_descriptor_acl_is_private(stream.fileno()))
                self.assertEqual(
                    controls.read_exact_object(stream.fileno()),
                    b"synthetic-record\n",
                )

    def test_path_replacement_cannot_supply_exact_object_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="g8-replace-") as temporary:
            root = Path(temporary)
            path = root / "events.txt"
            displaced = root / "displaced.txt"
            path.write_bytes(b"original-object\n")
            descriptor = controls.open_shared_file(path)
            try:
                os.replace(path, displaced)
                path.write_bytes(b"replacement-object\n")
                self.assertEqual(
                    controls.read_exact_object(descriptor),
                    b"original-object\n",
                )
                self.assertEqual(path.read_bytes(), b"replacement-object\n")
            finally:
                os.close(descriptor)

    def test_delete_on_close_removes_validated_object_not_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="g8-delete-") as temporary:
            root = Path(temporary)
            path = root / "candidate.txt"
            displaced = root / "displaced.txt"
            path.write_bytes(b"validated-object")
            descriptor = controls.open_file_for_exact_cleanup(path)
            try:
                os.replace(path, displaced)
                path.write_bytes(b"replacement-object")
                controls.delete_file_descriptor_on_close(descriptor)
            finally:
                os.close(descriptor)
            self.assertFalse(displaced.exists())
            self.assertEqual(path.read_bytes(), b"replacement-object")

    def test_handle_bound_rename_never_replaces_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="g8-rename-") as temporary:
            root = Path(temporary)
            claim = root / "claim.txt"
            destination = root / "destination.txt"
            claim.write_bytes(b"claim")
            descriptor = controls.open_file_for_exact_cleanup(claim)
            try:
                controls.rename_file_descriptor_noreplace(descriptor, destination)
            finally:
                os.close(descriptor)
            self.assertFalse(claim.exists())
            self.assertEqual(destination.read_bytes(), b"claim")

            second = root / "second.txt"
            second.write_bytes(b"second")
            descriptor = controls.open_file_for_exact_cleanup(second)
            try:
                with self.assertRaises(OSError):
                    controls.rename_file_descriptor_noreplace(descriptor, destination)
            finally:
                os.close(descriptor)
            self.assertEqual(destination.read_bytes(), b"claim")
            self.assertEqual(second.read_bytes(), b"second")

    def test_concurrent_exact_object_verification_meets_declared_budget(self) -> None:
        with tempfile.TemporaryDirectory(prefix="g8-concurrency-") as temporary:
            path = Path(temporary) / "events.txt"
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write("bounded-record\n")
                stream.flush()
                os.fsync(stream.fileno())
                before = controls.POWERSHELL_INVOCATIONS
                controls.establish_private_acl(path)
                after_establish = controls.POWERSHELL_INVOCATIONS
                self.assertEqual(after_establish, before + 1)

                def verify() -> float:
                    started = time.perf_counter()
                    self.assertTrue(
                        controls.file_descriptor_acl_is_private(stream.fileno())
                    )
                    self.assertEqual(
                        controls.read_exact_object(stream.fileno()),
                        b"bounded-record\n",
                    )
                    return (time.perf_counter() - started) * 1000

                with ThreadPoolExecutor(max_workers=16) as executor:
                    latencies = list(executor.map(lambda _index: verify(), range(800)))

                ordered = sorted(latencies)
                p95 = ordered[int(len(ordered) * 0.95) - 1]
                p99 = ordered[int(len(ordered) * 0.99) - 1]
                self.assertLessEqual(p95, 250.0)
                self.assertLessEqual(p99, 500.0)
                self.assertEqual(
                    controls.POWERSHELL_INVOCATIONS,
                    after_establish,
                )
                print(
                    {
                        "workers": 16,
                        "calls": len(latencies),
                        "median_ms": round(statistics.median(latencies), 3),
                        "p95_ms": round(p95, 3),
                        "p99_ms": round(p99, 3),
                        "powershell_invocations": controls.POWERSHELL_INVOCATIONS,
                    }
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
