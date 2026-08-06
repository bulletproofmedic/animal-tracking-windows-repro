from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

PRIVATE_IDENTITIES = {
    "failed_candidate": "c5e4d4134ff8c0b04ba5120ad4bf5d2c9ddbc023",
    "failed_tree": "62969daf508d5e0ea29fe4decfdb47c464f28819",
    "corrected_source": "b3f12700e754b705b9f470b8e368ba00c6885018",
    "corrected_control": "2d9a16df0ea30f4920743773d82b83757cbc3d85",
    "corrected_manifest": "08dc393a710f3d29345056f98fe52f1724ad8302",
    "corrected_retained": "4a6077f8642ca8c09ea552920bd39317b18f4d23",
    "corrected_candidate": "a33ac6d4d19cbc96f6345a7a64a774f0fbfe5e4c",
    "corrected_tree": "3f00a9552bae305a1ddb03c4cd08fac2271878d3",
    "allowlist_sha256": "e0232111fb152a2cdb159a843d964cc779f72a53c522e955e32442af40a554f4",
}


class FailingFlushStream:
    def __init__(self, wrapped: object) -> None:
        self._wrapped = wrapped

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)

    def flush(self) -> None:
        raise OSError("forced flush failure")


class ExactDescriptorGuard:
    def __init__(self, expected: dict[str, str]) -> None:
        self.expected = expected
        self._bounded_tail_lines = self._read_exact_descriptor

    @staticmethod
    def _read_exact_descriptor(file_descriptor: int) -> tuple[bytes, ...]:
        with open(file_descriptor, "rb", closefd=False) as stream:
            stream.seek(0)
            return tuple(stream.read().splitlines())

    def acknowledge(self, file_descriptor: int) -> None:
        lines = self._bounded_tail_lines(file_descriptor)
        if not lines or json.loads(lines[-1]) != self.expected:
            raise RuntimeError("durable event could not be acknowledged")


class AuditRemediationWindowsTests(unittest.TestCase):
    def test_flush_failure_cleanup_restores_stream_before_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security.log"
            handler = logging.FileHandler(path, encoding="utf-8")
            original_stream = handler.stream
            self.assertIsNotNone(original_stream)
            handler.stream = FailingFlushStream(original_stream)  # type: ignore[assignment]
            try:
                with self.assertRaisesRegex(OSError, "forced flush failure"):
                    handler.flush()
            finally:
                handler.stream = original_stream
                handler.close()
            self.assertTrue(path.exists())

    def test_mutation_targets_active_exact_descriptor_seam(self) -> None:
        expected = {"event_code": "SEC_INTEGRITY_FAILED", "record_id": "a" * 32}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security.log"
            path.write_text(json.dumps(expected, sort_keys=True) + "\n", encoding="utf-8")
            guard = ExactDescriptorGuard(expected)
            original = guard._bounded_tail_lines

            def mutate(file_descriptor: int) -> tuple[bytes, ...]:
                lines = list(original(file_descriptor))
                payload = json.loads(lines[-1])
                payload["event_code"] = "SEC_HOST_REJECTED"
                lines[-1] = json.dumps(payload, sort_keys=True).encode("utf-8")
                return tuple(lines)

            guard._bounded_tail_lines = mutate
            with path.open("rb") as stream:
                with self.assertRaisesRegex(RuntimeError, "could not be acknowledged"):
                    guard.acknowledge(stream.fileno())

    def test_acl_assertion_matches_complete_current_postcondition(self) -> None:
        script = """
$verified.GetOwner([System.Security.Principal.SecurityIdentifier])
if ($rules.Count -ne 2) { throw 'rules' }
if ($entry.IsInherited) { throw 'inherited' }
if ($entry.FileSystemRights -ne $rights) { throw 'rights' }
"""
        self.assertIn(
            "$verified.GetOwner([System.Security.Principal.SecurityIdentifier])",
            script,
        )
        self.assertIn("$rules.Count -ne 2", script)
        self.assertIn("$entry.IsInherited", script)
        self.assertIn("$entry.FileSystemRights -ne $rights", script)
        self.assertNotIn("$verified.Owner", script)

    def test_private_identity_binding_is_complete(self) -> None:
        self.assertEqual(len(PRIVATE_IDENTITIES), 9)
        for name, value in PRIVATE_IDENTITIES.items():
            expected_length = 64 if name == "allowlist_sha256" else 40
            self.assertEqual(len(value), expected_length)
            int(value, 16)


if __name__ == "__main__":
    unittest.main(verbosity=2)
