from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from repro.publication_protocol import Protocol, digest, publish_write_through


class PublicationProtocolTests(unittest.TestCase):
    def test_write_through_publication_preserves_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.part"
            destination = root / "destination.bin"
            source.write_bytes(b"synthetic-publication-payload")
            publish_write_through(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_bytes(), b"synthetic-publication-payload")
            self.assertEqual(digest(destination)[1], len(b"synthetic-publication-payload"))
            if os.name == "nt":
                self.assertEqual(destination.drive.casefold(), source.drive.casefold())

    def test_every_post_publication_interruption_recovers(self) -> None:
        for boundary in ("PUBLISHED", "REGISTRY", "RECORDED"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                protocol = Protocol(Path(directory))
                protocol.prepare(f"payload-{boundary}".encode())
                with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                    protocol.reconcile(interrupt_after=boundary)
                protocol.reconcile()
                self.assertFalse(protocol.journal.exists())
                self.assertTrue(protocol.destination.is_file())
                self.assertTrue(protocol.registry.is_file())

    def test_repeated_reconciliation_never_advertises_unverified_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            protocol = Protocol(Path(directory))
            protocol.prepare(b"stable")
            with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                protocol.reconcile(interrupt_after="PUBLISHED")
            protocol.destination.write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "published identity mismatch"):
                protocol.reconcile()
            self.assertFalse(protocol.registry.exists())
            self.assertTrue(protocol.journal.exists())


if __name__ == "__main__":
    unittest.main()
