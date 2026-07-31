from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from containment import (
    _REPARSE_POINT_FLAG,
    ValidationError,
    is_link_or_reparse,
    stream_stable_file,
    walk_regular_files,
)


class ContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "managed"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_regular_in_root_file_streams(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"authorized")
        destination = io.BytesIO()

        _digest, byte_count = stream_stable_file(source, destination, root=self.root)

        self.assertEqual(destination.getvalue(), b"authorized")
        self.assertEqual(byte_count, len(b"authorized"))

    def test_out_of_root_hard_link_is_rejected(self) -> None:
        outside = self.root.parent / "outside.bin"
        outside.write_bytes(b"outside-secret")
        linked = self.root / "linked.bin"
        try:
            os.link(outside, linked)
        except OSError as exc:
            self.skipTest(f"Hard-link creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValidationError, "multiple hard links"):
            stream_stable_file(linked, io.BytesIO(), root=self.root)

    def test_tile_member_hard_link_is_rejected_before_population_use(self) -> None:
        tile_root = self.root / "tiles"
        tile_root.mkdir()
        (tile_root / "manifest.json").write_text("{}", encoding="utf-8")
        outside = self.root.parent / "outside-tile.bin"
        outside.write_bytes(b"tile-bytes")
        linked = tile_root / "0.bin"
        try:
            os.link(outside, linked)
        except OSError as exc:
            self.skipTest(f"Hard-link creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValidationError, "multiple hard links"):
            walk_regular_files(tile_root)

    def test_file_symlink_is_rejected(self) -> None:
        outside = self.root.parent / "outside.bin"
        outside.write_bytes(b"outside")
        linked = self.root / "linked.bin"
        try:
            linked.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"Symbolic-link creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValidationError, "link or reparse point"):
            stream_stable_file(linked, io.BytesIO(), root=self.root)

    def test_reparse_attribute_is_rejected_for_regular_mode(self) -> None:
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_file_attributes=_REPARSE_POINT_FLAG,
        )
        self.assertTrue(is_link_or_reparse(metadata))

    @unittest.skipUnless(os.name == "nt", "Windows junction coverage")
    def test_nested_windows_junction_is_rejected(self) -> None:
        tile_root = self.root / "tiles"
        tile_root.mkdir()
        (tile_root / "manifest.json").write_text("{}", encoding="utf-8")
        outside = self.root.parent / "outside-junction"
        outside.mkdir()
        (outside / "escaped.bin").write_bytes(b"escaped")
        junction = tile_root / "junction"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.skipTest(result.stderr or result.stdout)

        try:
            with self.assertRaisesRegex(ValidationError, "link or reparse point"):
                walk_regular_files(tile_root)
        finally:
            if junction.exists():
                os.rmdir(junction)


if __name__ == "__main__":
    unittest.main()
