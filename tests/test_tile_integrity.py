from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from repro.tile_integrity import freeze, snapshot


def make_fixture(root: Path, tiles: dict[str, bytes]) -> tuple[Path, int]:
    maps = root / "maps"
    tile_root = maps / "tiles" / "fixture"
    tile_root.mkdir(parents=True)
    records = []
    total = 0
    for relative, content in sorted(tiles.items()):
        path = tile_root / Path(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        records.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "byte_count": len(content),
            }
        )
        total += len(content)
    manifest = tile_root / "manifest.json"
    raw = (json.dumps({"tiles": records}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest.write_bytes(raw)
    return manifest, total + len(raw)


class TileIntegrityTests(unittest.TestCase):
    def test_exact_closure_freezes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, total = make_fixture(
                root,
                {"0/0/0.png": b"zero", "0/1/0.png": b"one"},
            )
            freeze(manifest, root / "maps", root / "frozen", total)
            self.assertTrue((root / "frozen/manifest.json").is_file())
            self.assertTrue((root / "frozen/0/0/0.png").is_file())

    def test_same_size_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, total = make_fixture(root, {"0/0/0.png": b"AAAA"})
            (manifest.parent / "0/0/0.png").write_bytes(b"BBBB")
            with self.assertRaisesRegex(ValueError, "digest closure mismatch"):
                snapshot(manifest, root / "maps", total)

    def test_add_remove_preserving_total_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, total = make_fixture(
                root,
                {"0/0/0.png": b"AAAA", "0/1/0.png": b"BBBB"},
            )
            (manifest.parent / "0/1/0.png").unlink()
            replacement = manifest.parent / "0/2/0.png"
            replacement.parent.mkdir(parents=True, exist_ok=True)
            replacement.write_bytes(b"BBBB")
            with self.assertRaisesRegex(ValueError, "exact closure mismatch"):
                snapshot(manifest, root / "maps", total)

    def test_mutation_after_copy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, total = make_fixture(root, {"0/0/0.png": b"AAAA"})
            tile = manifest.parent / "0/0/0.png"
            with self.assertRaisesRegex(ValueError, "digest closure mismatch"):
                freeze(
                    manifest,
                    root / "maps",
                    root / "frozen",
                    total,
                    mutate_after_copy=lambda: tile.write_bytes(b"BBBB"),
                )

    def test_external_file_symlink_is_rejected_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, total = make_fixture(root, {"0/0/0.png": b"tile"})
            tile = manifest.parent / "0/0/0.png"
            external = root / "external.png"
            external.write_bytes(b"tile")
            tile.unlink()
            try:
                os.symlink(external, tile)
            except OSError:
                self.skipTest("file symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "link, junction, or reparse"):
                snapshot(manifest, root / "maps", total)

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_windows_junction_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, total = make_fixture(root, {"0/0/0.png": b"tile"})
            level = manifest.parent / "0"
            for path in sorted(level.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            level.rmdir()
            external = root / "external-level"
            (external / "0").mkdir(parents=True)
            (external / "0/0.png").write_bytes(b"tile")
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(level), str(external)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"junction creation unavailable: {result.stderr}")
            with self.assertRaisesRegex(ValueError, "link, junction, or reparse"):
                snapshot(manifest, root / "maps", total)


if __name__ == "__main__":
    unittest.main()
