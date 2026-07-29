from __future__ import annotations

import json
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path

from repro.package_identity import (
    canonical_manifest_identity,
    deterministic_id,
    file_identity,
    resolve_identity,
)


def write_package(path: Path, *, purpose: str, compression: int) -> None:
    payload = b"synthetic-payload"
    manifest = {
        "purpose": purpose,
        "items": [{"path": "payload.bin", "sha256": __import__("hashlib").sha256(payload).hexdigest(), "bytes": len(payload)}],
    }
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.writestr("payload.bin", payload)
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")


def receipt(path: Path, package_id: str) -> dict[str, object]:
    archive_sha, archive_bytes = file_identity(path)
    return {
        "phase": "RECORDED",
        "package_id": package_id,
        "archive_path": str(path.resolve()),
        "archive_sha256": archive_sha,
        "archive_bytes": archive_bytes,
        "canonical_manifest_sha256": canonical_manifest_identity(path),
    }


class PackageIdentityTests(unittest.TestCase):
    def test_exact_bytes_reuse_supplied_identity_and_property(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "package.bin"
            write_package(archive, purpose="original", compression=zipfile.ZIP_DEFLATED)
            supplied = str(uuid.uuid4())
            self.assertEqual(resolve_identity(archive, supplied_id=supplied, supplied_property="property-1", receipt=receipt(archive, supplied)), (supplied, "property-1", "SUPPLIED"))

    def test_metadata_only_repack_cannot_inherit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "package.bin"
            write_package(archive, purpose="original", compression=zipfile.ZIP_DEFLATED)
            supplied = str(uuid.uuid4())
            original_receipt = receipt(archive, supplied)
            write_package(archive, purpose="changed metadata", compression=zipfile.ZIP_DEFLATED)
            resolved_id, property_id, scheme = resolve_identity(archive, supplied_id=supplied, supplied_property="property-1", receipt=original_receipt)
            archive_sha, _ = file_identity(archive)
            self.assertEqual(resolved_id, deterministic_id(archive_sha))
            self.assertEqual(property_id, "")
            self.assertEqual(scheme, "ARCHIVE_SHA256")
            self.assertNotEqual(resolved_id, supplied)

    def test_compression_only_repack_cannot_inherit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "package.bin"
            write_package(archive, purpose="original", compression=zipfile.ZIP_DEFLATED)
            supplied = str(uuid.uuid4())
            original_receipt = receipt(archive, supplied)
            canonical = canonical_manifest_identity(archive)
            write_package(archive, purpose="original", compression=zipfile.ZIP_STORED)
            self.assertEqual(canonical_manifest_identity(archive), canonical)
            resolved_id, property_id, scheme = resolve_identity(archive, supplied_id=supplied, supplied_property="property-1", receipt=original_receipt)
            archive_sha, _ = file_identity(archive)
            self.assertEqual(resolved_id, deterministic_id(archive_sha))
            self.assertEqual(property_id, "")
            self.assertEqual(scheme, "ARCHIVE_SHA256")

    def test_missing_receipt_cannot_inherit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "package.bin"
            write_package(archive, purpose="original", compression=zipfile.ZIP_DEFLATED)
            supplied = str(uuid.uuid4())
            resolved_id, property_id, scheme = resolve_identity(archive, supplied_id=supplied, supplied_property="property-1", receipt=None)
            archive_sha, _ = file_identity(archive)
            self.assertEqual(resolved_id, deterministic_id(archive_sha))
            self.assertEqual(property_id, "")
            self.assertEqual(scheme, "ARCHIVE_SHA256")

    def test_wrong_destination_or_package_id_cannot_inherit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "package.bin"
            write_package(archive, purpose="original", compression=zipfile.ZIP_DEFLATED)
            supplied = str(uuid.uuid4())
            mismatched = receipt(archive, supplied)
            mismatched["archive_path"] = str((Path(directory) / "other.bin").resolve())
            self.assertEqual(resolve_identity(archive, supplied_id=supplied, supplied_property="property-1", receipt=mismatched)[2], "ARCHIVE_SHA256")
            mismatched = receipt(archive, str(uuid.uuid4()))
            self.assertEqual(resolve_identity(archive, supplied_id=supplied, supplied_property="property-1", receipt=mismatched)[2], "ARCHIVE_SHA256")


if __name__ == "__main__":
    unittest.main()
