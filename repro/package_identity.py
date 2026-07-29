from __future__ import annotations

import hashlib
import json
import uuid
import zipfile
from pathlib import Path

NAMESPACE = uuid.NAMESPACE_URL


def file_identity(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def canonical_manifest_identity(path: Path) -> str:
    with zipfile.ZipFile(path, "r") as archive:
        manifest = json.loads(archive.read("manifest.json"))
    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def deterministic_id(archive_sha256: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"urn:synthetic:package:sha256:{archive_sha256}"))


def resolve_identity(
    archive: Path,
    *,
    supplied_id: str,
    supplied_property: str,
    receipt: dict[str, object] | None,
) -> tuple[str, str, str]:
    archive_sha, archive_bytes = file_identity(archive)
    canonical_manifest = canonical_manifest_identity(archive)
    if receipt is not None and (
        receipt.get("phase") == "RECORDED"
        and receipt.get("package_id") == supplied_id
        and Path(str(receipt.get("archive_path"))).resolve() == archive.resolve()
        and receipt.get("archive_sha256") == archive_sha
        and receipt.get("archive_bytes") == archive_bytes
        and receipt.get("canonical_manifest_sha256") == canonical_manifest
    ):
        return supplied_id, supplied_property, "SUPPLIED"
    return deterministic_id(archive_sha), "", "ARCHIVE_SHA256"
