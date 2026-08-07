from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError


class RepairValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AssetState:
    media_kind: str
    lifecycle_status: str
    accepted_at: str | None
    missing_or_corrupt_detail: str
    managed_storage_key: str
    detected_mime_type: str
    detected_format: str
    byte_count: int
    width_pixels: int
    height_pixels: int
    original_filename: str
    source_system: str
    source_file_created_at: str | None
    source_file_modified_at: str | None


@dataclass(frozen=True, slots=True)
class ValidatedState:
    managed_storage_key: str
    detected_mime_type: str
    detected_format: str
    byte_count: int
    width_pixels: int
    height_pixels: int


def governed_repair(
    asset: AssetState,
    validated: ValidatedState,
    *,
    requested_media_kind: str,
) -> tuple[AssetState, dict[str, tuple[object, object]]]:
    """Model the exact successor's governed T2 repair-field transition."""
    if requested_media_kind != asset.media_kind:
        raise RepairValidationError(
            "Repair cannot change media_kind for an existing media asset."
        )

    desired: dict[str, object] = {
        "lifecycle_status": "MANAGED",
        "missing_or_corrupt_detail": "",
        "managed_storage_key": validated.managed_storage_key,
        "detected_mime_type": validated.detected_mime_type,
        "detected_format": validated.detected_format,
        "byte_count": validated.byte_count,
        "width_pixels": validated.width_pixels,
        "height_pixels": validated.height_pixels,
    }
    changes: dict[str, tuple[object, object]] = {}
    updates: dict[str, object] = {}
    for field, after in desired.items():
        before = getattr(asset, field)
        if before == after:
            continue
        changes[field] = (before, after)
        updates[field] = after
    return replace(asset, **updates), changes


def expected_thumbnail_dims(
    original_w: int,
    original_h: int,
    edge: int = 512,
) -> tuple[int, int]:
    x, y = original_w, original_h
    if x > edge:
        y = max(round(y * edge / x), 1)
        x = edge
    if y > edge:
        x = max(round(x * edge / y), 1)
        y = edge
    return x, y


def render_thumbnail_bytes(managed_path: Path, edge: int = 512) -> bytes:
    with Image.open(managed_path) as source:
        image = ImageOps.exif_transpose(source).convert("RGB")
        image.thumbnail((edge, edge))
        output = BytesIO()
        image.save(output, format="JPEG", quality=85, optimize=True)
        return output.getvalue()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def thumbnail_is_valid(
    thumbnail_path: Path,
    managed_path: Path,
    original_w: int,
    original_h: int,
    edge: int = 512,
) -> bool:
    """Accept only complete bytes equal to a fresh deterministic source render."""
    try:
        if not thumbnail_path.is_file() or not managed_path.is_file():
            return False
        with Image.open(thumbnail_path) as image:
            if image.format != "JPEG":
                return False
            if image.size != expected_thumbnail_dims(original_w, original_h, edge):
                return False
            image.verify()
        with Image.open(thumbnail_path) as image:
            image.load()
        expected = hashlib.sha256(render_thumbnail_bytes(managed_path, edge)).hexdigest()
        actual = sha256_file(thumbnail_path)
        return hmac.compare_digest(actual, expected)
    except (UnidentifiedImageError, OSError):
        return False


def ensure_thumbnail(
    thumbnail_path: Path,
    managed_path: Path,
    original_w: int,
    original_h: int,
    edge: int = 512,
) -> bool:
    """Return True only when regeneration was required."""
    if thumbnail_is_valid(
        thumbnail_path,
        managed_path,
        original_w,
        original_h,
        edge,
    ):
        return False
    thumbnail_path.parent.mkdir(parents=True, exist_ok=True)
    thumbnail_path.write_bytes(render_thumbnail_bytes(managed_path, edge))
    return True


def reconcile_state(status: str, *, managed_file_valid: bool) -> tuple[str, bool]:
    """Bounded F003/F004 no-regression model: valid files promote once."""
    if not managed_file_valid:
        return status, False
    if status == "MANAGED":
        return status, False
    return "MANAGED", True
