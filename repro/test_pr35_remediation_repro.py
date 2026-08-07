from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

from pr35_remediation_repro import (
    AssetState,
    RepairValidationError,
    ValidatedState,
    ensure_thumbnail,
    governed_repair,
    reconcile_state,
    render_thumbnail_bytes,
    thumbnail_is_valid,
)


def _image(
    path: Path,
    *,
    size: tuple[int, int] = (64, 48),
    color: tuple[int, int, int] = (30, 60, 90),
) -> None:
    Image.new("RGB", size, color=color).save(path, format="JPEG")


def _asset() -> AssetState:
    return AssetState(
        media_kind="TRAIL_CAMERA_IMAGE",
        lifecycle_status="MISSING",
        accepted_at="2026-01-02T03:04:05+00:00",
        missing_or_corrupt_detail="Simulated missing original",
        managed_storage_key="legacy/wrong-location.jpg",
        detected_mime_type="application/octet-stream",
        detected_format="UNKNOWN",
        byte_count=1,
        width_pixels=1,
        height_pixels=1,
        original_filename="original-photo.jpg",
        source_system="ORIGINAL_SOURCE",
        source_file_created_at="2026-01-02T03:04:00+00:00",
        source_file_modified_at="2026-01-02T03:05:00+00:00",
    )


def _validated() -> ValidatedState:
    return ValidatedState(
        managed_storage_key="sha256/aa/bb/aabb.jpg",
        detected_mime_type="image/jpeg",
        detected_format="JPEG",
        byte_count=1234,
        width_pixels=80,
        height_pixels=60,
    )


def test_governed_repair_records_every_authoritative_metadata_change() -> None:
    before = _asset()
    after, changes = governed_repair(
        before,
        _validated(),
        requested_media_kind="TRAIL_CAMERA_IMAGE",
    )

    assert set(changes) == {
        "lifecycle_status",
        "missing_or_corrupt_detail",
        "managed_storage_key",
        "detected_mime_type",
        "detected_format",
        "byte_count",
        "width_pixels",
        "height_pixels",
    }
    assert changes["lifecycle_status"] == ("MISSING", "MANAGED")
    assert changes["missing_or_corrupt_detail"] == (
        "Simulated missing original",
        "",
    )
    assert after.original_filename == before.original_filename
    assert after.source_system == before.source_system
    assert after.source_file_created_at == before.source_file_created_at
    assert after.source_file_modified_at == before.source_file_modified_at
    assert after.accepted_at == before.accepted_at


def test_repair_rejects_classification_change_without_mutation() -> None:
    before = _asset()
    with pytest.raises(RepairValidationError, match="cannot change media_kind"):
        governed_repair(
            before,
            _validated(),
            requested_media_kind="EVIDENCE_IMAGE",
        )
    assert before == _asset()


def test_invalid_derivative_is_regenerated_from_managed_source(tmp_path: Path) -> None:
    managed = tmp_path / "managed.jpg"
    derivative = tmp_path / "thumbnail.jpg"
    _image(managed, size=(96, 64))
    derivative.write_bytes(b"not-a-valid-derivative")

    expected = render_thumbnail_bytes(managed)
    assert ensure_thumbnail(derivative, managed, 96, 64) is True
    assert derivative.read_bytes() == expected
    assert thumbnail_is_valid(derivative, managed, 96, 64)
    assert ensure_thumbnail(derivative, managed, 96, 64) is False


def test_forged_jpeg_comment_does_not_bind_unrelated_derivative(tmp_path: Path) -> None:
    managed = tmp_path / "managed.jpg"
    derivative = tmp_path / "thumbnail.jpg"
    _image(managed, size=(64, 48), color=(30, 60, 90))

    unrelated = Image.new("RGB", (64, 48), color=(220, 10, 10))
    unrelated.save(
        derivative,
        format="JPEG",
        quality=85,
        optimize=True,
        comment="copyable-source-digest",
    )

    expected = render_thumbnail_bytes(managed)
    assert derivative.read_bytes() != expected
    assert not thumbnail_is_valid(derivative, managed, 64, 48)
    assert ensure_thumbnail(derivative, managed, 64, 48) is True
    assert derivative.read_bytes() == expected


def test_deterministic_render_is_byte_stable(tmp_path: Path) -> None:
    managed = tmp_path / "managed.jpg"
    _image(managed, size=(1280, 720))
    first = render_thumbnail_bytes(managed)
    second = render_thumbnail_bytes(managed)
    assert first == second


@pytest.mark.parametrize("status", ["STAGED", "MISSING", "CORRUPT"])
def test_recovery_and_crash_boundary_promote_once(status: str) -> None:
    recovered, changed = reconcile_state(status, managed_file_valid=True)
    assert (recovered, changed) == ("MANAGED", True)
    repeated, repeated_changed = reconcile_state(recovered, managed_file_valid=True)
    assert (repeated, repeated_changed) == ("MANAGED", False)


def test_invalid_managed_file_does_not_promote() -> None:
    assert reconcile_state("CORRUPT", managed_file_valid=False) == ("CORRUPT", False)
