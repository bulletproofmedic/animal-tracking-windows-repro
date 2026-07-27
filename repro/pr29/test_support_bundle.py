from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

import support_bundle
from support_bundle import SupportBundleValidationError, create_support_bundle

_REVIEW_TIME = datetime(2026, 7, 27, 12, 30, tzinfo=UTC)


def _create_bundle(destination: Path, log_files: list[Path]) -> None:
    create_support_bundle(
        destination,
        log_files=log_files,
        version_manifest={"application_version": "1.0.0", "source_commit": "abc123"},
        schema_history=[{"schema_version": 5, "status": "current"}],
        integrity_results={"database": "PASS", "managed_files": "PASS"},
        configuration={
            "mode": "local",
            "property_name": "Example Property",
            "database_path": r"C:\Users\Example\private.sqlite3",
            "api_key": "example-api-key",
        },
        sensitive_values=["Example Property", "IMAGE_0001.JPG"],
        disclosure_reviewed_by="owner",
        disclosure_reviewed_at=_REVIEW_TIME,
    )


def test_support_bundle_redacts_logs_and_governed_metadata(tmp_path: Path) -> None:
    source_log = tmp_path / "animal-tracking.log.1"
    source_log.write_text(
        json.dumps(
            {
                "timestamp": "2026-07-27T12:00:00Z",
                "event_code": "TEST",
                "message": (
                    "Example Property IMAGE_0001.JPG "
                    "password=example-password Bearer example.token cookie=example-session "
                    r"C:\Users\Example\private.sqlite3 12.345678,45.678901"
                ),
                "fields": {
                    "property_name": "Example Property",
                    "original_filename": "IMAGE_0001.JPG",
                    "session_token": "example-session",
                    "notes": "example private note",
                    "traceback": r"failed at C:\Users\Example\secret.txt",
                },
            },
            ensure_ascii=False,
        )
        + "\n"
        + "legacy pin=1234 at /home/example/private.sqlite3\n",
        encoding="utf-8",
    )
    destination = tmp_path / "support-bundle.zip"

    result = create_support_bundle(
        destination,
        log_files=[source_log],
        version_manifest={"application_version": "1.0.0", "source_commit": "abc123"},
        schema_history=[{"schema_version": 5, "status": "current"}],
        integrity_results={"database": "PASS", "managed_files": "PASS"},
        configuration={
            "mode": "local",
            "property_name": "Example Property",
            "database_path": r"C:\Users\Example\private.sqlite3",
            "api_key": "example-api-key",
        },
        sensitive_values=["Example Property", "IMAGE_0001.JPG"],
        disclosure_reviewed_by="owner",
        disclosure_reviewed_at=_REVIEW_TIME,
    )

    assert result.path == destination
    assert result.sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert result.member_count == 6
    assert result.byte_count == destination.stat().st_size

    with zipfile.ZipFile(destination) as archive:
        names = sorted(archive.namelist())
        assert names == [
            "logs/redacted-001.jsonl",
            "manifest.json",
            "metadata/configuration.json",
            "metadata/integrity-results.json",
            "metadata/schema-history.json",
            "metadata/version.json",
        ]
        rendered = "\n".join(
            archive.read(name).decode("utf-8", errors="replace") for name in names
        )
        manifest = json.loads(archive.read("manifest.json"))

    for forbidden in (
        "Example Property",
        "IMAGE_0001.JPG",
        "example-password",
        "example.token",
        "example-session",
        "example-api-key",
        "1234",
        "12.345678",
        "45.678901",
        "Example",
        "example",
        "private.sqlite3",
        "example private note",
        "secret.txt",
        source_log.name,
    ):
        assert forbidden not in rendered

    assert manifest["bundle_schema"] == "AnimalTrackingSupportBundleV1"
    assert manifest["disclosure_review"] == {
        "reviewed_at": "2026-07-27T12:30:00Z",
        "reviewed_by": "owner",
        "status": "COMPLETED",
    }
    assert manifest["source_log_count"] == 1
    assert "media" in manifest["excluded_by_default"]
    assert "maps" in manifest["excluded_by_default"]
    assert "exact_coordinates" in manifest["excluded_by_default"]


def test_support_bundle_uses_restrictive_output_mode_where_supported(tmp_path: Path) -> None:
    source_log = tmp_path / "animal-tracking.log"
    source_log.write_text('{"event_code":"TEST","message":"safe"}\n', encoding="utf-8")
    destination = tmp_path / "support-bundle.zip"

    _create_bundle(destination, [source_log])

    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_support_bundle_rejects_duplicate_or_nonregular_log_sources(tmp_path: Path) -> None:
    source_log = tmp_path / "animal-tracking.log"
    source_log.write_text("safe\n", encoding="utf-8")

    with pytest.raises(SupportBundleValidationError, match="Duplicate log sources"):
        _create_bundle(tmp_path / "duplicate.zip", [source_log, source_log])

    with pytest.raises(SupportBundleValidationError, match="regular file"):
        _create_bundle(tmp_path / "directory.zip", [tmp_path])


def test_support_bundle_enforces_log_count_and_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")

    monkeypatch.setattr(support_bundle, "_MAX_LOG_FILES", 1)
    with pytest.raises(SupportBundleValidationError, match="at most 1 log files"):
        _create_bundle(tmp_path / "too-many.zip", [first, second])

    monkeypatch.setattr(support_bundle, "_MAX_LOG_FILES", 10)
    monkeypatch.setattr(support_bundle, "_MAX_LOG_FILE_BYTES", 2)
    monkeypatch.setattr(support_bundle, "_MAX_TOTAL_LOG_BYTES", 20)
    with pytest.raises(SupportBundleValidationError, match="exceeds the 2-byte limit"):
        _create_bundle(tmp_path / "too-large.zip", [first])


def test_support_bundle_requires_completed_review_and_preserves_existing_output(
    tmp_path: Path,
) -> None:
    source_log = tmp_path / "animal-tracking.log"
    source_log.write_text("safe\n", encoding="utf-8")
    destination = tmp_path / "existing.zip"
    destination.write_bytes(b"existing")

    with pytest.raises(SupportBundleValidationError, match="already exists"):
        _create_bundle(destination, [source_log])
    assert destination.read_bytes() == b"existing"

    with pytest.raises(SupportBundleValidationError, match="reviewer identity"):
        create_support_bundle(
            tmp_path / "missing-reviewer.zip",
            log_files=[source_log],
            version_manifest={},
            schema_history=[],
            integrity_results={},
            configuration={},
            sensitive_values=["private"],
            disclosure_reviewed_by=" ",
            disclosure_reviewed_at=_REVIEW_TIME,
        )

    with pytest.raises(SupportBundleValidationError, match="timezone-aware"):
        create_support_bundle(
            tmp_path / "naive-review-time.zip",
            log_files=[source_log],
            version_manifest={},
            schema_history=[],
            integrity_results={},
            configuration={},
            sensitive_values=["private"],
            disclosure_reviewed_by="owner",
            disclosure_reviewed_at=datetime(2026, 7, 27, 12, 30),
        )
