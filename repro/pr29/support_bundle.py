from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
import unicodedata
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from logging_config import sanitize_log_text, sanitize_log_value

_BUNDLE_SCHEMA = "AnimalTrackingSupportBundleV1"
_MAX_LOG_FILES = 10
_MAX_LOG_FILE_BYTES = 10 * 1024 * 1024
_MAX_TOTAL_LOG_BYTES = _MAX_LOG_FILES * _MAX_LOG_FILE_BYTES
_SENSITIVE_LITERAL_REDACTION = "<sensitive-value-redacted>"


class SupportBundleValidationError(ValueError):
    """Raised when support-bundle inputs violate the disclosure boundary."""


@dataclass(frozen=True, slots=True)
class SupportBundleResult:
    path: Path
    sha256: str
    member_count: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class _BundleMember:
    archive_path: str
    source_path: Path
    sha256: str
    size_bytes: int


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return (rendered + "\n").encode("utf-8")


def _write_restricted(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def _compile_sensitive_literals(values: Sequence[str]) -> tuple[re.Pattern[str], ...]:
    normalized: set[str] = set()
    for value in values:
        candidate = unicodedata.normalize("NFC", value).strip()
        if not candidate:
            raise SupportBundleValidationError("Sensitive disclosure values cannot be empty.")
        normalized.add(candidate)
    return tuple(
        re.compile(re.escape(value), re.IGNORECASE)
        for value in sorted(normalized, key=lambda item: (-len(item), item.casefold()))
    )


def _redact_literals(value: object, patterns: tuple[re.Pattern[str], ...]) -> object:
    if isinstance(value, str):
        redacted = unicodedata.normalize("NFC", value)
        for pattern in patterns:
            redacted = pattern.sub(_SENSITIVE_LITERAL_REDACTION, redacted)
        return redacted
    if isinstance(value, Mapping):
        return {
            str(key): _redact_literals(nested_value, patterns)
            for key, nested_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        return [_redact_literals(item, patterns) for item in value]
    return value


def _sanitize_bundle_value(
    key: str,
    value: object,
    patterns: tuple[re.Pattern[str], ...],
) -> object:
    return _redact_literals(sanitize_log_value(key, value), patterns)


def _validate_log_sources(log_files: Sequence[Path]) -> tuple[Path, ...]:
    if not log_files:
        raise SupportBundleValidationError("A support bundle requires at least one log file.")
    if len(log_files) > _MAX_LOG_FILES:
        raise SupportBundleValidationError(
            f"A support bundle may include at most {_MAX_LOG_FILES} log files."
        )

    validated: list[Path] = []
    seen: set[Path] = set()
    total_bytes = 0
    for source in log_files:
        if source.is_symlink() or not source.is_file():
            raise SupportBundleValidationError("Every log source must be a regular file.")
        resolved = source.resolve(strict=True)
        if resolved in seen:
            raise SupportBundleValidationError("Duplicate log sources are not allowed.")
        seen.add(resolved)
        size_bytes = resolved.stat().st_size
        if size_bytes > _MAX_LOG_FILE_BYTES:
            raise SupportBundleValidationError(
                f"A log source exceeds the {_MAX_LOG_FILE_BYTES}-byte limit."
            )
        total_bytes += size_bytes
        if total_bytes > _MAX_TOTAL_LOG_BYTES:
            raise SupportBundleValidationError(
                f"Selected logs exceed the {_MAX_TOTAL_LOG_BYTES}-byte aggregate limit."
            )
        validated.append(resolved)
    return tuple(sorted(validated, key=lambda path: str(path).casefold()))


def _redact_log_file(
    source: Path,
    destination: Path,
    patterns: tuple[re.Pattern[str], ...],
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        source.open("r", encoding="utf-8", errors="replace") as input_file,
        destination.open("w", encoding="utf-8", newline="\n") as output_file,
    ):
        for line in input_file:
            raw_line = line.rstrip("\r\n")
            if not raw_line:
                continue
            try:
                parsed = json.loads(raw_line)
            except json.JSONDecodeError:
                payload: object = {
                    "event_code": "LEGACY_LOG_LINE",
                    "message": _redact_literals(sanitize_log_text(raw_line), patterns),
                }
            else:
                if isinstance(parsed, Mapping):
                    payload = _sanitize_bundle_value("log_record", parsed, patterns)
                else:
                    payload = {
                        "event_code": "LEGACY_LOG_LINE",
                        "message": _sanitize_bundle_value(
                            "legacy_log_value", parsed, patterns
                        ),
                    }
            output_file.write(_json_bytes(payload).decode("utf-8"))
    with contextlib.suppress(OSError):
        os.chmod(destination, 0o600)


def _member(archive_path: str, source_path: Path) -> _BundleMember:
    return _BundleMember(
        archive_path=archive_path,
        source_path=source_path,
        sha256=_sha256_file(source_path),
        size_bytes=source_path.stat().st_size,
    )


def _zip_timestamp(value: datetime) -> tuple[int, int, int, int, int, int]:
    utc_value = value.astimezone(UTC)
    year = max(1980, min(2107, utc_value.year))
    return (
        year,
        utc_value.month,
        utc_value.day,
        utc_value.hour,
        utc_value.minute,
        utc_value.second,
    )


def _write_zip_member(
    archive: zipfile.ZipFile,
    member: _BundleMember,
    reviewed_at: datetime,
) -> None:
    info = zipfile.ZipInfo(member.archive_path, date_time=_zip_timestamp(reviewed_at))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o600 & 0xFFFF) << 16
    archive.writestr(
        info,
        member.source_path.read_bytes(),
        compress_type=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    )


def create_support_bundle(
    destination: Path,
    *,
    log_files: Sequence[Path],
    version_manifest: Mapping[str, object],
    schema_history: Sequence[Mapping[str, object]],
    integrity_results: Mapping[str, object],
    configuration: Mapping[str, object],
    sensitive_values: Sequence[str],
    disclosure_reviewed_by: str,
    disclosure_reviewed_at: datetime,
) -> SupportBundleResult:
    """Create one bounded, disclosure-reviewed support archive."""

    reviewer = disclosure_reviewed_by.strip()
    if not reviewer:
        raise SupportBundleValidationError("Disclosure review requires a reviewer identity.")
    if disclosure_reviewed_at.utcoffset() is None:
        raise SupportBundleValidationError("Disclosure review time must be timezone-aware.")
    if destination.exists():
        raise SupportBundleValidationError("Support bundle destination already exists.")

    sources = _validate_log_sources(log_files)
    patterns = _compile_sensitive_literals(sensitive_values)
    destination.parent.mkdir(parents=True, exist_ok=True)

    archive_sha256 = ""
    archive_size = 0
    with tempfile.TemporaryDirectory(
        prefix=".animal-tracking-support-", dir=destination.parent
    ) as temporary_directory:
        workspace = Path(temporary_directory)
        members: list[_BundleMember] = []

        for index, source in enumerate(sources, start=1):
            redacted_path = workspace / "logs" / f"redacted-{index:03d}.jsonl"
            _redact_log_file(source, redacted_path, patterns)
            members.append(_member(f"logs/redacted-{index:03d}.jsonl", redacted_path))

        metadata_payloads: tuple[tuple[str, object], ...] = (
            (
                "metadata/version.json",
                _sanitize_bundle_value("version_manifest", version_manifest, patterns),
            ),
            (
                "metadata/schema-history.json",
                _sanitize_bundle_value("schema_history", schema_history, patterns),
            ),
            (
                "metadata/integrity-results.json",
                _sanitize_bundle_value("integrity_results", integrity_results, patterns),
            ),
            (
                "metadata/configuration.json",
                _sanitize_bundle_value("configuration", configuration, patterns),
            ),
        )
        for archive_path, payload in metadata_payloads:
            source_path = workspace / archive_path
            _write_restricted(source_path, _json_bytes(payload))
            members.append(_member(archive_path, source_path))

        reviewed_at = disclosure_reviewed_at.astimezone(UTC)
        manifest_payload = {
            "bundle_schema": _BUNDLE_SCHEMA,
            "created_at": reviewed_at.isoformat().replace("+00:00", "Z"),
            "disclosure_review": {
                "status": "COMPLETED",
                "reviewed_by": sanitize_log_text(reviewer),
                "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
            },
            "excluded_by_default": [
                "backup_contents",
                "exact_coordinates",
                "maps",
                "media",
                "private_paths",
                "secrets",
            ],
            "source_log_count": len(sources),
            "members": [
                {
                    "path": member.archive_path,
                    "sha256": member.sha256,
                    "size_bytes": member.size_bytes,
                }
                for member in sorted(members, key=lambda item: item.archive_path)
            ],
        }
        manifest_path = workspace / "manifest.json"
        _write_restricted(manifest_path, _json_bytes(manifest_payload))
        members.append(_member("manifest.json", manifest_path))

        with tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as archive_file:
            temporary_archive = Path(archive_file.name)
        with contextlib.suppress(OSError):
            os.chmod(temporary_archive, 0o600)

        archive_activated = False
        try:
            with zipfile.ZipFile(
                temporary_archive,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for member in sorted(members, key=lambda item: item.archive_path):
                    _write_zip_member(archive, member, reviewed_at)
            archive_sha256 = _sha256_file(temporary_archive)
            archive_size = temporary_archive.stat().st_size
            os.replace(temporary_archive, destination)
            archive_activated = True
            with contextlib.suppress(OSError):
                os.chmod(destination, 0o600)
        finally:
            if not archive_activated:
                temporary_archive.unlink(missing_ok=True)

    return SupportBundleResult(
        path=destination,
        sha256=archive_sha256,
        member_count=len(members),
        byte_count=archive_size,
    )
