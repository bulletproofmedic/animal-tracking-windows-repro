from __future__ import annotations

import contextlib
import json
import logging
import os
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType

_LOG_FILENAME = "animal-tracking.log"
_LOG_MAX_BYTES = 10 * 1024 * 1024
# RotatingFileHandler retains the active file in addition to backupCount files.
_LOG_BACKUP_COUNT = 9
_REDACTED = "<redacted>"
_BINARY_REDACTED = "<binary-redacted>"
_PATH_REDACTED = "<path-redacted>"
_COORDINATES_REDACTED = "<coordinates-redacted>"

_SENSITIVE_KEY_PARTS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "csrf",
    "exception_detail",
    "filename",
    "latitude",
    "longitude",
    "notes",
    "original_filename",
    "owner_note",
    "password",
    "passwd",
    "pin",
    "property_name",
    "secret",
    "session",
    "stack",
    "token",
    "traceback",
}

_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key
        |authorization
        |bearer
        |cookie
        |credential
        |csrf(?:middleware)?token
        |password
        |passwd
        |pin
        |secret
        |session(?:id)?
        |token
    )\b
    \s*[:=]\s*
    (
        "(?:[^"\\]|\\.)*"
        |'(?:[^'\\]|\\.)*'
        |[^\s,;]+
    )
    """
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_LABELED_COORDINATE = re.compile(
    r"""(?ix)
    \b(latitude|longitude|lat|lon|lng)\b
    \s*[:=]\s*
    [-+]?(?:\d{1,3}(?:\.\d+)?|\.\d+)
    """
)
_COORDINATE_PAIR = re.compile(
    r"""(?x)
    (?<![\w.])
    [-+]?(?:\d{1,2}(?:\.\d{4,})?|1[0-7]\d(?:\.\d{4,})?|180(?:\.0{4,})?)
    \s*[,/]\s*
    [-+]?(?:\d{1,2}(?:\.\d{4,})?|1[0-7]\d(?:\.\d{4,})?|180(?:\.0{4,})?)
    (?![\w.])
    """
)
_WINDOWS_PATH = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9])
    (?:
        [A-Z]:[\\/](?:[^<>"|?*\r\n]+)
        |\\\\[^\\/\s]+[\\/][^<>"|?*\r\n]+
    )
    """
)
_POSIX_PATH = re.compile(
    r"""(?x)
    (?<![:/A-Za-z0-9])
    /(?:home|Users|private|var|tmp|opt|srv|mnt|media)/[^\s,;]+
    """
)

ExcInfo = (
    bool | BaseException | tuple[type[BaseException], BaseException, TracebackType | None] | None
)


def _contains_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def sanitize_log_text(value: str) -> str:
    """Remove credential, coordinate, and private-path patterns from text."""

    redacted = _BEARER_TOKEN.sub("Bearer " + _REDACTED, value)
    redacted = _CREDENTIAL_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}={_REDACTED}",
        redacted,
    )
    redacted = _LABELED_COORDINATE.sub(
        lambda match: f"{match.group(1)}={_COORDINATES_REDACTED}",
        redacted,
    )
    redacted = _COORDINATE_PAIR.sub(_COORDINATES_REDACTED, redacted)
    redacted = _WINDOWS_PATH.sub(_PATH_REDACTED, redacted)
    return _POSIX_PATH.sub(_PATH_REDACTED, redacted)


def sanitize_log_value(key: str, value: object) -> object:
    """Sanitize one structured value before it is rendered or exported."""

    if _contains_sensitive_key(key):
        return _REDACTED
    if isinstance(value, Path):
        return _PATH_REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_log_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _BINARY_REDACTED
    if isinstance(value, Mapping):
        return {
            str(nested_key): sanitize_log_value(str(nested_key), nested_value)
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, Sequence):
        return [sanitize_log_value(key, item) for item in value]
    return sanitize_log_text(str(value))


def _default_event_code(record: logging.LogRecord) -> str:
    component = re.sub(r"[^A-Z0-9]+", "_", record.name.upper()).strip("_")
    return f"LOG_{component or 'ROOT'}_{record.levelname}"


class SafeJsonFormatter(logging.Formatter):
    """Emit one privacy-filtered JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z")
        )
        event_code = str(getattr(record, "event_code", _default_event_code(record)))
        correlation_id = getattr(record, "correlation_id", None)
        record_id = getattr(record, "record_id", None)
        safe_fields = getattr(record, "safe_fields", None)

        payload: dict[str, object] = {
            "timestamp": timestamp,
            "severity": record.levelname,
            "event_code": sanitize_log_text(event_code),
            "component": sanitize_log_text(record.name),
            "message": sanitize_log_text(record.getMessage()),
        }
        if correlation_id:
            payload["correlation_id"] = sanitize_log_value("correlation_id", correlation_id)
        if record_id:
            payload["record_id"] = sanitize_log_value("record_id", record_id)
        if isinstance(safe_fields, Mapping):
            payload["fields"] = {
                str(key): sanitize_log_value(str(key), value)
                for key, value in safe_fields.items()
            }
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception_class"] = record.exc_info[0].__name__

        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def log_event(
    logger: logging.Logger,
    level: int,
    event_code: str,
    message: str,
    *,
    correlation_id: str | None = None,
    record_id: str | None = None,
    fields: Mapping[str, object] | None = None,
    exc_info: ExcInfo = None,
) -> None:
    """Write one structured event through the privacy-filtering formatter."""

    extra: dict[str, object] = {"event_code": event_code}
    if correlation_id is not None:
        extra["correlation_id"] = correlation_id
    if record_id is not None:
        extra["record_id"] = record_id
    if fields is not None:
        extra["safe_fields"] = dict(fields)
    logger.log(level, message, extra=extra, exc_info=exc_info)


def _build_handler(handler: logging.Handler) -> logging.Handler:
    handler.setFormatter(SafeJsonFormatter())
    return handler


def configure_logging(log_directory: Path | None = None) -> None:
    handlers: list[logging.Handler] = [_build_handler(logging.StreamHandler())]
    if log_directory is not None:
        log_directory.mkdir(parents=True, exist_ok=True)
        log_path = log_directory / _LOG_FILENAME
        log_path.touch(mode=0o600, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(log_path, 0o600)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handlers.append(_build_handler(file_handler))
    logging.basicConfig(
        level=logging.INFO,
        handlers=handlers,
        force=True,
    )
