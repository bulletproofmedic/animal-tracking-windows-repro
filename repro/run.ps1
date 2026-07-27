$ErrorActionPreference = "Stop"

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22

@'
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
_LOG_BACKUP_COUNT = 10
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
    "latitude",
    "longitude",
    "password",
    "passwd",
    "pin",
    "secret",
    "session",
    "token",
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
    bool
    | BaseException
    | tuple[type[BaseException], BaseException, TracebackType | None]
    | None
)


def _contains_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact_text(value: str) -> str:
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


def _sanitize_value(key: str, value: object) -> object:
    if _contains_sensitive_key(key):
        return _REDACTED
    if isinstance(value, Path):
        return _PATH_REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _BINARY_REDACTED
    if isinstance(value, Mapping):
        return {
            str(nested_key): _sanitize_value(str(nested_key), nested_value)
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, Sequence):
        return [_sanitize_value(key, item) for item in value]
    return _redact_text(str(value))


def _default_event_code(record: logging.LogRecord) -> str:
    component = re.sub(r"[^A-Z0-9]+", "_", record.name.upper()).strip("_")
    return f"LOG_{component or 'ROOT'}_{record.levelname}"


class SafeJsonFormatter(logging.Formatter):
    """Emit one privacy-filtered JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        event_code = str(getattr(record, "event_code", _default_event_code(record)))
        correlation_id = getattr(record, "correlation_id", None)
        record_id = getattr(record, "record_id", None)
        safe_fields = getattr(record, "safe_fields", None)

        payload: dict[str, object] = {
            "timestamp": timestamp,
            "severity": record.levelname,
            "event_code": _redact_text(event_code),
            "component": _redact_text(record.name),
            "message": _redact_text(record.getMessage()),
        }
        if correlation_id:
            payload["correlation_id"] = _sanitize_value(
                "correlation_id", correlation_id
            )
        if record_id:
            payload["record_id"] = _sanitize_value("record_id", record_id)
        if isinstance(safe_fields, Mapping):
            payload["fields"] = {
                str(key): _sanitize_value(str(key), value)
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

'@ | Set-Content -Encoding utf8 repro/logging_config.py

@'
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from animal_tracking.logging_config import SafeJsonFormatter, configure_logging, log_event


def _record(message: str, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="animal_tracking.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_safe_json_formatter_emits_required_fields() -> None:
    payload = json.loads(
        SafeJsonFormatter().format(
            _record(
                "Started",
                event_code="APP-START",
                correlation_id="corr-1",
                record_id="record-1",
                safe_fields={"status": "READY", "count": 2},
            )
        )
    )

    assert payload["severity"] == "INFO"
    assert payload["event_code"] == "APP-START"
    assert payload["component"] == "animal_tracking.test"
    assert payload["message"] == "Started"
    assert payload["correlation_id"] == "corr-1"
    assert payload["record_id"] == "record-1"
    assert payload["fields"] == {"count": 2, "status": "READY"}
    assert payload["timestamp"].endswith("Z")


def test_safe_json_formatter_assigns_stable_default_event_code() -> None:
    payload = json.loads(SafeJsonFormatter().format(_record("Started")))

    assert payload["event_code"] == "LOG_ANIMAL_TRACKING_TEST_INFO"


def test_safe_json_formatter_redacts_sensitive_values() -> None:
    payload = json.loads(
        SafeJsonFormatter().format(
            _record(
                (
                    "password=hunter2 Bearer abc.def "
                    "latitude=43.912345 longitude=-78.112345 "
                    r"path=C:\Users\Example\private.sqlite3"
                ),
                event_code="SEC-TEST",
                safe_fields={
                    "api_key": "should-not-appear",
                    "database_path": Path("/home/example/private.sqlite3"),
                    "nested": {"session_token": "secret-value"},
                    "raw": b"private-bytes",
                },
            )
        )
    )
    rendered = json.dumps(payload, sort_keys=True)

    for forbidden in (
        "hunter2",
        "abc.def",
        "43.912345",
        "-78.112345",
        "Example",
        "should-not-appear",
        "secret-value",
        "private-bytes",
    ):
        assert forbidden not in rendered
    assert "<redacted>" in rendered
    assert "<coordinates-redacted>" in rendered
    assert "<path-redacted>" in rendered
    assert "<binary-redacted>" in rendered


def test_safe_json_formatter_records_exception_class_without_detail() -> None:
    try:
        raise RuntimeError(r"failed at C:\Users\Example\secret.txt")
    except RuntimeError:
        exc_info = sys.exc_info()

    record = _record("Operation failed", event_code="APP-FAIL")
    record.exc_info = exc_info
    rendered = SafeJsonFormatter().format(record)
    payload = json.loads(rendered)

    assert payload["exception_class"] == "RuntimeError"
    assert "Example" not in rendered
    assert "secret.txt" not in rendered


def test_log_event_populates_structured_extras() -> None:
    logger = logging.getLogger("animal_tracking.event-test")
    logger.handlers.clear()
    logger.propagate = False
    captured: list[logging.LogRecord] = []

    class CaptureHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    logger.addHandler(CaptureHandler())
    logger.setLevel(logging.INFO)

    log_event(
        logger,
        logging.INFO,
        "AT-TEST-001",
        "Completed",
        correlation_id="corr-2",
        record_id="record-2",
        fields={"status": "PASS"},
    )

    assert len(captured) == 1
    assert captured[0].event_code == "AT-TEST-001"
    assert captured[0].correlation_id == "corr-2"
    assert captured[0].record_id == "record-2"
    assert captured[0].safe_fields == {"status": "PASS"}


def test_configure_logging_writes_json_lines_with_governed_rotation(tmp_path: Path) -> None:
    configure_logging(tmp_path)
    logging.getLogger("animal_tracking.config-test").info("Configured")

    root = logging.getLogger()
    file_handlers = [
        handler
        for handler in root.handlers
        if isinstance(handler, logging.handlers.RotatingFileHandler)
    ]
    assert len(file_handlers) == 1
    handler = file_handlers[0]
    handler.flush()

    assert handler.maxBytes == 10 * 1024 * 1024
    assert handler.backupCount == 10

    lines = (tmp_path / "animal-tracking.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "Configured"

    for configured_handler in root.handlers:
        configured_handler.close()
    root.handlers.clear()

'@ | Set-Content -Encoding utf8 repro/test_logging_config.py

python -m ruff format --diff repro/logging_config.py repro/test_logging_config.py
