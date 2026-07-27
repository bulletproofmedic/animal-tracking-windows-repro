from __future__ import annotations

import json
import logging
import os
import stat
import sys
from pathlib import Path

from logging_config import SafeJsonFormatter, configure_logging, log_event


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
                "password=example-password Bearer example.token "
                "latitude=12.345678 longitude=45.678901 "
                r"path=C:\Users\Example\private.sqlite3",
                event_code="SEC-TEST",
                safe_fields={
                    "api_key": "example-api-key",
                    "database_path": Path("/home/example/private.sqlite3"),
                    "nested": {"session_token": "example-session"},
                    "raw": b"example-bytes",
                    "property_name": "Example Property",
                    "original_filename": "IMAGE_0001.JPG",
                    "owner_notes": "example private note",
                    "traceback": r"failed at C:\Users\Example\secret.txt",
                },
            )
        )
    )
    rendered = json.dumps(payload, sort_keys=True)

    for forbidden in (
        "example-password",
        "example.token",
        "12.345678",
        "45.678901",
        "Example",
        "example-api-key",
        "example-session",
        "example-bytes",
        "Example Property",
        "IMAGE_0001.JPG",
        "example private note",
        "secret.txt",
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
    # Active file plus nine backups equals the governed ten-file retention.
    assert handler.backupCount == 9

    log_path = tmp_path / "animal-tracking.log"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "Configured"
    if os.name != "nt":
        assert stat.S_IMODE(log_path.stat().st_mode) == 0o600

    for configured_handler in root.handlers:
        configured_handler.close()
    root.handlers.clear()
