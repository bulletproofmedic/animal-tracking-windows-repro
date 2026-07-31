from __future__ import annotations

import json
import logging
import math
import os
import stat
import sys
from pathlib import Path

from animal_tracking.logging_config import (
    ProtectedRotatingFileHandler,
    SafeJsonFormatter,
    configure_logging,
    log_event,
)


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


def _strict_json(value: str) -> dict[str, object]:
    def reject_constant(constant: str) -> object:
        raise ValueError(constant)

    parsed = json.loads(value, parse_constant=reject_constant)
    assert isinstance(parsed, dict)
    return parsed


def test_safe_json_formatter_emits_required_fields_and_closed_safe_fields() -> None:
    payload = _strict_json(
        SafeJsonFormatter().format(
            _record(
                "Started",
                event_code="APP-START",
                correlation_id="corr-1",
                record_id="record-1",
                safe_fields={
                    "status": "READY",
                    "count": 2,
                    "unknown": "must not survive",
                    "private_key": "secret",
                },
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
    assert str(payload["timestamp"]).endswith("Z")


def test_safe_json_formatter_assigns_stable_default_event_code() -> None:
    payload = _strict_json(SafeJsonFormatter().format(_record("Started")))
    assert payload["event_code"] == "LOG_ANIMAL_TRACKING_TEST_INFO"


def test_safe_json_formatter_redacts_adversarial_text_and_structured_values() -> None:
    message = (
        '{"password":"hunter2"} '
        "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44=fullwidth-secret "
        "pass\u200bword=hidden-secret "
        "Authorization Basic dXNlcjpwYXNz "
        "43.812346 -78.212346 "
        "//server/share/private.sqlite3 "
        "North Field Property IMG_0001.JPG"
    )
    payload = _strict_json(
        SafeJsonFormatter().format(
            _record(
                message,
                event_code="SEC-TEST",
                safe_fields={
                    "status": "password=structured-secret",
                    "coordinates": [43.8, -78.2],
                    "private_key": "private-secret",
                    "duration_ms": math.nan,
                },
            )
        )
    )
    rendered = json.dumps(payload, sort_keys=True, allow_nan=False)

    for forbidden in (
        "hunter2",
        "fullwidth-secret",
        "hidden-secret",
        "dXNlcjpwYXNz",
        "43.812346",
        "-78.212346",
        "server/share",
        "North Field Property",
        "IMG_0001.JPG",
        "structured-secret",
        "private-secret",
        "NaN",
    ):
        assert forbidden not in rendered
    assert "<non-finite-number>" in rendered


def test_safe_json_formatter_records_exception_class_without_detail() -> None:
    try:
        raise RuntimeError(r"failed at C:\Users\Example\secret.txt")
    except RuntimeError:
        exc_info = sys.exc_info()

    record = _record("Operation failed", event_code="APP-FAIL")
    record.exc_info = exc_info
    rendered = SafeJsonFormatter().format(record)
    payload = _strict_json(rendered)

    assert payload["exception_class"] == "RuntimeError"
    assert "Example" not in rendered
    assert "secret.txt" not in rendered


def test_safe_json_formatter_uses_minimal_fallback_for_serialization_failure() -> None:
    class Unprintable:
        def __str__(self) -> str:
            raise RuntimeError("secret detail")

    payload = _strict_json(
        SafeJsonFormatter().format(_record("safe", event_code=Unprintable()))
    )
    assert payload["event_code"] == "LOG_SERIALIZATION_FAILURE"
    assert payload["message"] == "Log event could not be serialized safely"
    assert "secret detail" not in json.dumps(payload)


def test_log_event_populates_only_registered_structured_extras() -> None:
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
        fields={"status": "PASS", "unknown": "private"},
    )

    assert len(captured) == 1
    assert captured[0].event_code == "AT-TEST-001"
    assert captured[0].correlation_id == "corr-2"
    assert captured[0].record_id == "record-2"
    assert captured[0].safe_fields == {"status": "PASS"}


def test_configure_logging_reprotects_active_and_rotated_files(tmp_path: Path) -> None:
    configure_logging(tmp_path)
    root = logging.getLogger()
    file_handlers = [
        handler for handler in root.handlers if isinstance(handler, ProtectedRotatingFileHandler)
    ]
    assert len(file_handlers) == 1
    handler = file_handlers[0]
    handler.maxBytes = 1

    logger = logging.getLogger("animal_tracking.rotation-test")
    for index in range(14):
        logger.info("rotation event %s", index)
    handler.flush()

    log_files = sorted(tmp_path.glob("animal-tracking.log*"))
    assert 2 <= len(log_files) <= 10
    assert handler.backupCount == 9
    for path in log_files:
        lines = path.read_text(encoding="utf-8").splitlines()
        assert all(_strict_json(line) for line in lines)
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    if os.name != "nt":
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700

    for configured_handler in root.handlers:
        configured_handler.close()
    root.handlers.clear()
