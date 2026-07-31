from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from animal_tracking.logging_config import (
    ExcInfo,
    ProtectedRotatingFileHandler,
    SafeJsonFormatter,
    configure_logging,
    log_event,
    protect_private_directory,
    protect_private_file,
)

_MINIMUM_LOG_FILENAME = "security-bootstrap.log"
_MINIMUM_LOG_MAX_BYTES = 1024 * 1024
_MINIMUM_LOG_BACKUP_COUNT = 1
_ACKNOWLEDGEMENT_TAIL_BYTES = 128 * 1024
_SECURITY_LOGGING_LOCK = threading.RLock()
_CORRELATION_ID = re.compile(r"[0-9a-f]{32}")
_ACTIVE_CORRELATION_ID: ContextVar[str | None] = ContextVar(
    "animal_tracking_security_correlation_id",
    default=None,
)


class SecurityEventCode(StrEnum):
    """Closed Release 1 application-security event taxonomy."""

    LOGGER_MINIMUM_READY = "SEC_LOGGER_MINIMUM_READY"
    LOGGER_COMPLETE_READY = "SEC_LOGGER_COMPLETE_READY"
    HOST_REJECTED = "SEC_HOST_REJECTED"
    ORIGIN_REJECTED = "SEC_ORIGIN_REJECTED"
    CSRF_REJECTED = "SEC_CSRF_REJECTED"
    STARTUP_FAILED = "SEC_STARTUP_FAILED"
    RECOVERY_ACTIVATION_FAILED = "SEC_RECOVERY_ACTIVATION_FAILED"
    RECOVERY_ROLLBACK_FAILED = "SEC_RECOVERY_ROLLBACK_FAILED"
    RECOVERY_FINALIZATION_FAILED = "SEC_RECOVERY_FINALIZATION_FAILED"
    INTEGRITY_FAILED = "SEC_INTEGRITY_FAILED"
    PERMISSION_FAILED = "SEC_PERMISSION_FAILED"
    SUPPORT_BUNDLE_CREATE_STARTED = "SEC_SUPPORT_BUNDLE_CREATE_STARTED"
    SUPPORT_BUNDLE_CREATE_SUCCEEDED = "SEC_SUPPORT_BUNDLE_CREATE_SUCCEEDED"
    SUPPORT_BUNDLE_CREATE_FAILED = "SEC_SUPPORT_BUNDLE_CREATE_FAILED"
    SUPPORT_BUNDLE_DISCLOSURE_RECORDED = "SEC_SUPPORT_BUNDLE_DISCLOSURE_RECORDED"
    SUPPORT_BUNDLE_DISCLOSURE_REJECTED = "SEC_SUPPORT_BUNDLE_DISCLOSURE_REJECTED"
    CONTROL_DEGRADED = "SEC_CONTROL_DEGRADED"
    CONTROL_UNAVAILABLE = "SEC_CONTROL_UNAVAILABLE"


class SecurityReasonCode(StrEnum):
    """Closed reason vocabulary; values contain no caller-controlled data."""

    NON_LOOPBACK_HOST = "NON_LOOPBACK_HOST"
    NON_LOOPBACK_ORIGIN = "NON_LOOPBACK_ORIGIN"
    NON_LOOPBACK_REFERER = "NON_LOOPBACK_REFERER"
    CSRF_VALIDATION_FAILED = "CSRF_VALIDATION_FAILED"
    RUNTIME_VALIDATION_FAILED = "RUNTIME_VALIDATION_FAILED"
    SETTINGS_LOAD_FAILED = "SETTINGS_LOAD_FAILED"
    RESTORE_ACTIVATION_FAILED = "RESTORE_ACTIVATION_FAILED"
    RUNTIME_PREPARATION_FAILED = "RUNTIME_PREPARATION_FAILED"
    COMPLETE_LOGGER_TRANSITION_FAILED = "COMPLETE_LOGGER_TRANSITION_FAILED"
    SECURITY_LOGGER_NOT_COMPLETE = "SECURITY_LOGGER_NOT_COMPLETE"
    LOOPBACK_PORT_UNAVAILABLE = "LOOPBACK_PORT_UNAVAILABLE"
    CHROME_UNAVAILABLE = "CHROME_UNAVAILABLE"
    PLATFORM_UNSUPPORTED = "PLATFORM_UNSUPPORTED"
    INSTANCE_LOCK_FAILED = "INSTANCE_LOCK_FAILED"
    DJANGO_PREFLIGHT_FAILED = "DJANGO_PREFLIGHT_FAILED"
    RESTORE_FINALIZATION_FAILED = "RESTORE_FINALIZATION_FAILED"
    RESTORE_ROLLBACK_FAILED = "RESTORE_ROLLBACK_FAILED"
    SERVER_START_FAILED = "SERVER_START_FAILED"
    READINESS_CHECK_FAILED = "READINESS_CHECK_FAILED"
    BROWSER_START_FAILED = "BROWSER_START_FAILED"
    PERMISSION_CONTROL_FAILED = "PERMISSION_CONTROL_FAILED"
    SUPPORT_BUNDLE_VALIDATION_FAILED = "SUPPORT_BUNDLE_VALIDATION_FAILED"
    SUPPORT_BUNDLE_PERMISSION_FAILED = "SUPPORT_BUNDLE_PERMISSION_FAILED"
    SUPPORT_BUNDLE_IO_FAILED = "SUPPORT_BUNDLE_IO_FAILED"
    SUPPORT_BUNDLE_ASSURANCE_LIMITED = "SUPPORT_BUNDLE_ASSURANCE_LIMITED"
    UNEXPECTED_FAILURE = "UNEXPECTED_FAILURE"


class SecurityOperation(StrEnum):
    """Closed operation vocabulary used by safe structured fields."""

    LOGGING = "LOGGING"
    HOST_VALIDATION = "HOST_VALIDATION"
    ORIGIN_VALIDATION = "ORIGIN_VALIDATION"
    CSRF_VALIDATION = "CSRF_VALIDATION"
    STARTUP = "STARTUP"
    SETTINGS = "SETTINGS"
    RECOVERY = "RECOVERY"
    INTEGRITY = "INTEGRITY"
    PERMISSIONS = "PERMISSIONS"
    SUPPORT_BUNDLE = "SUPPORT_BUNDLE"
    SERVER = "SERVER"
    BROWSER = "BROWSER"


class SecurityOutcome(StrEnum):
    """Closed outcome vocabulary."""

    READY = "READY"
    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    RECORDED = "RECORDED"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class SecurityLoggingStage(StrEnum):
    UNINITIALIZED = "UNINITIALIZED"
    MINIMUM = "MINIMUM"
    COMPLETE = "COMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


class SecurityEventSinkError(RuntimeError):
    """Raised when a mandatory security event cannot be durably acknowledged."""


@dataclass(frozen=True, slots=True)
class SecurityEventDetails:
    """The only structured values accepted by the security-event gateway."""

    operation: SecurityOperation
    outcome: SecurityOutcome
    reason_code: SecurityReasonCode | None = None
    status: SecurityLoggingStage | None = None
    count: int | None = None
    file_count: int | None = None
    member_count: int | None = None
    byte_count: int | None = None
    duration_ms: float | None = None
    enabled: bool | None = None

    def as_fields(self) -> dict[str, object]:
        fields: dict[str, object] = {
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }
        if self.reason_code is not None:
            fields["reason_code"] = self.reason_code.value
        if self.status is not None:
            fields["status"] = self.status.value
        for name, value in (
            ("count", self.count),
            ("file_count", self.file_count),
            ("member_count", self.member_count),
            ("byte_count", self.byte_count),
        ):
            if value is None:
                continue
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer.")
            fields[name] = value
        if self.duration_ms is not None:
            if not math.isfinite(self.duration_ms) or self.duration_ms < 0:
                raise ValueError("duration_ms must be a finite non-negative number.")
            fields["duration_ms"] = self.duration_ms
        if self.enabled is not None:
            fields["enabled"] = self.enabled
        return fields


@dataclass(frozen=True, slots=True)
class _EventSpec:
    level: int
    component: str
    message: str


_EVENT_SPECS: dict[SecurityEventCode, _EventSpec] = {
    SecurityEventCode.LOGGER_MINIMUM_READY: _EventSpec(
        logging.INFO,
        "animal_tracking.security.logging",
        "Minimum security logger is ready",
    ),
    SecurityEventCode.LOGGER_COMPLETE_READY: _EventSpec(
        logging.INFO,
        "animal_tracking.security.logging",
        "Complete security logger is ready",
    ),
    SecurityEventCode.HOST_REJECTED: _EventSpec(
        logging.WARNING,
        "animal_tracking.security.web",
        "A request failed Host validation",
    ),
    SecurityEventCode.ORIGIN_REJECTED: _EventSpec(
        logging.WARNING,
        "animal_tracking.security.web",
        "A mutation failed Origin or Referer validation",
    ),
    SecurityEventCode.CSRF_REJECTED: _EventSpec(
        logging.WARNING,
        "animal_tracking.security.web",
        "A request failed CSRF validation",
    ),
    SecurityEventCode.STARTUP_FAILED: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.startup",
        "Application startup failed safely",
    ),
    SecurityEventCode.RECOVERY_ACTIVATION_FAILED: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.recovery",
        "Pending recovery activation failed safely",
    ),
    SecurityEventCode.RECOVERY_ROLLBACK_FAILED: _EventSpec(
        logging.CRITICAL,
        "animal_tracking.security.recovery",
        "Recovery rollback failed safely",
    ),
    SecurityEventCode.RECOVERY_FINALIZATION_FAILED: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.recovery",
        "Recovery finalization failed safely",
    ),
    SecurityEventCode.INTEGRITY_FAILED: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.integrity",
        "An integrity control failed",
    ),
    SecurityEventCode.PERMISSION_FAILED: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.permissions",
        "A required permission control failed",
    ),
    SecurityEventCode.SUPPORT_BUNDLE_CREATE_STARTED: _EventSpec(
        logging.INFO,
        "animal_tracking.security.support",
        "Support-bundle creation started",
    ),
    SecurityEventCode.SUPPORT_BUNDLE_CREATE_SUCCEEDED: _EventSpec(
        logging.INFO,
        "animal_tracking.security.support",
        "Support-bundle creation completed",
    ),
    SecurityEventCode.SUPPORT_BUNDLE_CREATE_FAILED: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.support",
        "Support-bundle creation failed safely",
    ),
    SecurityEventCode.SUPPORT_BUNDLE_DISCLOSURE_RECORDED: _EventSpec(
        logging.INFO,
        "animal_tracking.security.support",
        "Support-bundle disclosure review was recorded",
    ),
    SecurityEventCode.SUPPORT_BUNDLE_DISCLOSURE_REJECTED: _EventSpec(
        logging.WARNING,
        "animal_tracking.security.support",
        "Support-bundle disclosure action was rejected",
    ),
    SecurityEventCode.CONTROL_DEGRADED: _EventSpec(
        logging.WARNING,
        "animal_tracking.security.controls",
        "A security control entered a degraded state",
    ),
    SecurityEventCode.CONTROL_UNAVAILABLE: _EventSpec(
        logging.ERROR,
        "animal_tracking.security.controls",
        "A required security control is unavailable",
    ),
}

_logging_stage = SecurityLoggingStage.UNINITIALIZED
_logging_data_root: Path | None = None
_minimum_log_directory: Path | None = None
_complete_log_directory: Path | None = None


class _RenderedEventCapture(logging.Filter):
    """Capture the exact formatter output for one handler and one record."""

    def __init__(self, record_id: str, handler: ProtectedRotatingFileHandler) -> None:
        super().__init__()
        self.record_id = record_id
        self.handler = handler
        self.rendered: bytes | None = None

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "record_id", None) == self.record_id:
            rendered = self.handler.format(record)
            self.rendered = rendered.encode("utf-8", errors="strict")
        return True


def new_security_correlation_id() -> str:
    return uuid4().hex


def _validated_correlation_id(value: str | None) -> str:
    candidate = value if value is not None else _ACTIVE_CORRELATION_ID.get()
    if candidate is None:
        candidate = new_security_correlation_id()
    if _CORRELATION_ID.fullmatch(candidate) is None:
        raise ValueError(
            "Security correlation identifiers must be 32 lowercase hexadecimal characters."
        )
    return candidate


@contextmanager
def security_event_correlation(correlation_id: str | None = None) -> Iterator[str]:
    """Propagate one bounded identifier across a related security-event sequence."""

    validated = _validated_correlation_id(correlation_id)
    token: Token[str | None] = _ACTIVE_CORRELATION_ID.set(validated)
    try:
        yield validated
    finally:
        _ACTIVE_CORRELATION_ID.reset(token)


def _emergency_unavailable_notice() -> None:
    payload = {
        "component": "animal_tracking.security.controls",
        "event_code": SecurityEventCode.CONTROL_UNAVAILABLE.value,
        "fields": {
            "operation": SecurityOperation.LOGGING.value,
            "outcome": SecurityOutcome.UNAVAILABLE.value,
            "reason_code": SecurityReasonCode.PERMISSION_CONTROL_FAILED.value,
        },
        "message": "A required security control is unavailable",
        "severity": "ERROR",
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    try:
        sys.stderr.write(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        )
        sys.stderr.flush()
    except Exception:
        pass


def _mark_logging_unavailable() -> SecurityEventSinkError:
    global _logging_stage
    with _SECURITY_LOGGING_LOCK:
        _logging_stage = SecurityLoggingStage.UNAVAILABLE
    _emergency_unavailable_notice()
    return SecurityEventSinkError("A mandatory security event could not be persisted safely.")


def _protected_handlers() -> tuple[ProtectedRotatingFileHandler, ...]:
    return tuple(
        handler
        for handler in logging.getLogger().handlers
        if isinstance(handler, ProtectedRotatingFileHandler)
    )


def _handler_identity_is_current(handler: ProtectedRotatingFileHandler) -> bool:
    stream = handler.stream
    if stream is None:
        return False
    path = Path(handler.baseFilename)
    if path.is_symlink() or not path.is_file():
        return False
    opened = os.fstat(stream.fileno())
    current = path.stat()
    if opened.st_dev != current.st_dev:
        return False
    if opened.st_ino and current.st_ino and opened.st_ino != current.st_ino:
        return False
    return True


def _bounded_tail_lines(path: Path) -> tuple[bytes, ...]:
    """Read no more than the fixed acknowledgement tail from one regular file."""

    if path.is_symlink() or not path.is_file():
        return ()
    try:
        with path.open("rb") as source:
            size = source.seek(0, os.SEEK_END)
            start = max(0, size - _ACKNOWLEDGEMENT_TAIL_BYTES)
            source.seek(start)
            payload = source.read(_ACKNOWLEDGEMENT_TAIL_BYTES)
    except OSError:
        return ()
    if start:
        separator = payload.find(b"\n")
        if separator < 0:
            return ()
        payload = payload[separator + 1 :]
    return tuple(payload.splitlines())


def _handler_contains_complete_event(
    expected_serialized_event: bytes,
    handler: ProtectedRotatingFileHandler,
) -> bool:
    """Require an exact serialized line in the bounded active-file tail."""

    return expected_serialized_event in _bounded_tail_lines(Path(handler.baseFilename))


@contextmanager
def _capture_handler_events(
    record_id: str,
    handlers: tuple[ProtectedRotatingFileHandler, ...],
) -> Iterator[dict[ProtectedRotatingFileHandler, _RenderedEventCapture]]:
    """Hold handler locks so the append and exact bounded acknowledgement are atomic."""

    captures: dict[ProtectedRotatingFileHandler, _RenderedEventCapture] = {}
    acquired: list[ProtectedRotatingFileHandler] = []
    try:
        for handler in handlers:
            handler.acquire()
            acquired.append(handler)
            capture = _RenderedEventCapture(record_id, handler)
            handler.addFilter(capture)
            captures[handler] = capture
        yield captures
    finally:
        for handler, capture in captures.items():
            handler.removeFilter(capture)
        for handler in reversed(acquired):
            handler.release()


def _acknowledge_durable_event(
    captures: dict[ProtectedRotatingFileHandler, _RenderedEventCapture],
) -> None:
    if not captures:
        raise SecurityEventSinkError("No protected security-event file handler is active.")
    for handler, capture in captures.items():
        if handler.stream is None:
            raise SecurityEventSinkError("A security-event handler has no open stream.")
        if capture.rendered is None:
            raise SecurityEventSinkError(
                "The security-event formatter did not produce the expected exact record."
            )
        handler.flush()
        os.fsync(handler.stream.fileno())
        if not _handler_identity_is_current(handler):
            raise SecurityEventSinkError("A security-event log path changed after initialization.")
        protect_private_file(Path(handler.baseFilename))
        if not _handler_contains_complete_event(capture.rendered, handler):
            raise SecurityEventSinkError(
                "The exact mandatory security event was not found after persistence."
            )


def emit_security_event(
    code: SecurityEventCode,
    details: SecurityEventDetails,
    *,
    correlation_id: str | None = None,
    exc_info: ExcInfo = None,
) -> None:
    """Synchronously persist one closed, privacy-safe, correlated security event."""

    if not isinstance(code, SecurityEventCode):
        raise TypeError("Security events require a SecurityEventCode value.")
    if not isinstance(details, SecurityEventDetails):
        raise TypeError("Security events require SecurityEventDetails.")
    spec = _EVENT_SPECS[code]
    record_id = uuid4().hex
    with _SECURITY_LOGGING_LOCK:
        if _logging_stage is SecurityLoggingStage.UNAVAILABLE:
            raise SecurityEventSinkError("Security-event logging is unavailable.")
        try:
            handlers = _protected_handlers()
            with _capture_handler_events(record_id, handlers) as captures:
                log_event(
                    logging.getLogger(spec.component),
                    spec.level,
                    code.value,
                    spec.message,
                    correlation_id=_validated_correlation_id(correlation_id),
                    record_id=record_id,
                    fields=details.as_fields(),
                    exc_info=exc_info,
                )
                _acknowledge_durable_event(captures)
        except Exception as error:
            raise _mark_logging_unavailable() from error


def _bootstrap_directory(data_root: Path) -> Path:
    return data_root.parent / f".{data_root.name}.security-bootstrap"


def _minimum_file_handler(log_directory: Path) -> ProtectedRotatingFileHandler:
    protect_private_directory(log_directory)
    log_path = log_directory / _MINIMUM_LOG_FILENAME
    if log_path.is_symlink():
        raise PermissionError("The minimum security log path cannot be a symbolic link.")
    flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(log_path, flags, 0o600)
    os.close(descriptor)
    protect_private_file(log_path)
    handler = ProtectedRotatingFileHandler(
        log_path,
        maxBytes=_MINIMUM_LOG_MAX_BYTES,
        backupCount=_MINIMUM_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(SafeJsonFormatter())
    return handler


def initialize_minimum_security_logging(data_root: Path) -> bool:
    """Create a bounded durable journal outside the root that recovery may replace."""

    global _complete_log_directory, _logging_data_root, _logging_stage, _minimum_log_directory
    resolved_root = data_root.expanduser().resolve()
    bootstrap_directory = _bootstrap_directory(resolved_root)
    with _SECURITY_LOGGING_LOCK:
        if _logging_stage is not SecurityLoggingStage.UNINITIALIZED:
            if resolved_root != _logging_data_root:
                raise RuntimeError("Security logging was already initialized for another data root.")
            return False
        try:
            file_handler = _minimum_file_handler(bootstrap_directory)
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(SafeJsonFormatter())
            logging.basicConfig(
                level=logging.INFO,
                handlers=[console_handler, file_handler],
                force=True,
            )
        except Exception:
            _logging_stage = SecurityLoggingStage.UNAVAILABLE
            _emergency_unavailable_notice()
            raise
        _logging_data_root = resolved_root
        _minimum_log_directory = bootstrap_directory
        _complete_log_directory = None
        _logging_stage = SecurityLoggingStage.MINIMUM

    emit_security_event(
        SecurityEventCode.LOGGER_MINIMUM_READY,
        SecurityEventDetails(
            operation=SecurityOperation.LOGGING,
            outcome=SecurityOutcome.READY,
            status=SecurityLoggingStage.MINIMUM,
            enabled=True,
        ),
    )
    return True


def transition_to_complete_security_logging(log_directory: Path) -> bool:
    """Switch to complete logging while retaining the minimum journal without replay."""

    global _complete_log_directory, _logging_stage
    resolved = log_directory.expanduser().resolve()
    with _SECURITY_LOGGING_LOCK:
        if _logging_stage is SecurityLoggingStage.UNAVAILABLE:
            raise SecurityEventSinkError("Security-event logging is unavailable.")
        if _logging_stage is SecurityLoggingStage.UNINITIALIZED or _logging_data_root is None:
            raise RuntimeError("Minimum security logging must be initialized first.")
        if resolved != (_logging_data_root / "logs").resolve():
            raise RuntimeError("Complete security logging must use the initialized data root.")
        if _logging_stage is SecurityLoggingStage.COMPLETE:
            return False
        try:
            configure_logging(resolved)
        except Exception:
            emit_security_event(
                SecurityEventCode.CONTROL_UNAVAILABLE,
                SecurityEventDetails(
                    operation=SecurityOperation.LOGGING,
                    outcome=SecurityOutcome.UNAVAILABLE,
                    reason_code=SecurityReasonCode.COMPLETE_LOGGER_TRANSITION_FAILED,
                    status=SecurityLoggingStage.MINIMUM,
                    enabled=False,
                ),
                exc_info=True,
            )
            raise
        _complete_log_directory = resolved
        _logging_stage = SecurityLoggingStage.COMPLETE

    emit_security_event(
        SecurityEventCode.LOGGER_COMPLETE_READY,
        SecurityEventDetails(
            operation=SecurityOperation.LOGGING,
            outcome=SecurityOutcome.READY,
            status=SecurityLoggingStage.COMPLETE,
            enabled=True,
        ),
    )
    return True


def minimum_security_log_paths() -> tuple[Path, ...]:
    """Return the bounded bootstrap-journal files without exposing their paths in events."""

    with _SECURITY_LOGGING_LOCK:
        if _minimum_log_directory is None:
            return ()
        candidates = (
            _minimum_log_directory / _MINIMUM_LOG_FILENAME,
            _minimum_log_directory / f"{_MINIMUM_LOG_FILENAME}.1",
        )
        return tuple(path for path in candidates if path.is_file() and not path.is_symlink())


def security_logging_stage() -> SecurityLoggingStage:
    with _SECURITY_LOGGING_LOCK:
        return _logging_stage
