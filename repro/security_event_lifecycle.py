from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable
from uuid import uuid4

BOOTSTRAP_MAX_BYTES = 16 * 1024
BOOTSTRAP_BACKUP_COUNT = 1
COMPLETE_MAX_BYTES = 64 * 1024
COMPLETE_BACKUP_COUNT = 1


class EventCode(StrEnum):
    LOGGER_MINIMUM_READY = "SEC_LOGGER_MINIMUM_READY"
    LOGGER_COMPLETE_READY = "SEC_LOGGER_COMPLETE_READY"
    HOST_REJECTED = "SEC_HOST_REJECTED"
    ORIGIN_REJECTED = "SEC_ORIGIN_REJECTED"
    CSRF_REJECTED = "SEC_CSRF_REJECTED"
    STARTUP_FAILED = "SEC_STARTUP_FAILED"
    RECOVERY_FAILED = "SEC_RECOVERY_FAILED"
    INTEGRITY_FAILED = "SEC_INTEGRITY_FAILED"
    PERMISSION_FAILED = "SEC_PERMISSION_FAILED"
    SUPPORT_CREATE_STARTED = "SEC_SUPPORT_CREATE_STARTED"
    SUPPORT_CREATE_SUCCEEDED = "SEC_SUPPORT_CREATE_SUCCEEDED"
    SUPPORT_CREATE_FAILED = "SEC_SUPPORT_CREATE_FAILED"
    SUPPORT_DISCLOSURE_RECORDED = "SEC_SUPPORT_DISCLOSURE_RECORDED"
    SUPPORT_DISCLOSURE_REJECTED = "SEC_SUPPORT_DISCLOSURE_REJECTED"
    CONTROL_DEGRADED = "SEC_CONTROL_DEGRADED"
    CONTROL_UNAVAILABLE = "SEC_CONTROL_UNAVAILABLE"


class ReasonCode(StrEnum):
    NON_LOOPBACK_HOST = "NON_LOOPBACK_HOST"
    NON_LOOPBACK_ORIGIN = "NON_LOOPBACK_ORIGIN"
    CSRF_VALIDATION_FAILED = "CSRF_VALIDATION_FAILED"
    SETTINGS_FAILED = "SETTINGS_FAILED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    PERMISSION_FAILED = "PERMISSION_FAILED"
    COMPLETE_LOGGER_FAILED = "COMPLETE_LOGGER_FAILED"
    SUPPORT_VALIDATION_FAILED = "SUPPORT_VALIDATION_FAILED"
    SUPPORT_ASSURANCE_LIMITED = "SUPPORT_ASSURANCE_LIMITED"


class Operation(StrEnum):
    LOGGING = "LOGGING"
    HOST = "HOST"
    ORIGIN = "ORIGIN"
    CSRF = "CSRF"
    STARTUP = "STARTUP"
    RECOVERY = "RECOVERY"
    INTEGRITY = "INTEGRITY"
    PERMISSIONS = "PERMISSIONS"
    SUPPORT = "SUPPORT"


class Outcome(StrEnum):
    READY = "READY"
    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    RECORDED = "RECORDED"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class Stage(StrEnum):
    UNINITIALIZED = "UNINITIALIZED"
    MINIMUM = "MINIMUM"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True, slots=True)
class Details:
    operation: Operation
    outcome: Outcome
    reason_code: ReasonCode | None = None
    stage: Stage | None = None
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
        if self.stage is not None:
            fields["status"] = self.stage.value
        for name, value in (
            ("file_count", self.file_count),
            ("member_count", self.member_count),
            ("byte_count", self.byte_count),
        ):
            if value is None:
                continue
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
            fields[name] = value
        if self.duration_ms is not None:
            if not math.isfinite(self.duration_ms) or self.duration_ms < 0:
                raise ValueError("duration_ms must be finite and non-negative")
            fields["duration_ms"] = self.duration_ms
        if self.enabled is not None:
            fields["enabled"] = self.enabled
        return fields


@dataclass(frozen=True, slots=True)
class EventSpec:
    level: int
    component: str
    message: str


EVENT_SPECS: dict[EventCode, EventSpec] = {
    EventCode.LOGGER_MINIMUM_READY: EventSpec(logging.INFO, "security.logging", "Minimum logger ready"),
    EventCode.LOGGER_COMPLETE_READY: EventSpec(logging.INFO, "security.logging", "Complete logger ready"),
    EventCode.HOST_REJECTED: EventSpec(logging.WARNING, "security.web", "Host validation rejected"),
    EventCode.ORIGIN_REJECTED: EventSpec(logging.WARNING, "security.web", "Origin validation rejected"),
    EventCode.CSRF_REJECTED: EventSpec(logging.WARNING, "security.web", "CSRF validation rejected"),
    EventCode.STARTUP_FAILED: EventSpec(logging.ERROR, "security.startup", "Startup failed safely"),
    EventCode.RECOVERY_FAILED: EventSpec(logging.ERROR, "security.recovery", "Recovery failed safely"),
    EventCode.INTEGRITY_FAILED: EventSpec(logging.ERROR, "security.integrity", "Integrity control failed"),
    EventCode.PERMISSION_FAILED: EventSpec(logging.ERROR, "security.permissions", "Permission control failed"),
    EventCode.SUPPORT_CREATE_STARTED: EventSpec(logging.INFO, "security.support", "Support creation started"),
    EventCode.SUPPORT_CREATE_SUCCEEDED: EventSpec(logging.INFO, "security.support", "Support creation completed"),
    EventCode.SUPPORT_CREATE_FAILED: EventSpec(logging.ERROR, "security.support", "Support creation failed safely"),
    EventCode.SUPPORT_DISCLOSURE_RECORDED: EventSpec(logging.INFO, "security.support", "Disclosure review recorded"),
    EventCode.SUPPORT_DISCLOSURE_REJECTED: EventSpec(logging.WARNING, "security.support", "Disclosure rejected"),
    EventCode.CONTROL_DEGRADED: EventSpec(logging.WARNING, "security.controls", "Security control degraded"),
    EventCode.CONTROL_UNAVAILABLE: EventSpec(logging.ERROR, "security.controls", "Security control unavailable"),
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "severity": record.levelname,
            "event_code": record.event_code,
            "component": record.name,
            "message": record.getMessage(),
            "record_id": record.record_id,
            "fields": record.safe_fields,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


class SecurityLifecycle:
    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root.resolve()
        self.bootstrap_directory = self.data_root.parent / f".{self.data_root.name}.security-bootstrap"
        self.bootstrap_path = self.bootstrap_directory / "security-bootstrap.jsonl"
        self.complete_path = self.data_root / "logs" / "security.jsonl"
        self.stage = Stage.UNINITIALIZED

    @staticmethod
    def _handler(path: Path, max_bytes: int, backups: int) -> RotatingFileHandler:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backups,
            encoding="utf-8",
        )
        handler.setFormatter(JsonFormatter())
        return handler

    @staticmethod
    def _flush() -> None:
        for handler in logging.getLogger().handlers:
            handler.flush()

    def emit(self, code: EventCode, details: Details) -> None:
        if not isinstance(code, EventCode) or not isinstance(details, Details):
            raise TypeError("closed event types are required")
        spec = EVENT_SPECS[code]
        logging.getLogger(spec.component).log(
            spec.level,
            spec.message,
            extra={
                "event_code": code.value,
                "record_id": uuid4().hex,
                "safe_fields": details.as_fields(),
            },
        )
        self._flush()

    def initialize_minimum(self) -> None:
        if self.stage is not Stage.UNINITIALIZED:
            raise RuntimeError("minimum logger already initialized")
        logging.basicConfig(
            level=logging.INFO,
            handlers=[self._handler(self.bootstrap_path, BOOTSTRAP_MAX_BYTES, BOOTSTRAP_BACKUP_COUNT)],
            force=True,
        )
        self.stage = Stage.MINIMUM
        self.emit(
            EventCode.LOGGER_MINIMUM_READY,
            Details(Operation.LOGGING, Outcome.READY, stage=Stage.MINIMUM, enabled=True),
        )

    def transition_complete(self, *, fail: bool = False) -> None:
        if self.stage is not Stage.MINIMUM:
            raise RuntimeError("minimum logger must be active")
        if fail:
            self.emit(
                EventCode.CONTROL_UNAVAILABLE,
                Details(
                    Operation.LOGGING,
                    Outcome.UNAVAILABLE,
                    reason_code=ReasonCode.COMPLETE_LOGGER_FAILED,
                    stage=Stage.MINIMUM,
                    enabled=False,
                ),
            )
            raise RuntimeError("synthetic complete logger failure")
        logging.basicConfig(
            level=logging.INFO,
            handlers=[self._handler(self.complete_path, COMPLETE_MAX_BYTES, COMPLETE_BACKUP_COUNT)],
            force=True,
        )
        self.stage = Stage.COMPLETE
        self.emit(
            EventCode.LOGGER_COMPLETE_READY,
            Details(Operation.LOGGING, Outcome.READY, stage=Stage.COMPLETE, enabled=True),
        )

    def bootstrap_paths(self) -> tuple[Path, ...]:
        candidates = (self.bootstrap_path, Path(f"{self.bootstrap_path}.1"))
        return tuple(path for path in candidates if path.is_file())


def run_startup(
    lifecycle: SecurityLifecycle,
    *,
    load_settings: Callable[[], None],
    apply_recovery: Callable[[], None],
) -> None:
    lifecycle.initialize_minimum()
    try:
        load_settings()
        apply_recovery()
        lifecycle.transition_complete()
    except PermissionError:
        lifecycle.emit(
            EventCode.PERMISSION_FAILED,
            Details(Operation.PERMISSIONS, Outcome.FAILED, ReasonCode.PERMISSION_FAILED),
        )
        lifecycle.emit(
            EventCode.STARTUP_FAILED,
            Details(Operation.STARTUP, Outcome.FAILED, ReasonCode.PERMISSION_FAILED),
        )
        raise
    except Exception:
        lifecycle.emit(
            EventCode.STARTUP_FAILED,
            Details(Operation.STARTUP, Outcome.FAILED, ReasonCode.SETTINGS_FAILED),
        )
        raise


def reject_host(lifecycle: SecurityLifecycle, raw_host: str) -> None:
    del raw_host
    lifecycle.emit(
        EventCode.HOST_REJECTED,
        Details(Operation.HOST, Outcome.REJECTED, ReasonCode.NON_LOOPBACK_HOST),
    )


def reject_origin(lifecycle: SecurityLifecycle, raw_origin: str) -> None:
    del raw_origin
    lifecycle.emit(
        EventCode.ORIGIN_REJECTED,
        Details(Operation.ORIGIN, Outcome.REJECTED, ReasonCode.NON_LOOPBACK_ORIGIN),
    )


def reject_csrf(lifecycle: SecurityLifecycle, raw_reason: str) -> None:
    del raw_reason
    lifecycle.emit(
        EventCode.CSRF_REJECTED,
        Details(Operation.CSRF, Outcome.REJECTED, ReasonCode.CSRF_VALIDATION_FAILED),
    )


def create_support_candidate(
    lifecycle: SecurityLifecycle,
    *,
    source_count: int,
    member_count: int,
    byte_count: int,
    reject: bool = False,
) -> tuple[Path, ...]:
    if lifecycle.stage is not Stage.COMPLETE:
        lifecycle.emit(
            EventCode.CONTROL_UNAVAILABLE,
            Details(
                Operation.SUPPORT,
                Outcome.UNAVAILABLE,
                reason_code=ReasonCode.COMPLETE_LOGGER_FAILED,
                stage=lifecycle.stage,
                enabled=False,
            ),
        )
        raise RuntimeError("complete logger is required")
    lifecycle.emit(
        EventCode.SUPPORT_CREATE_STARTED,
        Details(Operation.SUPPORT, Outcome.STARTED, file_count=source_count),
    )
    if reject:
        lifecycle.emit(
            EventCode.SUPPORT_DISCLOSURE_REJECTED,
            Details(Operation.SUPPORT, Outcome.REJECTED, ReasonCode.SUPPORT_VALIDATION_FAILED),
        )
        lifecycle.emit(
            EventCode.SUPPORT_CREATE_FAILED,
            Details(Operation.SUPPORT, Outcome.FAILED, ReasonCode.SUPPORT_VALIDATION_FAILED),
        )
        raise ValueError("synthetic disclosure rejection")
    bootstrap = lifecycle.bootstrap_paths()
    lifecycle.emit(
        EventCode.SUPPORT_DISCLOSURE_RECORDED,
        Details(
            Operation.SUPPORT,
            Outcome.RECORDED,
            member_count=member_count + len(bootstrap),
            byte_count=byte_count,
        ),
    )
    lifecycle.emit(
        EventCode.CONTROL_DEGRADED,
        Details(
            Operation.SUPPORT,
            Outcome.DEGRADED,
            reason_code=ReasonCode.SUPPORT_ASSURANCE_LIMITED,
            enabled=True,
        ),
    )
    lifecycle.emit(
        EventCode.SUPPORT_CREATE_SUCCEEDED,
        Details(
            Operation.SUPPORT,
            Outcome.SUCCEEDED,
            member_count=member_count + len(bootstrap),
            byte_count=byte_count,
        ),
    )
    return bootstrap
