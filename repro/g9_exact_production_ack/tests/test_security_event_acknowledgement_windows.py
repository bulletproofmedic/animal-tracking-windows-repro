from __future__ import annotations

import json
import logging
import os
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from animal_tracking import _security_event_ack_guard as acknowledgement_guard
from animal_tracking import logging_config
from animal_tracking.security import events
from animal_tracking.security.events import (
    SecurityEventCode,
    SecurityEventDetails,
    SecurityEventSinkError,
    SecurityLoggingStage,
    SecurityOperation,
    SecurityOutcome,
    SecurityReasonCode,
)

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Exact supported-Windows security-event acknowledgement harness",
)

_BUDGETS = acknowledgement_guard.SECURITY_EVENT_ACKNOWLEDGEMENT_BUDGETS
_CALLS = 800
_WORKERS = _BUDGETS["supported_windows_concurrent_workers"]
_P95_BUDGET_MS = _BUDGETS["supported_windows_p95_latency_ms"]
_P99_BUDGET_MS = _BUDGETS["supported_windows_p99_latency_ms"]


def _reset_event_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(events, "_logging_stage", SecurityLoggingStage.UNINITIALIZED)
    monkeypatch.setattr(events, "_logging_data_root", None)
    monkeypatch.setattr(events, "_minimum_log_directory", None)
    monkeypatch.setattr(events, "_complete_log_directory", None)


def _complete_log_paths(log_directory: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (
                path
                for path in log_directory.glob("animal-tracking.log*")
                if path.is_file()
            ),
            key=lambda path: path.name,
        )
    )


def _records(paths: tuple[Path, ...]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in paths:
        records.extend(
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        )
    return records


def _percentile(values: list[float], proportion: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, int(len(ordered) * proportion) - 1)]


def _rejection_details() -> SecurityEventDetails:
    return SecurityEventDetails(
        operation=SecurityOperation.HOST_VALIDATION,
        outcome=SecurityOutcome.REJECTED,
        reason_code=SecurityReasonCode.NON_LOOPBACK_HOST,
    )


def test_complete_acknowledgement_path_meets_budget_without_event_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _reset_event_state(monkeypatch)
    data_root = tmp_path / "active-root"
    log_directory = data_root / "logs"
    process_starts = 0
    original_run = logging_config.subprocess.run

    def counted_run(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[object]:
        nonlocal process_starts
        process_starts += 1
        return original_run(*args, **kwargs)

    monkeypatch.setattr(logging_config.subprocess, "run", counted_run)

    try:
        assert events.initialize_minimum_security_logging(data_root)
        assert events.transition_to_complete_security_logging(log_directory)
        setup_process_starts = process_starts
        details = _rejection_details()

        def emit(index: int) -> float:
            started = time.perf_counter()
            events.emit_security_event(
                SecurityEventCode.HOST_REJECTED,
                details,
                correlation_id=f"{index:032x}",
            )
            return (time.perf_counter() - started) * 1000.0

        with ThreadPoolExecutor(max_workers=_WORKERS) as executor:
            latencies = list(executor.map(emit, range(_CALLS)))

        paths = _complete_log_paths(log_directory)
        rejection_records = [
            record
            for record in _records(paths)
            if record.get("event_code") == SecurityEventCode.HOST_REJECTED.value
        ]
        p95 = _percentile(latencies, 0.95)
        p99 = _percentile(latencies, 0.99)

        assert process_starts == setup_process_starts
        assert len(rejection_records) == _CALLS
        assert len({str(record["correlation_id"]) for record in rejection_records}) == _CALLS
        assert len({str(record["record_id"]) for record in rejection_records}) == _CALLS
        assert p95 <= _P95_BUDGET_MS
        assert p99 <= _P99_BUDGET_MS
        print(
            json.dumps(
                {
                    "scenario": "complete_security_event_acknowledgement_load",
                    "workers": _WORKERS,
                    "calls": _CALLS,
                    "failures": 0,
                    "event_count": len(rejection_records),
                    "median_ms": round(statistics.median(latencies), 3),
                    "p95_ms": round(p95, 3),
                    "p99_ms": round(p99, 3),
                    "bytes_read": sum(path.stat().st_size for path in paths),
                    "setup_process_starts": setup_process_starts,
                    "steady_state_process_starts": process_starts - setup_process_starts,
                },
                sort_keys=True,
            )
        )
    finally:
        logging.basicConfig(handlers=[logging.NullHandler()], force=True)


def test_complete_acknowledgement_survives_near_limit_rollover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _reset_event_state(monkeypatch)
    data_root = tmp_path / "active-root"
    log_directory = data_root / "logs"

    try:
        assert events.initialize_minimum_security_logging(data_root)
        assert events.transition_to_complete_security_logging(log_directory)
        handler = next(
            handler
            for handler in events._protected_handlers()  # noqa: SLF001
            if Path(handler.baseFilename).name == "animal-tracking.log"
        )
        assert handler.stream is not None
        handler.flush()
        current_size = os.fstat(handler.stream.fileno()).st_size
        filler_size = handler.maxBytes - current_size - 64
        prefix = '{"padding":"'
        suffix = '"}\n'
        assert filler_size > len(prefix) + len(suffix)
        handler.stream.write(
            prefix + "x" * (filler_size - len(prefix) - len(suffix)) + suffix
        )
        handler.flush()
        os.fsync(handler.stream.fileno())

        events.emit_security_event(
            SecurityEventCode.ORIGIN_REJECTED,
            SecurityEventDetails(
                operation=SecurityOperation.ORIGIN_VALIDATION,
                outcome=SecurityOutcome.REJECTED,
                reason_code=SecurityReasonCode.NON_LOOPBACK_ORIGIN,
            ),
            correlation_id="f" * 32,
        )

        paths = _complete_log_paths(log_directory)
        matching = [
            record
            for record in _records(paths)
            if record.get("event_code") == SecurityEventCode.ORIGIN_REJECTED.value
            and record.get("correlation_id") == "f" * 32
        ]
        assert (log_directory / "animal-tracking.log.1").is_file()
        assert len(matching) == 1
        print(
            json.dumps(
                {
                    "scenario": "near_limit_rollover",
                    "event_count": len(matching),
                    "bytes_read": sum(path.stat().st_size for path in paths),
                    "rollover": True,
                },
                sort_keys=True,
            )
        )
    finally:
        logging.basicConfig(handlers=[logging.NullHandler()], force=True)


def test_exact_windows_acl_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _reset_event_state(monkeypatch)
    data_root = tmp_path / "active-root"
    log_directory = data_root / "logs"

    try:
        assert events.initialize_minimum_security_logging(data_root)
        assert events.transition_to_complete_security_logging(log_directory)
        active = log_directory / "animal-tracking.log"
        environment = os.environ.copy()
        environment["AT_SECURITY_EVENT_TEST_PATH"] = str(active)
        script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:AT_SECURITY_EVENT_TEST_PATH
$acl = [System.IO.File]::GetAccessControl($path)
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = [System.Security.AccessControl.FileSystemRights]::Read
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $everyone, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($rule)
[System.IO.File]::SetAccessControl($path, $acl)
"""
        completed = subprocess.run(  # noqa: S603, S607
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
        assert completed.returncode == 0, completed.stderr

        with pytest.raises(SecurityEventSinkError, match="could not be persisted"):
            events.emit_security_event(
                SecurityEventCode.PERMISSION_FAILED,
                SecurityEventDetails(
                    operation=SecurityOperation.PERMISSIONS,
                    outcome=SecurityOutcome.FAILED,
                    reason_code=SecurityReasonCode.PERMISSION_CONTROL_FAILED,
                ),
                correlation_id="e" * 32,
            )
        assert events.security_logging_stage() is SecurityLoggingStage.UNAVAILABLE
    finally:
        logging.basicConfig(handlers=[logging.NullHandler()], force=True)
