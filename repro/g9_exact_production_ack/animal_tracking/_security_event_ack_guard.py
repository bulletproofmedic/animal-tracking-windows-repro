from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

_ACKNOWLEDGEMENT_TAIL_BYTES = 128 * 1024
_INSTALLED = False
SECURITY_EVENT_ACKNOWLEDGEMENT_BUDGETS = {
    "max_tail_bytes_per_handler": _ACKNOWLEDGEMENT_TAIL_BYTES,
    "steady_state_acl_subprocesses_per_event": 0,
    "supported_windows_concurrent_workers": 16,
    "supported_windows_p95_latency_ms": 250,
    "supported_windows_p99_latency_ms": 500,
}


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_dev != right.st_dev:
        return False
    if left.st_ino and right.st_ino and left.st_ino != right.st_ino:
        return False
    return True


def _reopen_same_object_for_read(file_descriptor: int) -> int:
    if os.name == "nt":
        from animal_tracking._windows_handle_security import (
            reopen_file_descriptor_for_read,
        )

        return reopen_file_descriptor_for_read(file_descriptor)
    opened = os.fstat(file_descriptor)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    for candidate in (f"/proc/self/fd/{file_descriptor}", f"/dev/fd/{file_descriptor}"):
        try:
            reopened = os.open(candidate, flags)
        except OSError:
            continue
        if _same_identity(opened, os.fstat(reopened)):
            return reopened
        os.close(reopened)
    raise OSError("The active security-event file object could not be reopened safely.")


def _descriptor_is_private(file_descriptor: int) -> bool:
    if os.name == "nt":
        from animal_tracking._windows_handle_security import (
            file_descriptor_acl_is_private,
        )

        return file_descriptor_acl_is_private(file_descriptor)
    return stat.S_IMODE(os.fstat(file_descriptor).st_mode) == 0o600


def _bounded_tail_lines(file_descriptor: int) -> tuple[bytes, ...]:
    reopened = _reopen_same_object_for_read(file_descriptor)
    try:
        with os.fdopen(reopened, "rb", closefd=True) as source:
            size = source.seek(0, os.SEEK_END)
            start = max(0, size - _ACKNOWLEDGEMENT_TAIL_BYTES)
            source.seek(start)
            payload = source.read(_ACKNOWLEDGEMENT_TAIL_BYTES)
    except Exception:
        try:
            os.close(reopened)
        except OSError:
            pass
        raise
    if start:
        separator = payload.find(b"\n")
        if separator < 0:
            return ()
        payload = payload[separator + 1 :]
    return tuple(payload.splitlines())


def _acknowledge_durable_event(captures: dict[Any, Any]) -> None:
    from animal_tracking.security import events

    if not captures:
        raise events.SecurityEventSinkError(
            "No protected security-event file handler is active."
        )
    for handler, capture in captures.items():
        stream = handler.stream
        if stream is None:
            raise events.SecurityEventSinkError(
                "A security-event handler has no open stream."
            )
        if capture.rendered is None:
            raise events.SecurityEventSinkError(
                "The security-event formatter did not produce the expected exact "
                "record."
            )
        stream.flush()
        file_descriptor = stream.fileno()
        os.fsync(file_descriptor)
        if not events._handler_identity_is_current(handler):  # noqa: SLF001
            raise events.SecurityEventSinkError(
                "A security-event log path changed after initialization."
            )
        events.protect_private_file(Path(handler.baseFilename))
        if not events._handler_identity_is_current(handler):  # noqa: SLF001
            raise events.SecurityEventSinkError(
                "A security-event log path changed during permission verification."
            )
        if not _descriptor_is_private(file_descriptor):
            raise events.SecurityEventSinkError(
                "The active security-event file object is not owner-private."
            )
        if capture.rendered not in _bounded_tail_lines(file_descriptor):
            raise events.SecurityEventSinkError(
                "The exact mandatory security event was not found on the persisted "
                "file object."
            )
        if not events._handler_identity_is_current(handler):  # noqa: SLF001
            raise events.SecurityEventSinkError(
                "A security-event log path changed during exact-record acknowledgement."
            )


def install_security_event_acknowledgement_guard() -> None:
    """Replace pathname-based acknowledgement with exact-open-object verification."""

    global _INSTALLED
    if _INSTALLED:
        return
    from animal_tracking.security import events

    events._acknowledge_durable_event = _acknowledge_durable_event  # noqa: SLF001
    _INSTALLED = True
