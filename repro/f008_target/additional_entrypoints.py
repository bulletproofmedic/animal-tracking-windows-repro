"""Additional target-ordered read-before-mutation boundaries for F008 revalidation."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

TARGET_COMMIT = "42c72f37d3e17f2ad51ec16c867acdfdf1458dc9"
SOURCE_BLOBS = {
    "startup.py": "dc685898513e989acef7114bc2e1eaf4adbc7e8c",
    "failure_recovery.py": "fab82ea1a31587f8d384f8b36e47d6989a02aff5",
}


class StartupError(RuntimeError):
    pass


def _read(path: Path, strict_reader: Callable[[Path], dict[str, object]]) -> dict[str, object]:
    try:
        return strict_reader(path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StartupError("The restore activation journal is malformed.") from exc


def rollback_activation(path: Path, *, lock_acquired: bool, strict_reader, mutation) -> None:
    if not lock_acquired:
        raise StartupError("Restore rollback requires the stable recovery lock.")
    _read(path, strict_reader)
    mutation("rollback_transition_or_root_move")


def finalize_activation(path: Path, *, lock_acquired: bool, strict_reader, mutation) -> None:
    if not lock_acquired:
        raise StartupError("Restore finalization requires the stable recovery lock.")
    _read(path, strict_reader)
    mutation("finalize_transition_or_rollback_delete")


def persist_activation_outcome(path: Path, *, lock_acquired: bool, strict_reader, mutation) -> None:
    if not lock_acquired:
        raise StartupError("Outcome persistence requires the stable recovery lock.")
    _read(path, strict_reader)
    mutation("restore_operation_update")


def close_recovery_journal(path: Path, *, lock_acquired: bool, strict_reader, mutation) -> None:
    if not lock_acquired:
        raise StartupError("Journal archival requires the stable recovery lock.")
    _read(path, strict_reader)
    mutation("journal_archive_or_unlink")


def recover_startup_failure(path: Path, *, lock_acquired: bool, strict_reader, mutation) -> None:
    if not lock_acquired:
        raise StartupError("Startup failure recovery requires the stable recovery lock.")
    _read(path, strict_reader)
    mutation("failure_routing_transition_or_root_move")
