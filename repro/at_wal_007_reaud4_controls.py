from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class ControlError(RuntimeError):
    pass


@dataclass
class TerminalState:
    active_root: Path
    rollback_root: Path
    staged_root: Path
    journal_path: Path


def _read_journal(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ControlError("journal must be an object")
    return value


def _write_journal(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _validate_terminal_pending(state: TerminalState) -> None:
    if not state.active_root.is_dir() or not state.rollback_root.is_dir():
        raise ControlError("terminal pending authority is incomplete")
    if state.staged_root.exists():
        raise ControlError("terminal pending unexpectedly retains staging")


def legacy_finalize(state: TerminalState) -> str:
    journal = _read_journal(state.journal_path)
    if journal.get("phase") != "READY":
        raise ControlError("READY required")
    journal["phase"] = "FINALIZE_PENDING"
    _write_journal(state.journal_path, journal)
    _validate_terminal_pending(state)
    return "FINALIZE_PENDING"


def legacy_apply_pending(state: TerminalState) -> str:
    journal = _read_journal(state.journal_path)
    phase = str(journal.get("phase"))
    if phase == "FINALIZE_PENDING":
        _validate_terminal_pending(state)
    return phase


def legacy_recover_failure(state: TerminalState) -> str:
    journal = _read_journal(state.journal_path)
    phase = str(journal.get("phase"))
    if phase == "FINALIZE_PENDING":
        _validate_terminal_pending(state)
        return phase
    raise ControlError("unsupported synthetic phase")


def sha256_path(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
            total += len(block)
    return digest.hexdigest(), total


def verify_destination(path: Path, journal: dict[str, object]) -> None:
    if not path.is_file():
        raise ControlError("destination missing")
    digest, size = sha256_path(path)
    if digest != journal["archive_sha256"] or size != journal["archive_bytes"]:
        raise ControlError("destination identity mismatch")


def register_with_readback(
    destination: Path,
    journal: dict[str, object],
    row: dict[str, object],
    *,
    after_registration: Callable[[Path], None] | None = None,
) -> None:
    try:
        verify_destination(destination, journal)
        row["status"] = "COMPLETE"
        row["validation_status"] = "VERIFIED"
        if after_registration is not None:
            after_registration(destination)
        verify_destination(destination, journal)
    except (ControlError, OSError):
        row["status"] = "INVALID"
        row["validation_status"] = "INVALID"
        raise


def archive_recorded_with_readback(
    destination: Path,
    journal: dict[str, object],
    row: dict[str, object],
    history_path: Path,
    *,
    before_history: Callable[[Path], None] | None = None,
) -> None:
    try:
        if before_history is not None:
            before_history(destination)
        verify_destination(destination, journal)
        if row.get("status") != "COMPLETE" or row.get("validation_status") != "VERIFIED":
            raise ControlError("registration readback mismatch")
        verify_destination(destination, journal)
    except (ControlError, OSError):
        row["status"] = "INVALID"
        row["validation_status"] = "INVALID"
        raise
    history_path.write_text(json.dumps(journal, sort_keys=True), encoding="utf-8")


def compression_only_repack(path: Path) -> None:
    replacement = path.with_suffix(path.suffix + ".repacked")
    with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(
        replacement,
        "x",
        compression=zipfile.ZIP_STORED,
        allowZip64=True,
    ) as target:
        for member in source.infolist():
            target.writestr(member.filename, source.read(member.filename))
    os.replace(replacement, path)
