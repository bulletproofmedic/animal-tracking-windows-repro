from __future__ import annotations

import ctypes
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PHASES = {"PREPARED", "PUBLISHED", "RECORDED"}


def _flush(path: Path) -> None:
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def publish_write_through(source: Path, destination: Path) -> None:
    if not source.is_file() or destination.exists():
        raise RuntimeError("invalid publication boundary")
    _flush(source)
    if os.name == "nt":
        win_dll: Any = ctypes.__dict__["WinDLL"]
        kernel32: Any = win_dll("kernel32", use_last_error=True)
        move_file_ex: Any = kernel32.MoveFileExW
        move_file_ex.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        move_file_ex.restype = ctypes.c_int
        if not move_file_ex(str(source), str(destination), 0x00000008):
            error = ctypes.get_last_error()
            raise OSError(error, os.strerror(error))
    else:
        os.replace(source, destination)
    _flush(destination)


def digest(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("xb") as handle:
        handle.write(json.dumps(value, sort_keys=True).encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


@dataclass
class Protocol:
    root: Path

    @property
    def source(self) -> Path:
        return self.root / "artifact.part"

    @property
    def destination(self) -> Path:
        return self.root / "artifact.bin"

    @property
    def journal(self) -> Path:
        return self.root / "publication.json"

    @property
    def registry(self) -> Path:
        return self.root / "registry.json"

    def prepare(self, payload: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.source.write_bytes(payload)
        _flush(self.source)
        sha256, byte_count = digest(self.source)
        write_json(
            self.journal,
            {
                "phase": "PREPARED",
                "sha256": sha256,
                "bytes": byte_count,
            },
        )

    def reconcile(self, *, interrupt_after: str | None = None) -> None:
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        phase = journal["phase"]
        if phase not in PHASES:
            raise RuntimeError("unsupported phase")
        if phase == "PREPARED":
            if self.destination.exists():
                if digest(self.destination) != (journal["sha256"], journal["bytes"]):
                    raise RuntimeError("published identity mismatch")
                self.source.unlink(missing_ok=True)
            else:
                if digest(self.source) != (journal["sha256"], journal["bytes"]):
                    raise RuntimeError("prepared identity mismatch")
                publish_write_through(self.source, self.destination)
            journal["phase"] = "PUBLISHED"
            write_json(self.journal, journal)
            if interrupt_after == "PUBLISHED":
                raise RuntimeError("injected interruption")
            phase = "PUBLISHED"
        if phase == "PUBLISHED":
            if digest(self.destination) != (journal["sha256"], journal["bytes"]):
                raise RuntimeError("published identity mismatch")
            write_json(
                self.registry,
                {
                    "status": "VERIFIED",
                    "sha256": journal["sha256"],
                    "bytes": journal["bytes"],
                },
            )
            if interrupt_after == "REGISTRY":
                raise RuntimeError("injected interruption")
            recorded = json.loads(self.registry.read_text(encoding="utf-8"))
            if recorded["status"] != "VERIFIED" or (
                recorded["sha256"], recorded["bytes"]
            ) != digest(self.destination):
                raise RuntimeError("registration readback mismatch")
            journal["phase"] = "RECORDED"
            write_json(self.journal, journal)
            if interrupt_after == "RECORDED":
                raise RuntimeError("injected interruption")
            phase = "RECORDED"
        if phase == "RECORDED":
            recorded = json.loads(self.registry.read_text(encoding="utf-8"))
            if recorded["status"] != "VERIFIED" or (
                recorded["sha256"], recorded["bytes"]
            ) != digest(self.destination):
                raise RuntimeError("registration readback mismatch")
            self.journal.unlink()
