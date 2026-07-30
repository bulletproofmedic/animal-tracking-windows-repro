from __future__ import annotations

import hashlib
import os
import runpy
import sys
from pathlib import Path

_EXPECTED_SHA256 = "cc5e0226f7a06f825390c2f2c3ce8933eabb020ac21ff53151dfd01514d711cf"
_OLD = "            sid_pointer = ctypes.c_void_p(ace_pointer.value + AccessAllowedAce.sid_start.offset)\n"
_NEW = (
    "            ace_address = ace_pointer.value\n"
    "            if ace_address is None:\n"
    "                raise OSError(\"GetAce returned a null ACE pointer\")\n"
    "            sid_pointer = ctypes.c_void_p(ace_address + AccessAllowedAce.sid_start.offset)\n"
)


def _patch_exact_candidate() -> None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise RuntimeError("RUNNER_TEMP is unavailable.")
    path = Path(runner_temp) / "generation7-acl-reproducer" / "animal_tracking" / "_windows_acl_guard.py"
    text = path.read_text(encoding="utf-8")
    if _OLD not in text:
        raise RuntimeError("Expected pre-correction candidate line was not found.")
    corrected = text.replace(_OLD, _NEW, 1)
    path.write_text(corrected, encoding="utf-8")
    normalized = path.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
    digest = hashlib.sha256(normalized).hexdigest()
    if digest != _EXPECTED_SHA256:
        raise RuntimeError(f"Corrected ACL candidate identity mismatch: {digest}")


def _run_installed_mypy() -> None:
    repository_root = Path(__file__).resolve().parent
    sys.path = [
        entry
        for entry in sys.path
        if entry and Path(entry).resolve() != repository_root
    ]
    runpy.run_module("mypy", run_name="__main__", alter_sys=True)


_patch_exact_candidate()
_run_installed_mypy()
