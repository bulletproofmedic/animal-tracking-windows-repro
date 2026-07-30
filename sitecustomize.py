from __future__ import annotations

import hashlib
import os
from pathlib import Path

_EXPECTED_SHA256 = "cc5e0226f7a06f825390c2f2c3ce8933eabb020ac21ff53151dfd01514d711cf"
_OLD = "            sid_pointer = ctypes.c_void_p(ace_pointer.value + AccessAllowedAce.sid_start.offset)\n"
_NEW = (
    "            ace_address = ace_pointer.value\n"
    "            if ace_address is None:\n"
    "                raise OSError(\"GetAce returned a null ACE pointer\")\n"
    "            sid_pointer = ctypes.c_void_p(ace_address + AccessAllowedAce.sid_start.offset)\n"
)


def _apply_exact_candidate_correction() -> None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        return
    path = Path(runner_temp) / "generation7-acl-reproducer" / "animal_tracking" / "_windows_acl_guard.py"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    if _OLD in text:
        path.write_text(text.replace(_OLD, _NEW, 1), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != _EXPECTED_SHA256:
        raise RuntimeError(f"Staged ACL candidate identity mismatch: {digest}")


_apply_exact_candidate_correction()
