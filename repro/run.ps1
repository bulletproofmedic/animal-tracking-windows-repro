$ErrorActionPreference = "Stop"
$root = Join-Path $env:RUNNER_TEMP "generation7-acl-reproducer"
if (Test-Path $root) { Remove-Item -Recurse -Force $root }
New-Item -ItemType Directory -Force -Path (Join-Path $root "animal_tracking") | Out-Null
$content = @'
from __future__ import annotations

import os
import subprocess
from pathlib import Path

powershell_invocations = 0


def _apply_windows_acl(path: Path, *, directory: bool) -> None:
    global powershell_invocations
    powershell_invocations += 1
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:AT_PROTECTED_PATH
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
if ($env:AT_PROTECTED_DIRECTORY -eq '1') {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
} else {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
}
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true, $false)
$currentRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $current, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($currentRule)
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $system, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($systemRule)
if ($env:AT_PROTECTED_DIRECTORY -eq '1') {
    [System.IO.Directory]::SetAccessControl($path, $acl)
} else {
    [System.IO.File]::SetAccessControl($path, $acl)
}
"""
    environment = os.environ.copy()
    environment["AT_PROTECTED_PATH"] = str(path)
    environment["AT_PROTECTED_DIRECTORY"] = "1" if directory else "0"
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise PermissionError(f"Windows ACL establishment failed: {detail}")


def protect_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("Directory target is invalid.")
    _apply_windows_acl(path, directory=True)


def protect_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise PermissionError("File target is invalid.")
    _apply_windows_acl(path, directory=False)
'@
Set-Content -LiteralPath (Join-Path $root "animal_tracking\logging_config.py") -Value $content -Encoding utf8NoBOM
$content = @'
from __future__ import annotations

import ctypes
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Final

from animal_tracking import logging_config

_PROTECTED_IDENTITY_LIMIT: Final = 1024
_FILE_ALL_ACCESS: Final = 0x001F01FF
_OBJECT_INHERIT_ACE: Final = 0x01
_CONTAINER_INHERIT_ACE: Final = 0x02
_ACCESS_ALLOWED_ACE_TYPE: Final = 0x00
_SE_DACL_PROTECTED: Final = 0x1000

_Identity = tuple[int, int, int, bool]
_CACHE_LOCK = threading.RLock()
_PROTECTED_IDENTITIES: OrderedDict[_Identity, None] = OrderedDict()
_ORIGINAL_PROTECT_FILE = logging_config.protect_private_file
_ORIGINAL_PROTECT_DIRECTORY = logging_config.protect_private_directory
_INSTALLED = False


def _path_identity(path: Path, *, directory: bool) -> _Identity:
    metadata = path.stat(follow_symlinks=False)
    return (metadata.st_dev, metadata.st_ino, metadata.st_ctime_ns, directory)


def _remember(identity: _Identity) -> None:
    with _CACHE_LOCK:
        _PROTECTED_IDENTITIES.pop(identity, None)
        _PROTECTED_IDENTITIES[identity] = None
        while len(_PROTECTED_IDENTITIES) > _PROTECTED_IDENTITY_LIMIT:
            _PROTECTED_IDENTITIES.popitem(last=False)


def _is_remembered(identity: _Identity) -> bool:
    with _CACHE_LOCK:
        if identity not in _PROTECTED_IDENTITIES:
            return False
        _PROTECTED_IDENTITIES.move_to_end(identity)
        return True


def _clear_identity_cache() -> None:
    with _CACHE_LOCK:
        _PROTECTED_IDENTITIES.clear()


def _windows_acl_is_private(path: Path, *, directory: bool) -> bool:
    """Verify the exact owner and protected two-entry DACL without a subprocess."""

    from ctypes import wintypes

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("ace_count", wintypes.DWORD),
            ("acl_bytes_in_use", wintypes.DWORD),
            ("acl_bytes_free", wintypes.DWORD),
        ]

    class AceHeader(ctypes.Structure):
        _fields_ = [
            ("ace_type", wintypes.BYTE),
            ("ace_flags", wintypes.BYTE),
            ("ace_size", wintypes.WORD),
        ]

    class AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("header", AceHeader),
            ("mask", wintypes.DWORD),
            ("sid_start", wintypes.DWORD),
        ]

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    def sid_string(sid: ctypes.c_void_p) -> str:
        rendered = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(rendered.value)
        finally:
            kernel32.LocalFree(ctypes.cast(rendered, ctypes.c_void_p))

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation sizing failed")
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        current_user = sid_string(ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents.user.sid)
    finally:
        kernel32.CloseHandle(token)

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise OSError(result, "GetNamedSecurityInfoW failed")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorControl failed")
        if not control.value & _SE_DACL_PROTECTED:
            return False
        if not owner or sid_string(owner) != current_user or not dacl:
            return False

        info = AclSizeInformation()
        if not advapi32.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")
        if info.ace_count != 2:
            return False

        expected_flags = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if directory else 0
        observed: dict[str, int] = {}
        for index in range(info.ace_count):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise OSError(ctypes.get_last_error(), "GetAce failed")
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(AccessAllowedAce)).contents
            if ace.header.ace_type != _ACCESS_ALLOWED_ACE_TYPE:
                return False
            if ace.header.ace_flags != expected_flags or ace.mask != _FILE_ALL_ACCESS:
                return False
            sid_pointer = ctypes.c_void_p(ace_pointer.value + AccessAllowedAce.sid_start.offset)
            sid = sid_string(sid_pointer)
            if sid in observed:
                return False
            observed[sid] = ace.mask
        return set(observed) == {current_user, "S-1-5-18"}
    finally:
        kernel32.LocalFree(descriptor)


def _protect_windows_path(path: Path, *, directory: bool) -> None:
    if path.is_symlink() or (not path.is_dir() if directory else not path.is_file()):
        kind = "directory" if directory else "file"
        raise PermissionError(f"Private {kind} is not a regular {kind}: {path}.")

    before = _path_identity(path, directory=directory)
    if _is_remembered(before):
        if not _windows_acl_is_private(path, directory=directory):
            raise PermissionError(f"Private Windows ACL drift was detected for {path}.")
        if _path_identity(path, directory=directory) != before:
            raise PermissionError(f"Private Windows path changed during ACL verification: {path}.")
        return

    establish = _ORIGINAL_PROTECT_DIRECTORY if directory else _ORIGINAL_PROTECT_FILE
    establish(path)
    if not _windows_acl_is_private(path, directory=directory):
        raise PermissionError(f"Private Windows ACL verification failed for {path}.")
    after = _path_identity(path, directory=directory)
    if after != before:
        raise PermissionError(f"Private Windows path changed while establishing its ACL: {path}.")
    _remember(after)


def _guarded_protect_private_file(path: Path) -> None:
    _protect_windows_path(path, directory=False)


def _guarded_protect_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _protect_windows_path(path, directory=True)


def install_windows_acl_guard() -> None:
    """Install the Windows-only in-process ACL verification wrapper once."""

    global _INSTALLED
    if os.name != "nt" or _INSTALLED:
        return
    logging_config.protect_private_file = _guarded_protect_private_file
    logging_config.protect_private_directory = _guarded_protect_private_directory
    _INSTALLED = True
'@
Set-Content -LiteralPath (Join-Path $root "animal_tracking\_windows_acl_guard.py") -Value $content -Encoding utf8NoBOM
$content = @'
"""Animal Tracking Release 1 implementation package."""

from animal_tracking._windows_acl_guard import install_windows_acl_guard as _install_windows_acl_guard

__version__ = "0.1.0.dev2"

_install_windows_acl_guard()
del _install_windows_acl_guard
'@
Set-Content -LiteralPath (Join-Path $root "animal_tracking\__init__.py") -Value $content -Encoding utf8NoBOM
$content = @'
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from animal_tracking import _windows_acl_guard as guard
from animal_tracking import logging_config
from animal_tracking.logging_config import protect_private_file as event_protect_private_file


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def introduce_drift(path: Path) -> None:
    completed = subprocess.run(
        ["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout).strip())


def expect_drift_failure(callable_) -> None:
    try:
        callable_()
    except PermissionError as error:
        require("ACL drift" in str(error), f"unexpected failure: {error}")
    else:
        raise AssertionError("ACL drift was not detected.")


def main() -> None:
    require(
        event_protect_private_file is guard._guarded_protect_private_file,
        "event-style import did not bind to the guarded function",
    )
    guard._clear_identity_cache()

    with tempfile.TemporaryDirectory(prefix="generation7-acl-") as temporary:
        root = Path(temporary)
        file_path = root / "security-event.jsonl"
        file_path.write_text("{}\n", encoding="utf-8")

        event_protect_private_file(file_path)
        require(logging_config.powershell_invocations == 1, "first file contact must establish ACL once")

        sequential_calls = 500
        sequential_started = time.perf_counter()
        for _ in range(sequential_calls):
            event_protect_private_file(file_path)
        sequential_seconds = time.perf_counter() - sequential_started
        require(
            logging_config.powershell_invocations == 1,
            "remembered file verification started another PowerShell process",
        )

        concurrent_workers = 16
        calls_per_worker = 100
        concurrent_started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrent_workers) as executor:
            futures = [
                executor.submit(
                    lambda: [event_protect_private_file(file_path) for _ in range(calls_per_worker)]
                )
                for _ in range(concurrent_workers)
            ]
            for future in futures:
                future.result(timeout=60)
        concurrent_seconds = time.perf_counter() - concurrent_started
        require(
            logging_config.powershell_invocations == 1,
            "concurrent file verification started another PowerShell process",
        )

        introduce_drift(file_path)
        expect_drift_failure(lambda: event_protect_private_file(file_path))
        require(
            logging_config.powershell_invocations == 1,
            "drift detection attempted PowerShell repair instead of failing closed",
        )

        directory_path = root / "logs"
        logging_config.protect_private_directory(directory_path)
        require(logging_config.powershell_invocations == 2, "directory ACL was not established once")
        for _ in range(100):
            logging_config.protect_private_directory(directory_path)
        require(
            logging_config.powershell_invocations == 2,
            "remembered directory verification started another PowerShell process",
        )
        introduce_drift(directory_path)
        expect_drift_failure(lambda: logging_config.protect_private_directory(directory_path))
        require(
            logging_config.powershell_invocations == 2,
            "directory drift detection attempted PowerShell repair",
        )

        result = {
            "result": "PASS",
            "python": __import__("sys").version,
            "sequential_calls": sequential_calls,
            "sequential_seconds": round(sequential_seconds, 6),
            "concurrent_workers": concurrent_workers,
            "concurrent_calls": concurrent_workers * calls_per_worker,
            "concurrent_seconds": round(concurrent_seconds, 6),
            "powershell_acl_establishment_invocations": logging_config.powershell_invocations,
            "file_acl_drift_detected": True,
            "directory_acl_drift_detected": True,
        }
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
'@
Set-Content -LiteralPath (Join-Path $root "validate_acl_guard.py") -Value $content -Encoding utf8NoBOM
$env:PYTHONPATH = $root
python (Join-Path $root "validate_acl_guard.py")
