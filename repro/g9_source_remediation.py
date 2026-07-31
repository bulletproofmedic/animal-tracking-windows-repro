from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import stat
import subprocess
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Final
from uuid import uuid4

_ACKNOWLEDGEMENT_TAIL_BYTES = 128 * 1024
_CHUNK_BYTES = 1024 * 1024
_FILE_ALL_ACCESS: Final = 0x001F01FF
_ACCESS_ALLOWED_ACE_TYPE: Final = 0x00
_SE_DACL_PROTECTED: Final = 0x1000
_OWNER_SECURITY_INFORMATION: Final = 0x00000001
_DACL_SECURITY_INFORMATION: Final = 0x00000004
_SE_FILE_OBJECT: Final = 1
_GENERIC_READ: Final = 0x80000000
_DELETE: Final = 0x00010000
_FILE_SHARE_READ: Final = 0x00000001
_FILE_SHARE_WRITE: Final = 0x00000002
_FILE_SHARE_DELETE: Final = 0x00000004
_OPEN_EXISTING: Final = 3
_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN: Final = 0x08000000
_FILE_DISPOSITION_INFO: Final = 4
_FILE_DISPOSITION_INFO_EX: Final = 21
_FILE_DISPOSITION_FLAG_DELETE: Final = 0x00000001
_FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: Final = 0x00000002
_FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE: Final = 0x00000010
_INVALID_HANDLE_VALUE: Final = ctypes.c_void_p(-1).value

ACKNOWLEDGEMENT_BUDGETS = {
    "max_tail_bytes_per_handler": _ACKNOWLEDGEMENT_TAIL_BYTES,
    "steady_state_acl_subprocesses_per_event": 0,
    "supported_windows_concurrent_workers": 16,
    "supported_windows_p95_latency_ms": 250,
    "supported_windows_p99_latency_ms": 500,
}

POWERSHELL_INVOCATIONS = 0
_PROTECTED_IDENTITIES: set[tuple[int, int, int]] = set()
_PROTECTED_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class CleanupResult:
    path: Path
    sha256: str
    byte_count: int


def result_for(path: Path, payload: bytes) -> CleanupResult:
    return CleanupResult(
        path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
    )


def cleanup_claim_path(result: CleanupResult) -> Path:
    name_digest = hashlib.sha256(os.fsencode(result.path.name)).hexdigest()[:16]
    return result.path.with_name(
        f".{name_digest}.{result.sha256}.failed-activation.claim"
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_dev != right.st_dev:
        return False
    if left.st_ino and right.st_ino and left.st_ino != right.st_ino:
        return False
    return True


def _path_matches_descriptor(path: Path, file_descriptor: int) -> bool:
    try:
        current = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(current.st_mode) and _same_identity(
        current, os.fstat(file_descriptor)
    )


def _hash_descriptor(file_descriptor: int) -> tuple[str, int]:
    duplicate = os.dup(file_descriptor)
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(duplicate, "rb", closefd=True) as source:
        source.seek(0)
        for chunk in iter(lambda: source.read(_CHUNK_BYTES), b""):
            count += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), count


def _descriptor_matches_result(
    file_descriptor: int, result: CleanupResult
) -> bool:
    metadata = os.fstat(file_descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != result.byte_count:
        return False
    digest, count = _hash_descriptor(file_descriptor)
    return count == result.byte_count and digest == result.sha256


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows handle APIs are unavailable on this platform.")


def _windows_libraries() -> tuple[Any, Any, Any]:
    _require_windows()
    import msvcrt

    return (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
        msvcrt,
    )


def _sid_string(sid: ctypes.c_void_p, advapi32: Any, kernel32: Any) -> str:
    from ctypes import wintypes

    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    rendered = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
    try:
        return str(rendered.value)
    finally:
        kernel32.LocalFree(ctypes.cast(rendered, ctypes.c_void_p))


def _current_user_sid(advapi32: Any, kernel32: Any) -> str:
    from ctypes import wintypes

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

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

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation sizing failed")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        sid = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents.user.sid
        return _sid_string(sid, advapi32, kernel32)
    finally:
        kernel32.CloseHandle(token)


def establish_private_acl(path: Path) -> None:
    global POWERSHELL_INVOCATIONS
    POWERSHELL_INVOCATIONS += 1
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:G9_SYNTHETIC_PATH
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true, $false)
$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $current, $rights, $inheritance, $propagation, $allow
)))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $system, $rights, $inheritance, $propagation, $allow
)))
[System.IO.File]::SetAccessControl($path, $acl)
"""
    environment = os.environ.copy()
    environment["G9_SYNTHETIC_PATH"] = str(path)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError("Synthetic ACL establishment failed.")


def file_descriptor_acl_is_private(file_descriptor: int) -> bool:
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

    advapi32, kernel32, msvcrt = _windows_libraries()
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    result = advapi32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise OSError(result, "GetSecurityInfo failed")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        if not advapi32.GetSecurityDescriptorControl(
            descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorControl failed")
        if not control.value & _SE_DACL_PROTECTED or not owner or not dacl:
            return False
        current_user = _current_user_sid(advapi32, kernel32)
        if _sid_string(owner, advapi32, kernel32) != current_user:
            return False

        advapi32.GetAclInformation.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        advapi32.GetAclInformation.restype = wintypes.BOOL
        information = AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl,
            ctypes.byref(information),
            ctypes.sizeof(information),
            2,
        ):
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")
        if information.ace_count != 2:
            return False

        advapi32.GetAce.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.GetAce.restype = wintypes.BOOL
        observed: dict[str, int] = {}
        for index in range(information.ace_count):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise OSError(ctypes.get_last_error(), "GetAce failed")
            if ace_pointer.value is None:
                raise OSError("GetAce returned a null ACE pointer")
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(AccessAllowedAce)).contents
            if (
                ace.header.ace_type != _ACCESS_ALLOWED_ACE_TYPE
                or ace.header.ace_flags != 0
                or ace.mask != _FILE_ALL_ACCESS
            ):
                return False
            sid_pointer = ctypes.c_void_p(
                ace_pointer.value + AccessAllowedAce.sid_start.offset
            )
            sid = _sid_string(sid_pointer, advapi32, kernel32)
            if sid in observed:
                return False
            observed[sid] = ace.mask
        return set(observed) == {current_user, "S-1-5-18"}
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(descriptor)


def reopen_file_descriptor_for_read(file_descriptor: int) -> int:
    from ctypes import wintypes

    _advapi32, kernel32, msvcrt = _windows_libraries()
    kernel32.ReOpenFile.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.ReOpenFile.restype = wintypes.HANDLE
    original = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
    handle = kernel32.ReOpenFile(
        original,
        _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        _FILE_FLAG_SEQUENTIAL_SCAN,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "ReOpenFile failed")
    try:
        return msvcrt.open_osfhandle(
            handle,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def open_file_for_exact_cleanup(path: Path) -> int:
    from ctypes import wintypes

    _advapi32, kernel32, msvcrt = _windows_libraries()
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        str(path),
        _GENERIC_READ | _DELETE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    try:
        return msvcrt.open_osfhandle(
            handle,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def delete_file_descriptor_on_close(file_descriptor: int) -> None:
    from ctypes import wintypes

    _advapi32, kernel32, msvcrt = _windows_libraries()
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))

    class FileDispositionInfoEx(ctypes.Structure):
        _fields_ = [("flags", wintypes.DWORD)]

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOL)]

    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    extended = FileDispositionInfoEx(
        _FILE_DISPOSITION_FLAG_DELETE
        | _FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
        | _FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
    )
    if kernel32.SetFileInformationByHandle(
        handle,
        _FILE_DISPOSITION_INFO_EX,
        ctypes.byref(extended),
        ctypes.sizeof(extended),
    ):
        return
    first_error = ctypes.get_last_error()
    legacy = FileDispositionInfo(True)
    if kernel32.SetFileInformationByHandle(
        handle,
        _FILE_DISPOSITION_INFO,
        ctypes.byref(legacy),
        ctypes.sizeof(legacy),
    ):
        return
    raise OSError(
        ctypes.get_last_error() or first_error,
        "SetFileInformationByHandle failed",
    )


def _open_candidate(path: Path) -> int:
    if os.name == "nt":
        return open_file_for_exact_cleanup(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _delete_open_exact_file(path: Path, file_descriptor: int) -> None:
    if os.name == "nt":
        delete_file_descriptor_on_close(file_descriptor)
        return
    if not _path_matches_descriptor(path, file_descriptor):
        raise RuntimeError("The cleanup candidate path changed before exact removal.")
    raise RuntimeError(
        "Exact cleanup is unavailable on this platform; the claim was preserved."
    )


def unlink_exact_result(
    result: CleanupResult,
    *,
    before_open: Any = None,
    before_delete: Any = None,
) -> Path:
    claim = cleanup_claim_path(result)
    if claim.exists() or claim.is_symlink():
        raise RuntimeError("A cleanup claim already exists.")
    os.replace(result.path, claim)
    if before_open is not None:
        before_open(claim)
    descriptor = _open_candidate(claim)
    try:
        claimed = CleanupResult(claim, result.sha256, result.byte_count)
        if not _descriptor_matches_result(descriptor, claimed):
            raise RuntimeError("The claimed file no longer matches its exact identity.")
        if not _path_matches_descriptor(claim, descriptor):
            raise RuntimeError("The claim changed during exact identity validation.")
        if before_delete is not None:
            before_delete(claim)
        _delete_open_exact_file(claim, descriptor)
    finally:
        os.close(descriptor)
    return claim


def delete_exact_marker(
    marker: Path,
    expected: bytes,
    *,
    before_delete: Any = None,
) -> None:
    descriptor = _open_candidate(marker)
    try:
        duplicate = os.dup(descriptor)
        with os.fdopen(duplicate, "rb", closefd=True) as source:
            observed = source.read(len(expected) + 1)
        if observed != expected:
            raise RuntimeError("The cleanup marker changed before removal.")
        if not _path_matches_descriptor(marker, descriptor):
            raise RuntimeError("The cleanup marker path changed before removal.")
        if before_delete is not None:
            before_delete(marker)
        _delete_open_exact_file(marker, descriptor)
    finally:
        os.close(descriptor)


def _path_identity(path: Path) -> tuple[int, int, int]:
    metadata = path.stat(follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino, metadata.st_ctime_ns


def _verify_windows_path_acl(path: Path) -> bool:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        return file_descriptor_acl_is_private(descriptor)
    finally:
        os.close(descriptor)


def protect_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise PermissionError("Private log is not a regular file.")
    if os.name != "nt":
        os.chmod(path, 0o600)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise PermissionError("Private file mode was not established.")
        return
    identity = _path_identity(path)
    with _PROTECTED_LOCK:
        if identity in _PROTECTED_IDENTITIES:
            if not _verify_windows_path_acl(path):
                raise PermissionError("Private Windows ACL drift was detected.")
            return
        establish_private_acl(path)
        if not _verify_windows_path_acl(path):
            raise PermissionError("Private Windows ACL verification failed.")
        _PROTECTED_IDENTITIES.add(_path_identity(path))


class SyntheticJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "component": "synthetic.security",
            "correlation_id": record.correlation_id,
            "event_code": record.event_code,
            "message": "Synthetic rejection event",
            "record_id": record.record_id,
            "severity": record.levelname,
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class ProtectedRotatingFileHandler(RotatingFileHandler):
    def _open(self):  # type: ignore[no-untyped-def]
        stream = super()._open()
        try:
            protect_private_file(Path(self.baseFilename))
        except Exception:
            stream.close()
            raise
        return stream


def _handler_identity_is_current(handler: ProtectedRotatingFileHandler) -> bool:
    stream = handler.stream
    if stream is None:
        return False
    path = Path(handler.baseFilename)
    if path.is_symlink() or not path.is_file():
        return False
    return _same_identity(os.fstat(stream.fileno()), path.stat())


def _reopen_same_object_for_read(file_descriptor: int) -> int:
    if os.name == "nt":
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
    raise OSError("The active file object could not be reopened safely.")


def _descriptor_is_private(file_descriptor: int) -> bool:
    if os.name == "nt":
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


def acknowledge(
    handler: ProtectedRotatingFileHandler, rendered: bytes
) -> None:
    if handler.stream is None:
        raise RuntimeError("The event handler has no open stream.")
    handler.flush()
    descriptor = handler.stream.fileno()
    os.fsync(descriptor)
    if not _handler_identity_is_current(handler):
        raise RuntimeError("The event log path changed after initialization.")
    protect_private_file(Path(handler.baseFilename))
    if not _handler_identity_is_current(handler):
        raise RuntimeError("The event log path changed during ACL verification.")
    if not _descriptor_is_private(descriptor):
        raise RuntimeError("The active event file is not owner-private.")
    if rendered not in _bounded_tail_lines(descriptor):
        raise RuntimeError("The exact event was not found on the persisted file object.")
    if not _handler_identity_is_current(handler):
        raise RuntimeError("The event log path changed during acknowledgement.")


class SyntheticEventLogger:
    def __init__(self, path: Path, *, max_bytes: int, backup_count: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.handler = ProtectedRotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        self.handler.setFormatter(SyntheticJsonFormatter())
        self.logger = logging.Logger("synthetic.security", level=logging.INFO)
        self.logger.propagate = False
        self.logger.addHandler(self.handler)

    def emit(self, correlation_id: str) -> None:
        record = logging.LogRecord(
            name="synthetic.security",
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg="Synthetic rejection event",
            args=(),
            exc_info=None,
        )
        record.correlation_id = correlation_id
        record.event_code = "SEC_SYNTHETIC_REJECTED"
        record.record_id = uuid4().hex
        with self._lock:
            self.handler.acquire()
            try:
                rendered = self.handler.format(record).encode("utf-8")
                self.handler.handle(record)
                acknowledge(self.handler, rendered)
            finally:
                self.handler.release()

    def close(self) -> None:
        self.handler.close()


def drift_windows_acl(path: Path) -> None:
    _require_windows()
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:G9_SYNTHETIC_PATH
$acl = Get-Acl -LiteralPath $path
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = [System.Security.AccessControl.FileSystemRights]::Read
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $everyone, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl
"""
    environment = os.environ.copy()
    environment["G9_SYNTHETIC_PATH"] = str(path)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError("Synthetic ACL drift setup failed.")


def log_paths(path: Path) -> tuple[Path, ...]:
    return tuple(sorted(path.parent.glob(f"{path.name}*"), key=lambda item: item.name))


def read_event_records(paths: tuple[Path, ...]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            if payload.get("event_code") == "SEC_SYNTHETIC_REJECTED":
                records.append(payload)
    return records
