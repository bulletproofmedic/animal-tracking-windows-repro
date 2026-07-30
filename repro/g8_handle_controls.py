from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path
from typing import Any, Final

_FILE_ALL_ACCESS: Final = 0x001F01FF
_ACCESS_ALLOWED_ACE_TYPE: Final = 0x00
_SE_DACL_PROTECTED: Final = 0x1000
_OWNER_SECURITY_INFORMATION: Final = 0x00000001
_DACL_SECURITY_INFORMATION: Final = 0x00000004
_SE_FILE_OBJECT: Final = 1
_GENERIC_READ: Final = 0x80000000
_GENERIC_WRITE: Final = 0x40000000
_DELETE: Final = 0x00010000
_FILE_SHARE_READ: Final = 0x00000001
_FILE_SHARE_WRITE: Final = 0x00000002
_FILE_SHARE_DELETE: Final = 0x00000004
_OPEN_EXISTING: Final = 3
_FILE_ATTRIBUTE_NORMAL: Final = 0x00000080
_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN: Final = 0x08000000
_FILE_DISPOSITION_INFO: Final = 4
_FILE_RENAME_INFO: Final = 3
_FILE_DISPOSITION_INFO_EX: Final = 21
_FILE_DISPOSITION_FLAG_DELETE: Final = 0x00000001
_FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: Final = 0x00000002
_FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE: Final = 0x00000010
_INVALID_HANDLE_VALUE: Final = ctypes.c_void_p(-1).value

POWERSHELL_INVOCATIONS = 0


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("This diagnostic requires Windows.")


def _libraries() -> tuple[Any, Any, Any]:
    _require_windows()
    import msvcrt

    return (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
        msvcrt,
    )


def establish_private_acl(path: Path) -> None:
    global POWERSHELL_INVOCATIONS
    POWERSHELL_INVOCATIONS += 1
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:G8_SYNTHETIC_PATH
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
    environment["G8_SYNTHETIC_PATH"] = str(path)
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
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        sid = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents.user.sid
        return _sid_string(sid, advapi32, kernel32)
    finally:
        kernel32.CloseHandle(token)


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

    advapi32, kernel32, msvcrt = _libraries()
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
        advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        control = wintypes.WORD()
        revision = wintypes.DWORD()
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

    _advapi32, kernel32, msvcrt = _libraries()
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


def read_exact_object(file_descriptor: int) -> bytes:
    reopened = reopen_file_descriptor_for_read(file_descriptor)
    with os.fdopen(reopened, "rb", closefd=True) as source:
        source.seek(0)
        return source.read()


def open_shared_file(path: Path) -> int:
    from ctypes import wintypes

    _advapi32, kernel32, msvcrt = _libraries()
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
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    try:
        return msvcrt.open_osfhandle(
            handle,
            os.O_RDWR | getattr(os, "O_BINARY", 0),
        )
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def open_file_for_exact_cleanup(path: Path) -> int:
    from ctypes import wintypes

    _advapi32, kernel32, msvcrt = _libraries()
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

    _advapi32, kernel32, msvcrt = _libraries()
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


def rename_file_descriptor_noreplace(file_descriptor: int, destination: Path) -> None:
    from ctypes import wintypes

    _advapi32, kernel32, msvcrt = _libraries()
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
    rendered = str(destination.resolve())
    encoded = rendered.encode("utf-16-le")

    class FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", wintypes.BOOL),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    buffer_size = FileRenameInfo.file_name.offset + len(encoded)
    buffer = ctypes.create_string_buffer(buffer_size)
    information = ctypes.cast(buffer, ctypes.POINTER(FileRenameInfo)).contents
    information.replace_if_exists = False
    information.root_directory = None
    information.file_name_length = len(encoded)
    ctypes.memmove(
        ctypes.addressof(buffer) + FileRenameInfo.file_name.offset,
        encoded,
        len(encoded),
    )

    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    if not kernel32.SetFileInformationByHandle(
        handle,
        _FILE_RENAME_INFO,
        buffer,
        buffer_size,
    ):
        raise OSError(ctypes.get_last_error(), "Handle-bound no-replace rename failed")
