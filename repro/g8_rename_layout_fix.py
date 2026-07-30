from __future__ import annotations

import ctypes
from pathlib import Path

_FILE_RENAME_INFO = 3


def rename_file_descriptor_noreplace(file_descriptor: int, destination: Path) -> None:
    """Use the Win32 FILE_RENAME_INFO layout with one-byte BOOLEAN."""

    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
    encoded = str(destination.resolve()).encode("utf-16-le")

    class FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", wintypes.BYTE),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    buffer_size = FileRenameInfo.file_name.offset + len(encoded) + 2
    buffer = ctypes.create_string_buffer(buffer_size)
    information = ctypes.cast(buffer, ctypes.POINTER(FileRenameInfo)).contents
    information.replace_if_exists = 0
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
