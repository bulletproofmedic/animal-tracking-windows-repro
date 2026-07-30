from __future__ import annotations

import ctypes
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


class AuthorityError(RuntimeError):
    pass


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _validate_directory(path: Path) -> None:
    metadata = os.lstat(path)
    if _is_reparse(path):
        raise AuthorityError("link or reparse point")
    if not stat.S_ISDIR(metadata.st_mode):
        raise AuthorityError("not a directory")


def _open_without_delete_sharing(path: Path, *, directory: bool) -> int:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file: Any = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    desired_access = 0x80 if directory else 0x80000000
    flags = 0x00200000 | (0x02000000 if directory else 0)
    handle = create_file(
        str(path),
        desired_access,
        0x1 | 0x2,
        None,
        3,
        flags,
        None,
    )
    value = int(handle or 0)
    if not value or value == ctypes.c_void_p(-1).value:
        raise AuthorityError(f"CreateFileW failed: {ctypes.get_last_error()}")
    return value


def _close(handle: int) -> None:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(ctypes.c_void_p(handle))


def _create_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)


class WindowsAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows-specific authority semantics")

    def test_directory_handle_alone_does_not_pin_namespace_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / ".active.recovery"
            displaced = parent / ".active.recovery.displaced"
            root.mkdir()
            handle = _open_without_delete_sharing(root, directory=True)
            try:
                root.rename(displaced)
                self.assertFalse(root.exists())
                self.assertTrue(displaced.is_dir())
            finally:
                _close(handle)
            displaced.rename(root)

    def test_sentinel_file_handle_blocks_authority_root_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / ".active.recovery"
            displaced = parent / ".active.recovery.displaced"
            root.mkdir()
            sentinel = root / ".authority.pin"
            sentinel.write_bytes(b"1")
            handle = _open_without_delete_sharing(sentinel, directory=False)
            try:
                with self.assertRaises(OSError):
                    root.rename(displaced)
                self.assertTrue(root.is_dir())
                self.assertFalse(displaced.exists())
            finally:
                _close(handle)

    def test_preexisting_junction_is_rejected_as_authority_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "redirected"
            root = parent / ".active.recovery"
            target.mkdir()
            _create_junction(root, target)
            self.assertTrue(_is_reparse(root))
            with self.assertRaisesRegex(AuthorityError, "link or reparse"):
                _validate_directory(root)

    def test_nested_junction_is_rejected_before_child_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / ".active.recovery"
            target = parent / "redirected-runtime"
            runtime = root / "runtime"
            root.mkdir()
            target.mkdir()
            _create_junction(runtime, target)
            _validate_directory(root)
            self.assertTrue(_is_reparse(runtime))
            with self.assertRaisesRegex(AuthorityError, "link or reparse"):
                _validate_directory(runtime)
            self.assertFalse((target / "recovery.lock").exists())


if __name__ == "__main__":
    unittest.main()
