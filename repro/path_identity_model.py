from __future__ import annotations

import ctypes
import json
import os
import stat
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator


class ControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int
    volume_serial: int
    file_index: int

    def as_dict(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "volume_serial": self.volume_serial,
            "file_index": self.file_index,
        }

    @classmethod
    def from_dict(cls, value: object) -> DirectoryIdentity:
        if not isinstance(value, dict):
            raise ControlError("identity missing")
        result: dict[str, int] = {}
        for key in ("device", "inode", "volume_serial", "file_index"):
            raw = value.get(key)
            if type(raw) is not int or raw < 0:
                raise ControlError("identity malformed")
            result[key] = raw
        return cls(**result)


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTimeLow", ctypes.c_uint32),
        ("ftCreationTimeHigh", ctypes.c_uint32),
        ("ftLastAccessTimeLow", ctypes.c_uint32),
        ("ftLastAccessTimeHigh", ctypes.c_uint32),
        ("ftLastWriteTimeLow", ctypes.c_uint32),
        ("ftLastWriteTimeHigh", ctypes.c_uint32),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


def absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def metadata(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as exc:
        raise ControlError("path unavailable") from exc
    attrs = int(getattr(value, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if stat.S_ISLNK(value.st_mode) or attrs & reparse:
        raise ControlError("link or reparse path")
    if not stat.S_ISDIR(value.st_mode):
        raise ControlError("not a directory")
    return value


def open_windows_directory(path: Path) -> int:
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
    handle = create_file(
        str(path),
        0x00000080,
        0x00000001 | 0x00000002,
        None,
        3,
        0x00200000 | 0x02000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    value = int(handle or 0)
    if not value or value == invalid:
        error = ctypes.get_last_error()
        raise ControlError("directory handle unavailable") from OSError(
            error, os.strerror(error)
        )
    return value


def windows_identity(handle: int) -> tuple[int, int]:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    function: Any = kernel32.GetFileInformationByHandle
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation)]
    function.restype = ctypes.c_int
    info = _ByHandleFileInformation()
    if not function(ctypes.c_void_p(handle), ctypes.byref(info)):
        error = ctypes.get_last_error()
        raise ControlError("handle identity unavailable") from OSError(error, os.strerror(error))
    index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
    return int(info.dwVolumeSerialNumber), index


class Pin:
    def __init__(self, path: Path, expected: DirectoryIdentity | None = None) -> None:
        self.path = absolute(path)
        value = metadata(self.path)
        self.device = int(value.st_dev)
        self.inode = int(value.st_ino)
        self.handle: int | None = None
        self.fd: int | None = None
        volume = 0
        index = 0
        if os.name == "nt":
            self.handle = open_windows_directory(self.path)
            volume, index = windows_identity(self.handle)
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            self.fd = os.open(self.path, flags)
        self.identity = DirectoryIdentity(self.device, self.inode, volume, index)
        if expected is not None and expected != self.identity:
            self.close()
            raise ControlError("recorded directory identity changed")
        self.verify()

    def verify(self) -> None:
        value = metadata(self.path)
        if int(value.st_dev) != self.device or int(value.st_ino) != self.inode:
            raise ControlError("directory pathname changed")
        if self.handle is not None:
            if windows_identity(self.handle) != (
                self.identity.volume_serial,
                self.identity.file_index,
            ):
                raise ControlError("directory handle changed")
        if self.fd is not None:
            value = os.fstat(self.fd)
            if int(value.st_dev) != self.device or int(value.st_ino) != self.inode:
                raise ControlError("directory descriptor changed")

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.handle is not None:
            kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None

    def __enter__(self) -> Pin:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass
class Chain:
    pins: tuple[Pin, ...]

    @property
    def final(self) -> Pin:
        return self.pins[-1]

    def verify(self) -> None:
        for pin in self.pins:
            pin.verify()


@contextmanager
def pin_chain(path: Path, *, expected: DirectoryIdentity | None = None) -> Iterator[Chain]:
    target = absolute(path)
    anchor = Path(target.anchor)
    current = anchor
    components = [anchor]
    for part in target.parts[len(anchor.parts) :]:
        current /= part
        components.append(current)
    with ExitStack() as stack:
        pins: list[Pin] = []
        for position, component in enumerate(components):
            pin = stack.enter_context(
                Pin(component, expected if position == len(components) - 1 else None)
            )
            pins.append(pin)
        chain = Chain(tuple(pins))
        chain.verify()
        yield chain
        chain.verify()


def publish_new(source: Path, destination: Path, chain: Chain) -> None:
    chain.verify()
    if source.parent != destination.parent or absolute(source.parent) != chain.final.path:
        raise ControlError("publication outside pinned directory")
    if destination.exists() or destination.is_symlink():
        raise ControlError("destination exists")
    if not source.is_file() or source.is_symlink():
        raise ControlError("source is not regular")
    with source.open("r+b") as handle:
        os.fsync(handle.fileno())
    chain.verify()
    if os.name == "nt":
        kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        move: Any = kernel32.MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        move.restype = ctypes.c_int
        if not move(str(source), str(destination), 0x00000008):
            error = ctypes.get_last_error()
            raise ControlError("publication failed") from OSError(error, os.strerror(error))
    else:
        os.link(source, destination)
        source.unlink()
    chain.verify()
    if not destination.is_file() or destination.is_symlink():
        raise ControlError("published object is unsafe")


def write_journal(path: Path, destination: Path, identity: DirectoryIdentity) -> None:
    path.write_text(
        json.dumps(
            {
                "destination": str(absolute(destination)),
                "destination_directory_identity": identity.as_dict(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def reconcile(journal_path: Path, temporary: Path) -> Path:
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    destination = absolute(Path(journal["destination"]))
    expected = DirectoryIdentity.from_dict(journal["destination_directory_identity"])
    with pin_chain(destination.parent, expected=expected) as chain:
        publish_new(temporary, destination, chain)
    return destination


def extract_member(
    payload: bytes,
    staged_root: Path,
    relative: str,
    *,
    probe: Callable[[str, Path], None] | None = None,
) -> Path:
    root = absolute(staged_root)
    parts = Path(*relative.split("/"))
    target = absolute(root / parts)
    target.relative_to(root)
    with Pin(root) as root_pin:
        parent = target.parent
        current = root
        with ExitStack() as stack:
            pins = [root_pin]
            for part in parent.relative_to(root).parts:
                current /= part
                pins[-1].verify()
                current.mkdir(exist_ok=True)
                pins.append(stack.enter_context(Pin(current)))
            chain = Chain(tuple(pins))
            temporary = target.with_suffix(target.suffix + ".part")
            if probe is not None:
                probe("before_temporary_open", temporary)
            chain.verify()
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if probe is not None:
                probe("before_final_publication", target)
            chain.verify()
            publish_new(temporary, target, chain)
            return target
