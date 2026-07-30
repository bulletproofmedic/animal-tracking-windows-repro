from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator
from uuid import uuid4


class ControlError(RuntimeError):
    pass


PROBE: Callable[[str, Path], None] = lambda _boundary, _path: None


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
            raise ControlError("directory identity missing")
        fields: dict[str, int] = {}
        for key in ("device", "inode", "volume_serial", "file_index"):
            raw = value.get(key)
            if type(raw) is not int or raw < 0:
                raise ControlError("directory identity malformed")
            fields[key] = raw
        return cls(**fields)


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


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_wchar_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", ctypes.c_ulong),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_void_p),
        ("Information", ctypes.c_size_t),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_bool)]


def absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _validate_name(name: str) -> None:
    if not name or name in {".", ".."} or Path(name).name != name:
        raise ControlError("invalid child name")
    if "/" in name or "\\" in name:
        raise ControlError("invalid child name")


def _metadata(path: Path) -> os.stat_result:
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


def _file_metadata(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as exc:
        raise ControlError("sentinel unavailable") from exc
    attrs = int(getattr(value, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if stat.S_ISLNK(value.st_mode) or attrs & reparse:
        raise ControlError("sentinel is a link or reparse path")
    if not stat.S_ISREG(value.st_mode):
        raise ControlError("sentinel is not a regular file")
    return value


def _handle_details(handle: int) -> tuple[int, int, int]:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    function: Any = kernel32.GetFileInformationByHandle
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation)]
    function.restype = ctypes.c_int
    information = _ByHandleFileInformation()
    if not function(ctypes.c_void_p(handle), ctypes.byref(information)):
        error = ctypes.get_last_error()
        raise ControlError("handle identity unavailable") from OSError(
            error, os.strerror(error)
        )
    index = (int(information.nFileIndexHigh) << 32) | int(
        information.nFileIndexLow
    )
    return (
        int(information.dwVolumeSerialNumber),
        index,
        int(information.dwFileAttributes),
    )


def _close_handle(handle: int) -> None:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(ctypes.c_void_p(handle))


class EphemeralSentinel:
    """Hold a delete-blocking file open for one directory-operation lifetime."""

    def __init__(self, directory: Path) -> None:
        if os.name != "nt":
            raise ControlError("ephemeral sentinel diagnostic requires Windows")
        self.path: Path | None = None
        self.handle: int | None = None
        self.device = 0
        self.inode = 0
        self.volume = 0
        self.index = 0
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
        invalid = ctypes.c_void_p(-1).value
        for _attempt in range(8):
            path = directory / f".animal-tracking-pin-{uuid4().hex}.tmp"
            raw = create_file(
                str(path),
                0x80000000 | 0x40000000 | 0x00010000,
                0x00000001 | 0x00000002,
                None,
                1,
                0x00000002 | 0x00000100 | 0x00200000 | 0x04000000,
                None,
            )
            handle = int(raw or 0)
            if handle and handle != invalid:
                self.path = path
                self.handle = handle
                try:
                    value = _file_metadata(path)
                    self.device = int(value.st_dev)
                    self.inode = int(value.st_ino)
                    self.volume, self.index, _ = _handle_details(handle)
                    self.verify()
                    return
                except BaseException:
                    self.close()
                    raise
            error = ctypes.get_last_error()
            if error not in {80, 183}:
                raise ControlError("ephemeral sentinel creation failed") from OSError(
                    error, os.strerror(error)
                )
        raise ControlError("ephemeral sentinel name collisions")

    def verify(self) -> None:
        if self.path is None or self.handle is None:
            raise ControlError("ephemeral sentinel is closed")
        value = _file_metadata(self.path)
        if (int(value.st_dev), int(value.st_ino)) != (self.device, self.inode):
            raise ControlError("ephemeral sentinel pathname changed")
        volume, index, _ = _handle_details(self.handle)
        if (volume, index) != (self.volume, self.index):
            raise ControlError("ephemeral sentinel handle changed")

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle is not None:
            _close_handle(handle)


def _status_error(status: int) -> OSError:
    ntdll: Any = ctypes.WinDLL("ntdll")
    convert: Any = ntdll.RtlNtStatusToDosError
    convert.argtypes = [ctypes.c_long]
    convert.restype = ctypes.c_ulong
    code = int(convert(ctypes.c_long(status)))
    return OSError(code, os.strerror(code))


@contextmanager
def _owner_only_security_descriptor() -> Iterator[int | None]:
    if os.name != "nt":
        yield None
        return
    advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    convert: Any = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    convert.restype = ctypes.c_int
    descriptor = ctypes.c_void_p()
    size = ctypes.c_uint32()
    sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)):
        error = ctypes.get_last_error()
        raise ControlError("security descriptor unavailable") from OSError(
            error, os.strerror(error)
        )
    try:
        yield int(descriptor.value or 0)
    finally:
        if descriptor.value:
            kernel32.LocalFree(ctypes.c_void_p(descriptor.value))


def _open_relative(
    parent_handle: int,
    name: str,
    *,
    directory: bool,
    create: bool,
    writable: bool = False,
    deletable: bool = False,
    exclusive: bool = False,
    security_descriptor: int | None = None,
) -> int:
    _validate_name(name)
    buffer = ctypes.create_unicode_buffer(name)
    byte_length = len(name.encode("utf-16-le"))
    unicode_name = _UnicodeString(
        byte_length,
        byte_length + 2,
        ctypes.cast(buffer, ctypes.c_wchar_p),
    )
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        ctypes.c_void_p(parent_handle),
        ctypes.pointer(unicode_name),
        0x00000040,
        ctypes.c_void_p(security_descriptor) if security_descriptor else None,
        None,
    )
    io_status = _IoStatusBlock()
    handle = ctypes.c_void_p()
    ntdll: Any = ctypes.WinDLL("ntdll")
    create_file: Any = ntdll.NtCreateFile
    create_file.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    create_file.restype = ctypes.c_long
    if directory:
        access = 0x00000001 | 0x00000020 | 0x00000080 | 0x00100000
        if deletable:
            access |= 0x00010000
    else:
        access = 0x80000000 | 0x00100000
        if writable:
            access |= 0x40000000
        if deletable:
            access |= 0x00010000
    share = 0x00000001 | 0x00000002
    if not deletable:
        share |= 0x00000004
    if exclusive:
        disposition = 2
    elif directory and create:
        disposition = 3
    elif create:
        disposition = 2
    else:
        disposition = 1
    options = 0x00000020 | 0x00200000
    options |= 0x00000001 if directory else 0x00000040
    status = int(
        create_file(
            ctypes.byref(handle),
            access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            0x00000080,
            share,
            disposition,
            options,
            None,
            0,
        )
    )
    if status < 0 or not handle.value:
        raise ControlError("relative open failed") from _status_error(status)
    value = int(handle.value)
    _, _, attrs = _handle_details(value)
    if attrs & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        _close_handle(value)
        raise ControlError("reparse child")
    if bool(attrs & 0x00000010) != directory:
        _close_handle(value)
        raise ControlError("wrong child type")
    return value


def _rename_open_file(file_handle: int, parent_handle: int, name: str) -> None:
    _validate_name(name)
    file_name_type = ctypes.c_wchar * len(name)

    class _FileRenameInformation(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", ctypes.c_bool),
            ("RootDirectory", ctypes.c_void_p),
            ("FileNameLength", ctypes.c_uint32),
            ("FileName", file_name_type),
        ]

    information = _FileRenameInformation(
        False,
        ctypes.c_void_p(parent_handle),
        len(name.encode("utf-16-le")),
        name,
    )
    io_status = _IoStatusBlock()
    ntdll: Any = ctypes.WinDLL("ntdll")
    function: Any = ntdll.NtSetInformationFile
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    function.restype = ctypes.c_long
    status = int(
        function(
            ctypes.c_void_p(file_handle),
            ctypes.byref(io_status),
            ctypes.byref(information),
            ctypes.sizeof(information),
            10,  # FileRenameInformation
        )
    )
    if status < 0:
        raise ControlError("relative rename failed") from _status_error(status)


def _delete_open(file_handle: int) -> None:
    information = _FileDispositionInfo(True)
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    function: Any = kernel32.SetFileInformationByHandle
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    function.restype = ctypes.c_int
    if not function(
        ctypes.c_void_p(file_handle),
        4,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error = ctypes.get_last_error()
        raise ControlError("handle delete failed") from OSError(
            error, os.strerror(error)
        )


class Pin:
    def __init__(
        self,
        path: Path,
        *,
        expected: DirectoryIdentity | None = None,
    ) -> None:
        self.path = absolute(path)
        value = _metadata(self.path)
        self.device = int(value.st_dev)
        self.inode = int(value.st_ino)
        self.handle: int | None = None
        self.fd: int | None = None
        self.sentinel: EphemeralSentinel | None = None
        volume = 0
        index = 0
        if os.name == "nt":
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
            raw = create_file(
                str(self.path),
                0x00000001 | 0x00000020 | 0x00000080 | 0x00100000,
                0x00000001 | 0x00000002,
                None,
                3,
                0x00200000 | 0x02000000,
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            self.handle = int(raw or 0)
            if not self.handle or self.handle == invalid:
                error = ctypes.get_last_error()
                raise ControlError("directory pin failed") from OSError(
                    error, os.strerror(error)
                )
            volume, index, _ = _handle_details(self.handle)
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            self.fd = os.open(self.path, flags)
        self.identity = DirectoryIdentity(self.device, self.inode, volume, index)
        if expected is not None and expected != self.identity:
            self.close()
            raise ControlError("recorded directory identity changed")
        self.verify()

    @classmethod
    def from_child_handle(cls, path: Path, handle: int) -> Pin:
        instance = cls.__new__(cls)
        instance.path = absolute(path)
        value = _metadata(instance.path)
        instance.device = int(value.st_dev)
        instance.inode = int(value.st_ino)
        instance.handle = handle
        instance.fd = None
        instance.sentinel = None
        volume, index, _ = _handle_details(handle)
        instance.identity = DirectoryIdentity(
            instance.device,
            instance.inode,
            volume,
            index,
        )
        instance.verify()
        return instance

    @classmethod
    def from_child_fd(cls, path: Path, fd: int) -> Pin:
        instance = cls.__new__(cls)
        instance.path = absolute(path)
        value = os.fstat(fd)
        instance.device = int(value.st_dev)
        instance.inode = int(value.st_ino)
        instance.handle = None
        instance.fd = fd
        instance.sentinel = None
        instance.identity = DirectoryIdentity(instance.device, instance.inode, 0, 0)
        instance.verify()
        return instance

    def verify(self) -> None:
        value = _metadata(self.path)
        if int(value.st_dev) != self.device or int(value.st_ino) != self.inode:
            raise ControlError("directory pathname changed")
        if self.handle is not None:
            volume, index, _ = _handle_details(self.handle)
            if (volume, index) != (
                self.identity.volume_serial,
                self.identity.file_index,
            ):
                raise ControlError("directory handle changed")
        if self.fd is not None:
            value = os.fstat(self.fd)
            if (int(value.st_dev), int(value.st_ino)) != (
                self.device,
                self.inode,
            ):
                raise ControlError("directory descriptor changed")
        if self.sentinel is not None:
            self.sentinel.verify()

    def protect_namespace(self) -> None:
        self.verify()
        if os.name == "nt" and self.sentinel is None:
            self.sentinel = EphemeralSentinel(self.path)
        self.verify()

    def child(
        self,
        name: str,
        *,
        create: bool,
        exclusive: bool = False,
        secure: bool = False,
    ) -> Pin:
        _validate_name(name)
        self.verify()
        PROBE("after_child_parent_identity_check", self.path / name)
        if os.name == "nt":
            assert self.handle is not None
            with _owner_only_security_descriptor() as descriptor:
                handle = _open_relative(
                    self.handle,
                    name,
                    directory=True,
                    create=create,
                    exclusive=exclusive,
                    security_descriptor=descriptor if secure and create else None,
                )
            try:
                child = Pin.from_child_handle(self.path / name, handle)
            except BaseException:
                _close_handle(handle)
                raise
        else:
            assert self.fd is not None
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=self.fd)
                except FileExistsError:
                    if exclusive:
                        raise ControlError("directory exists") from None
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(name, flags, dir_fd=self.fd)
            try:
                child = Pin.from_child_fd(self.path / name, fd)
            except BaseException:
                os.close(fd)
                raise
        self.verify()
        try:
            if create:
                child.protect_namespace()
        except BaseException:
            child.close()
            raise
        return child

    def replace_empty_staging_child(self, name: str) -> Pin:
        if os.name == "nt":
            assert self.handle is not None
            old = _open_relative(
                self.handle,
                name,
                directory=True,
                create=False,
                deletable=True,
            )
            try:
                _delete_open(old)
            finally:
                _close_handle(old)
        else:
            assert self.fd is not None
            os.rmdir(name, dir_fd=self.fd)
        return self.child(name, create=True, exclusive=True, secure=True)

    def open_file(
        self,
        name: str,
        *,
        create: bool,
        mutable: bool,
        deletable: bool,
    ) -> BinaryIO:
        self.verify()
        PROBE("after_temporary_parent_identity_check", self.path / name)
        if os.name == "nt":
            assert self.handle is not None
            raw = _open_relative(
                self.handle,
                name,
                directory=False,
                create=create,
                writable=mutable,
                deletable=deletable,
                exclusive=create,
            )
            try:
                import msvcrt

                flags = os.O_BINARY | (os.O_RDWR if mutable else os.O_RDONLY)
                fd = msvcrt.open_osfhandle(raw, flags)
            except BaseException:
                _close_handle(raw)
                raise
        else:
            assert self.fd is not None
            flags = os.O_RDWR if mutable else os.O_RDONLY
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(name, flags, 0o600, dir_fd=self.fd)
        file = os.fdopen(fd, "r+b" if mutable else "rb")
        try:
            self.verify()
        except BaseException:
            if create:
                with suppress(Exception):
                    self.delete_without_verify(file, name)
            file.close()
            raise
        return file

    def delete_without_verify(self, file: BinaryIO, name: str) -> None:
        if os.name == "nt":
            import msvcrt

            _delete_open(int(msvcrt.get_osfhandle(file.fileno())))
        else:
            assert self.fd is not None
            os.unlink(name, dir_fd=self.fd)

    def publish(self, file: BinaryIO, source_name: str, destination_name: str) -> None:
        file.flush()
        os.fsync(file.fileno())
        PROBE("before_final_publication", self.path / destination_name)
        self.verify()
        PROBE("after_final_parent_identity_check", self.path / destination_name)
        if os.name == "nt":
            import msvcrt

            assert self.handle is not None
            _rename_open_file(
                int(msvcrt.get_osfhandle(file.fileno())),
                self.handle,
                destination_name,
            )
        else:
            assert self.fd is not None
            os.link(
                source_name,
                destination_name,
                src_dir_fd=self.fd,
                dst_dir_fd=self.fd,
                follow_symlinks=False,
            )
            os.unlink(source_name, dir_fd=self.fd)
        file.flush()
        os.fsync(file.fileno())
        if self.fd is not None:
            os.fsync(self.fd)
        self.verify()

    def close(self) -> None:
        if self.sentinel is not None:
            self.sentinel.close()
            self.sentinel = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.handle is not None:
            _close_handle(self.handle)
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
    parts = target.parts[len(anchor.parts) :]
    with ExitStack() as stack:
        pins = [stack.enter_context(Pin(anchor))]
        for index, part in enumerate(parts):
            child = stack.enter_context(pins[-1].child(part, create=False))
            pins.append(child)
            if index == len(parts) - 1 and expected is not None:
                if child.identity != expected:
                    raise ControlError("recorded directory identity changed")
        pins[-1].protect_namespace()
        chain = Chain(tuple(pins))
        chain.verify()
        yield chain
        chain.verify()


def sha256_file(file: BinaryIO) -> tuple[str, int]:
    position = file.tell()
    try:
        file.seek(0)
        digest = hashlib.sha256()
        size = 0
        while block := file.read(65536):
            digest.update(block)
            size += len(block)
        return digest.hexdigest(), size
    finally:
        file.seek(position)


def publish_payload(directory: Path, name: str, payload: bytes) -> DirectoryIdentity:
    with pin_chain(directory) as chain:
        selected = chain.final.identity
        temp_name = f"{name}.part"
        with chain.final.open_file(
            temp_name,
            create=True,
            mutable=True,
            deletable=True,
        ) as file:
            published = False
            try:
                file.write(payload)
                temporary = chain.final.identity
                if temporary != selected:
                    raise ControlError("identity changed before temporary creation")
                chain.final.publish(file, temp_name, name)
                published = True
                final = chain.final.identity
                if final != selected:
                    raise ControlError("identity changed at final publication")
            except BaseException:
                if not published:
                    with suppress(Exception):
                        chain.final.delete_without_verify(file, temp_name)
                raise
        return selected


def write_journal(
    path: Path,
    destination: Path,
    identity: DirectoryIdentity,
    payload: bytes,
) -> None:
    encoded = identity.as_dict()
    path.write_text(
        json.dumps(
            {
                "phase": "PREPARED",
                "destination": str(absolute(destination)),
                "temporary": str(absolute(destination.with_suffix(destination.suffix + ".part"))),
                "directory_identity_at_selection": encoded,
                "directory_identity_at_temporary_creation": encoded,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def reconcile(journal_path: Path) -> Path:
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    destination = absolute(Path(journal["destination"]))
    temporary = absolute(Path(journal["temporary"]))
    expected = DirectoryIdentity.from_dict(journal["directory_identity_at_selection"])
    if DirectoryIdentity.from_dict(
        journal["directory_identity_at_temporary_creation"]
    ) != expected:
        raise ControlError("recorded identities differ")
    with pin_chain(destination.parent, expected=expected) as chain:
        with chain.final.open_file(
            temporary.name,
            create=False,
            mutable=True,
            deletable=True,
        ) as file:
            digest, size = sha256_file(file)
            if digest != journal["sha256"] or size != journal["bytes"]:
                raise ControlError("temporary identity mismatch")
            chain.final.publish(file, temporary.name, destination.name)
        journal["phase"] = "PUBLISHED"
        journal["directory_identity_at_final_publication"] = (
            chain.final.identity.as_dict()
        )
        journal_path.write_text(json.dumps(journal, sort_keys=True), encoding="utf-8")
        return destination


def extract_payload(staged_root: Path, relative: str, payload: bytes) -> Path:
    root = absolute(staged_root)
    with pin_chain(root.parent) as parent_chain:
        root_pin = parent_chain.final.replace_empty_staging_child(root.name)
        with root_pin, ExitStack() as stack:
            parts = Path(*relative.split("/"))
            current = root_pin
            for part in parts.parent.parts:
                current = stack.enter_context(current.child(part, create=True))
            temp_name = f"{parts.name}.part"
            with current.open_file(
                temp_name,
                create=True,
                mutable=True,
                deletable=True,
            ) as file:
                published = False
                try:
                    file.write(payload)
                    file.flush()
                    os.fsync(file.fileno())
                    current.publish(file, temp_name, parts.name)
                    published = True
                except BaseException:
                    if not published:
                        with suppress(Exception):
                            current.delete_without_verify(file, temp_name)
                    raise
            return root / parts
