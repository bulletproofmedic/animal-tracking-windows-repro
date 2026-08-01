from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator


class IdentityMismatch(RuntimeError):
    """Raised when a path no longer names the object that was selected."""


@dataclass(frozen=True)
class FileIdentity:
    """The portable identity fields used by the small Windows harness."""

    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    changed_ns: int
    file_attributes: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> FileIdentity:
        return cls(
            device=int(value.st_dev),
            inode=int(value.st_ino),
            mode=int(value.st_mode),
            size=int(value.st_size),
            mtime_ns=int(value.st_mtime_ns),
            changed_ns=int(getattr(value, "st_ctime_ns", 0)),
            file_attributes=int(getattr(value, "st_file_attributes", 0)),
        )


RETAINED_FIELDS = (
    "device",
    "inode",
    "mode",
    "size",
    "mtime_ns",
    "file_attributes",
)


def snapshot_path(path: Path) -> FileIdentity:
    return FileIdentity.from_stat(os.lstat(path))


def snapshot_handle(handle: BinaryIO) -> FileIdentity:
    return FileIdentity.from_stat(os.fstat(handle.fileno()))


def matches_after_open(
    before: FileIdentity,
    after: FileIdentity,
    *,
    windows: bool | None = None,
) -> bool:
    """Compare lstat-before-open with fstat-after-open.

    Windows can report a different change-time value across this otherwise
    unchanged transition.  Only that field is relaxed, and only here.  The
    caller can pass ``windows`` in tests to make the contract deterministic.
    """

    is_windows = os.name == "nt" if windows is None else windows
    if not is_windows:
        return before == after
    return all(getattr(before, field) == getattr(after, field) for field in RETAINED_FIELDS)


def matches_strictly(expected: FileIdentity, actual: FileIdentity) -> bool:
    """Strict comparison for expected, final, and digest-related checks."""

    return expected == actual


def sha256_bytes(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class _CloseThen:
    """Close a stream before invoking a deterministic replacement callback."""

    def __init__(
        self,
        handle: BinaryIO,
        after_close: Callable[[BinaryIO], None] | None,
    ) -> None:
        self.handle = handle
        self.after_close = after_close

    def __enter__(self) -> BinaryIO:
        return self.handle

    def __exit__(self, *_exc: object) -> bool:
        self.handle.close()
        if self.after_close is not None:
            self.after_close(self.handle)
        return False


@contextmanager
def verified_open(
    path: Path,
    *,
    mode: str = "rb",
    after_close: Callable[[BinaryIO], None] | None = None,
) -> Iterator[BinaryIO]:
    """Open a regular file and verify identity before and after the body.

    ``after_close`` is a test-only hook.  The wrapper closes the underlying
    stream first, then runs the hook, and only then does this context manager's
    post-yield strict identity check.  That gives the Windows replacement test
    a deterministic ordering without relying on a race.
    """

    expected = snapshot_path(path)
    handle = path.open(mode)
    try:
        opened = snapshot_handle(handle)
        if not matches_after_open(expected, opened):
            raise IdentityMismatch("identity changed while opening")
        with _CloseThen(handle, after_close):
            yield handle
        final = snapshot_path(path)
        if not matches_strictly(expected, final):
            raise IdentityMismatch("identity changed after close")
    finally:
        handle.close()
