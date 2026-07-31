from __future__ import annotations

import hashlib
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

_COPY_CHUNK_SIZE = 1024 * 1024
_REPARSE_POINT_FLAG = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class ValidationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PathIdentity:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int
    file_attributes: int


@dataclass(frozen=True, slots=True)
class RegularPathSnapshot:
    path: Path
    root: Path
    directories: tuple[tuple[Path, PathIdentity], ...]
    file_identity: PathIdentity


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def identity(metadata: os.stat_result) -> PathIdentity:
    return PathIdentity(
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        mode=int(metadata.st_mode),
        size=int(metadata.st_size),
        modified_ns=int(metadata.st_mtime_ns),
        changed_ns=int(metadata.st_ctime_ns),
        file_attributes=int(getattr(metadata, "st_file_attributes", 0)),
    )


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_POINT_FLAG
    )


def require_directory(path: Path, metadata: os.stat_result, *, allow_mount: bool) -> None:
    if is_link_or_reparse(metadata):
        raise ValidationError(f"path contains a link or reparse point: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError(f"path contains a non-directory: {path}")
    if not allow_mount and path.is_mount():
        raise ValidationError(f"path crosses a nested mount: {path}")


def require_regular_file(path: Path, metadata: os.stat_result) -> None:
    if is_link_or_reparse(metadata):
        raise ValidationError(f"source is a link or reparse point: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"source is not a regular file: {path}")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise ValidationError(
            f"source has multiple hard links and cannot prove root containment: {path}"
        )


def snapshot_regular_path(path: Path, *, root: Path) -> RegularPathSnapshot:
    absolute_root = lexical_absolute(root)
    absolute_path = lexical_absolute(path)
    try:
        relative = absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise ValidationError(f"source is outside the authorized root: {absolute_path}") from exc
    if not relative.parts:
        raise ValidationError("root cannot itself be archived as a file")

    directories: list[tuple[Path, PathIdentity]] = []
    root_metadata = os.lstat(absolute_root)
    require_directory(absolute_root, root_metadata, allow_mount=True)
    directories.append((absolute_root, identity(root_metadata)))

    current = absolute_root
    for part in relative.parts[:-1]:
        current /= part
        metadata = os.lstat(current)
        require_directory(current, metadata, allow_mount=False)
        directories.append((current, identity(metadata)))

    file_metadata = os.lstat(absolute_path)
    require_regular_file(absolute_path, file_metadata)
    try:
        absolute_path.resolve(strict=True).relative_to(absolute_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"source escapes the authorized root: {absolute_path}") from exc
    return RegularPathSnapshot(
        path=absolute_path,
        root=absolute_root,
        directories=tuple(directories),
        file_identity=identity(file_metadata),
    )


def verify_snapshot(snapshot: RegularPathSnapshot) -> None:
    for index, (directory, expected) in enumerate(snapshot.directories):
        metadata = os.lstat(directory)
        require_directory(directory, metadata, allow_mount=index == 0)
        if identity(metadata) != expected:
            raise ValidationError(f"directory changed during processing: {directory}")
    metadata = os.lstat(snapshot.path)
    require_regular_file(snapshot.path, metadata)
    if identity(metadata) != snapshot.file_identity:
        raise ValidationError(f"source changed during processing: {snapshot.path}")


@contextmanager
def open_regular_source(path: Path, *, root: Path) -> Iterator[tuple[BinaryIO, RegularPathSnapshot]]:
    snapshot = snapshot_regular_path(path, root=root)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(snapshot.path, flags)
        opened = os.fstat(descriptor)
        require_regular_file(snapshot.path, opened)
        if identity(opened) != snapshot.file_identity:
            raise ValidationError(f"source was replaced while opening: {snapshot.path}")
        verify_snapshot(snapshot)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            yield handle, snapshot
        verify_snapshot(snapshot)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def stream_stable_file(source: Path, destination: BinaryIO, *, root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    with open_regular_source(source, root=root) as (handle, snapshot):
        opened_identity = identity(os.fstat(handle.fileno()))
        while chunk := handle.read(_COPY_CHUNK_SIZE):
            destination.write(chunk)
            digest.update(chunk)
            byte_count += len(chunk)
        if identity(os.fstat(handle.fileno())) != opened_identity:
            raise ValidationError(f"source changed while being read: {snapshot.path}")
        verify_snapshot(snapshot)
    return digest.hexdigest(), byte_count


def walk_regular_files(root: Path) -> tuple[Path, ...]:
    absolute_root = lexical_absolute(root)
    root_metadata = os.lstat(absolute_root)
    require_directory(absolute_root, root_metadata, allow_mount=True)
    files: list[Path] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda row: row.name)
        for entry in entries:
            candidate = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if is_link_or_reparse(metadata):
                raise ValidationError(f"member is a link or reparse point: {candidate}")
            if stat.S_ISDIR(metadata.st_mode):
                require_directory(candidate, metadata, allow_mount=False)
                visit(candidate)
            elif stat.S_ISREG(metadata.st_mode):
                require_regular_file(candidate, metadata)
                snapshot_regular_path(candidate, root=absolute_root)
                files.append(candidate)
            else:
                raise ValidationError(f"unsupported member type: {candidate}")

    visit(absolute_root)
    return tuple(sorted(files, key=lambda path: path.as_posix()))
