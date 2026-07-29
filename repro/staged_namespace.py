from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Callable


def _digest(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _is_reparse_or_link(path: Path) -> bool:
    metadata = os.lstat(path)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def expected_namespace(members: list[str]) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for member in members:
        candidate = PurePosixPath(member)
        if candidate.is_absolute() or not candidate.parts:
            raise ValueError("invalid staged member")
        if any(part in {"", ".", ".."} for part in candidate.parts):
            raise ValueError("invalid staged member")
        if "\\" in member or candidate.as_posix() in files:
            raise ValueError("invalid or duplicated staged member")
        normalized = candidate.as_posix()
        files.add(normalized)
        parent = candidate.parent
        while parent.parts:
            directories.add(parent.as_posix())
            parent = parent.parent
    return files, directories


def actual_namespace(root: Path) -> tuple[set[str], set[str], dict[str, tuple[str, int]]]:
    if _is_reparse_or_link(root):
        raise ValueError("staged root is a link or reparse point")
    if not root.is_dir():
        raise ValueError("staged root missing")
    files: set[str] = set()
    directories: set[str] = set()
    identities: dict[str, tuple[str, int]] = {}
    resolved_root = root.resolve()
    stack = [root]
    while stack:
        directory = stack.pop()
        for entry in sorted(os.scandir(directory), key=lambda row: row.name):
            path = Path(entry.path)
            if _is_reparse_or_link(path):
                raise ValueError("link, junction, or reparse node")
            resolved = path.resolve()
            resolved.relative_to(resolved_root)
            relative = path.relative_to(root).as_posix()
            if entry.is_dir(follow_symlinks=False):
                directories.add(relative)
                stack.append(path)
            elif entry.is_file(follow_symlinks=False):
                files.add(relative)
                identities[relative] = _digest(path)
            else:
                raise ValueError("unsupported node")
    return files, directories, identities


def verify_exact_namespace(root: Path, members: list[str], verify_bytes: Callable[[], None]) -> None:
    expected_files, expected_directories = expected_namespace(members)
    before_files, before_directories, before_identities = actual_namespace(root)
    if before_files != expected_files:
        raise ValueError("file namespace is not exact")
    if before_directories != expected_directories:
        raise ValueError("directory namespace is not exact")
    verify_bytes()
    after_files, after_directories, after_identities = actual_namespace(root)
    if after_files != before_files or after_directories != before_directories or after_identities != before_identities:
        raise ValueError("staged namespace changed during verification")
