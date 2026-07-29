from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable


@dataclass(frozen=True)
class Record:
    path: str
    sha256: str
    byte_count: int


def digest(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def is_reparse_or_link(path: Path) -> bool:
    metadata = os.lstat(path)
    attrs = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attrs & reparse)


def walk_regular(root: Path, maps_root: Path) -> dict[str, Path]:
    if is_reparse_or_link(root) or is_reparse_or_link(maps_root):
        raise ValueError("link or reparse root")
    files: dict[str, Path] = {}
    stack = [root]
    while stack:
        directory = stack.pop()
        for entry in sorted(os.scandir(directory), key=lambda row: row.name):
            path = Path(entry.path)
            if is_reparse_or_link(path):
                raise ValueError("link, junction, or reparse node")
            if entry.is_dir(follow_symlinks=False):
                stack.append(path)
            elif entry.is_file(follow_symlinks=False):
                resolved = path.resolve()
                resolved.relative_to(root.resolve())
                resolved.relative_to(maps_root.resolve())
                files[path.relative_to(root).as_posix()] = path
            else:
                raise ValueError("unsupported node")
    return files


def manifest_records(manifest: Path) -> dict[str, Record]:
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    records: dict[str, Record] = {}
    manifest_sha, manifest_bytes = digest(manifest)
    records[manifest.name] = Record(manifest.name, manifest_sha, manifest_bytes)
    for item in raw["tiles"]:
        candidate = PurePosixPath(item["path"])
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            raise ValueError("unsafe path")
        relative = candidate.as_posix()
        if relative in records:
            raise ValueError("duplicate path")
        records[relative] = Record(relative, item["sha256"], item["byte_count"])
    return records


def snapshot(manifest: Path, maps_root: Path, expected_total: int) -> dict[str, Record]:
    records = manifest_records(manifest)
    files = walk_regular(manifest.parent, maps_root)
    if set(files) != set(records):
        raise ValueError("exact closure mismatch")
    total = 0
    for relative, record in records.items():
        actual = digest(files[relative])
        if actual != (record.sha256, record.byte_count):
            raise ValueError("digest closure mismatch")
        total += actual[1]
    if total != expected_total:
        raise ValueError("total mismatch")
    return records


def freeze(
    manifest: Path,
    maps_root: Path,
    destination: Path,
    expected_total: int,
    mutate_after_copy: Callable[[], None] | None = None,
) -> None:
    before = snapshot(manifest, maps_root, expected_total)
    for relative in sorted(before):
        source = manifest.parent / Path(*relative.split("/"))
        target = destination / Path(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if digest(target) != (before[relative].sha256, before[relative].byte_count):
            raise ValueError("copy mismatch")
    if mutate_after_copy is not None:
        mutate_after_copy()
    after = snapshot(manifest, maps_root, expected_total)
    if after != before:
        raise ValueError("source changed while freezing")
