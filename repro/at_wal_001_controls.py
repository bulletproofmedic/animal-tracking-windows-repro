from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO


class LockUnavailable(RuntimeError):
    """Raised when another process owns the external startup lock."""


class ExternalFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: BinaryIO | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise LockUnavailable("another process owns the lock") from exc
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise LockUnavailable("another process owns the lock") from exc
            self._handle = handle
        except Exception:
            handle.close()
            raise

    def release(self) -> None:
        if self._handle is None:
            return
        handle = self._handle
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            self._handle = None

    def __enter__(self) -> ExternalFileLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_or_create_secret(data_root: Path) -> str:
    secret_path = data_root / "config" / "service.secret"
    if secret_path.exists():
        return secret_path.read_text(encoding="ascii").strip()
    secret = secrets.token_urlsafe(48)
    _atomic_write(secret_path, secret + "\n")
    return secret


@dataclass(slots=True)
class IntervalRecord:
    interval_type: str
    deployment_id: str
    start: int
    end: int | None
    status: str = "FINAL"
    is_current: bool = True


def replace_interval(
    predecessor: IntervalRecord,
    *,
    interval_type: str,
    deployment_id: str,
    start: int,
    end: int | None,
    overlap_rejected: bool = False,
) -> IntervalRecord:
    if end is not None and end < start:
        raise ValueError("interval end precedes start")
    if predecessor.interval_type != interval_type:
        raise ValueError("predecessor type mismatch")
    if predecessor.deployment_id != deployment_id:
        raise ValueError("predecessor deployment mismatch")
    if predecessor.status != "FINAL" or not predecessor.is_current:
        raise ValueError("predecessor is not the current FINAL interval")

    prior_status = predecessor.status
    prior_current = predecessor.is_current
    predecessor.status = "SUPERSEDED"
    predecessor.is_current = False
    try:
        if overlap_rejected:
            raise ValueError("successor overlaps another FINAL interval")
        return IntervalRecord(interval_type, deployment_id, start, end)
    except Exception:
        predecessor.status = prior_status
        predecessor.is_current = prior_current
        raise


@dataclass(slots=True)
class ReviewRecord:
    property_id: str
    species_code: str
    observation_status: str
    event_status: str


def assign_reviewed_species(
    record: ReviewRecord,
    *,
    property_id: str,
    resolved_species_code: str,
) -> tuple[dict[str, str], dict[str, str]]:
    if record.property_id != property_id:
        raise ValueError("property mismatch")
    if record.species_code != "UNKNOWN" or record.observation_status != "NEEDS_REVIEW":
        raise ValueError("observation is outside the review-resolution workflow")
    if record.event_status in {"VOID", "DUPLICATE"}:
        raise ValueError("inactive event cannot be resolved")
    if resolved_species_code == "UNKNOWN":
        raise ValueError("resolved species must not be UNKNOWN")

    before = {
        "species_code": record.species_code,
        "observation_status": record.observation_status,
        "event_status": record.event_status,
    }
    record.species_code = resolved_species_code
    record.observation_status = "ACCEPTED"
    record.event_status = "ACCEPTED"
    after = {
        "species_code": record.species_code,
        "observation_status": record.observation_status,
        "event_status": record.event_status,
    }
    return before, after


def _run_git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_bytes,
        capture_output=True,
        check=True,
    )
    return completed.stdout


def committed_blob(repo: Path, relative_path: str) -> bytes:
    return _run_git(repo, "show", f"HEAD:{relative_path}")


def validate_manifest_rows(repo: Path, rows: list[dict[str, object]]) -> list[str]:
    failures: list[str] = []
    for row in rows:
        path = str(row["path"])
        try:
            raw = committed_blob(repo, path)
        except subprocess.CalledProcessError:
            failures.append(f"{path}: missing committed blob")
            continue
        actual_size = len(raw)
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_size != int(row["size"]):
            failures.append(f"{path}: size mismatch")
        if actual_hash != str(row["sha256"]):
            failures.append(f"{path}: hash mismatch")
    return failures


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    mode: str
    object_type: str
    object_id: str
    byte_count: int | None
    sha256: str | None
    classification: str


def enumerate_commit_tree(repo: Path) -> list[TreeEntry]:
    raw = _run_git(repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    entries: list[TreeEntry] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path_bytes = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        path = path_bytes.decode("utf-8")
        byte_count: int | None = None
        digest: str | None = None
        if object_type == "blob":
            content = _run_git(repo, "cat-file", "blob", object_id)
            byte_count = len(content)
            digest = hashlib.sha256(content).hexdigest()
        if mode == "120000":
            classification = "SYMLINK"
        elif mode == "160000" or object_type == "commit":
            classification = "SUBMODULE"
        elif mode == "100755":
            classification = "EXECUTABLE"
        elif object_type == "blob" and content.startswith(
            b"version https://git-lfs.github.com/spec/v1\n"
        ):
            classification = "LFS_POINTER"
        else:
            classification = "REGULAR"
        entries.append(
            TreeEntry(path, mode, object_type, object_id, byte_count, digest, classification)
        )
    return entries


def worktree_status(repo: Path) -> list[str]:
    return _run_git(repo, "status", "--porcelain=v1", "-z").decode("utf-8").split("\0")[:-1]


def _write_json(path: Path, payload: dict[str, object]) -> None:
    _atomic_write(path, json.dumps(payload, sort_keys=True) + "\n")


def _owner_worker(args: argparse.Namespace) -> int:
    with ExternalFileLock(args.lock):
        _write_json(args.ready, {"status": "LOCKED"})
        deadline = time.monotonic() + 30
        while not args.release.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("owner release signal was not received")
            time.sleep(0.05)
        secret = load_or_create_secret(args.data_root)
        _write_json(args.result, {"status": "OWNER", "secret": secret})
    return 0


def _contender_worker(args: argparse.Namespace) -> int:
    try:
        with ExternalFileLock(args.lock):
            marker = args.data_root / "contender-created.txt"
            _atomic_write(marker, "unexpected\n")
            _write_json(args.result, {"status": "UNEXPECTED_LOCK"})
            return 2
    except LockUnavailable:
        _write_json(args.result, {"status": "BLOCKED"})
        return 0


def _restart_worker(args: argparse.Namespace) -> int:
    with ExternalFileLock(args.lock):
        secret = load_or_create_secret(args.data_root)
        _write_json(args.result, {"status": "RESTART", "secret": secret})
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("owner", "contender", "restart"))
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--release", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.mode == "owner":
        if args.ready is None or args.release is None:
            raise ValueError("owner mode requires ready and release paths")
        return _owner_worker(args)
    if args.mode == "contender":
        return _contender_worker(args)
    return _restart_worker(args)


if __name__ == "__main__":
    sys.exit(main())
