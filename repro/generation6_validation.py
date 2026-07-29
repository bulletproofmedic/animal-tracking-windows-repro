from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCANNER_PATH = ROOT / "generation6_scan_secrets.py"
ACKNOWLEDGEMENT_TAIL_BYTES = 128 * 1024
MARKER_SCHEMA = "PublicGeneration6FailedActivationCleanupV1"
MARKER_MAX_BYTES = 4096


def load_scanner():
    spec = importlib.util.spec_from_file_location("generation6_scan_secrets", SCANNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the staged scanner.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def bounded_tail_lines(path: Path) -> tuple[bytes, ...]:
    if path.is_symlink() or not path.is_file():
        return ()
    with path.open("rb") as source:
        size = source.seek(0, os.SEEK_END)
        start = max(0, size - ACKNOWLEDGEMENT_TAIL_BYTES)
        source.seek(start)
        payload = source.read(ACKNOWLEDGEMENT_TAIL_BYTES)
    if start:
        separator = payload.find(b"\n")
        if separator < 0:
            return ()
        payload = payload[separator + 1 :]
    return tuple(payload.splitlines())


@dataclass(frozen=True, slots=True)
class Result:
    path: Path
    sha256: str
    byte_count: int


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_result_is_current(result: Result) -> bool:
    try:
        metadata = result.path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not result.path.is_symlink()
        and metadata.st_size == result.byte_count
        and file_sha256(result.path) == result.sha256
    )


def marker_path(destination: Path) -> Path:
    return destination.with_name(f".{destination.name}.failed-activation.json")


def marker_payload(result: Result) -> dict[str, object]:
    return {
        "schema": MARKER_SCHEMA,
        "destination_name": result.path.name,
        "sha256": result.sha256,
        "byte_count": result.byte_count,
    }


def write_marker(result: Result) -> None:
    marker = marker_path(result.path)
    raw = (
        json.dumps(marker_payload(result), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(raw) > MARKER_MAX_BYTES:
        raise RuntimeError("Marker exceeded its bounded size.")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(marker, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def cleanup_failed_activation(result: Result) -> None:
    if not exact_result_is_current(result):
        write_marker(result)
        raise RuntimeError("Exact activated archive identity changed.")
    result.path.unlink()


def recover_failed_activation(destination: Path) -> None:
    marker = marker_path(destination)
    if not marker.exists():
        return
    payload = json.loads(marker.read_text(encoding="utf-8"))
    result = Result(
        path=destination,
        sha256=str(payload["sha256"]),
        byte_count=int(payload["byte_count"]),
    )
    if destination.exists():
        if not exact_result_is_current(result):
            raise RuntimeError("Recovery refused a non-matching archive.")
        destination.unlink()
    marker.unlink()


def git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def initialize_repository(repository: Path) -> None:
    repository.mkdir()
    git(repository, "init")
    git(repository, "config", "user.email", "public-repro@example.invalid")
    git(repository, "config", "user.name", "Public Reproducer")
    (repository / "README.md").write_text("clean\n", encoding="utf-8")
    git(repository, "add", "README.md")
    git(repository, "commit", "-m", "Initial clean commit")


class Generation6Validation(unittest.TestCase):
    def test_exact_acknowledgement_rejects_same_id_mutation_and_bounds_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "security.log"
            record_id = "a" * 32
            expected = json.dumps(
                {
                    "event_code": "SEC_INTEGRITY_FAILED",
                    "fields": {"operation": "INTEGRITY", "outcome": "FAILED"},
                    "record_id": record_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            mutated = json.dumps(
                {
                    "event_code": "SEC_HOST_REJECTED",
                    "fields": {"operation": "HOST_VALIDATION", "outcome": "REJECTED"},
                    "record_id": record_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            filler = b'{"event_code":"FILLER"}\n' * (ACKNOWLEDGEMENT_TAIL_BYTES // 12)
            path.write_bytes(expected + b"\n" + filler + mutated + b"\n")
            lines = bounded_tail_lines(path)
            self.assertNotIn(expected, lines)
            self.assertIn(mutated, lines)
            self.assertNotEqual(expected, mutated)
            self.assertLessEqual(sum(len(line) + 1 for line in lines), ACKNOWLEDGEMENT_TAIL_BYTES)

    def test_scanner_detects_current_token_formats_without_output_disclosure(self) -> None:
        scanner = load_scanner()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            initialize_repository(repository)
            fine_grained = ("github" + "_pat_") + ("A" * 50)
            stateless = ("g" + "hs_12345_") + ("B" * 24) + "." + ("C" * 12) + "." + ("D" * 12)
            (repository / "one.txt").write_text(fine_grained, encoding="utf-8")
            (repository / "two.txt").write_text(stateless, encoding="utf-8")
            git(repository, "add", "one.txt", "two.txt")
            payload = scanner.scan_repository(repository)
            rendered = json.dumps(payload, sort_keys=True)
            github_findings = [
                finding
                for finding in payload["findings"]
                if finding["rule"] == "github_token"
            ]
            self.assertEqual(len(github_findings), 2)
            self.assertGreaterEqual(payload["finding_count"], 2)
            self.assertNotIn(fine_grained, rendered)
            self.assertNotIn(stateless, rendered)

    def test_scanner_redacts_secret_path_and_preserves_history_path_scope(self) -> None:
        scanner = load_scanner()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            initialize_repository(repository)
            path_secret = ("github" + "_pat_") + ("P" * 50)
            secret_path = repository / f"{path_secret}.txt"
            secret_path.write_text("clean\n", encoding="utf-8")
            git(repository, "add", secret_path.name)
            payload = scanner.scan_repository(repository)
            rendered = json.dumps(payload, sort_keys=True)
            self.assertTrue(
                any(
                    finding["source"] == "current_tracked_path"
                    and finding["path"] == "<path-redacted>"
                    for finding in payload["findings"]
                )
            )
            self.assertNotIn(path_secret, rendered)

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            initialize_repository(repository)
            token = ("A" + "KIA") + ("R" * 16)
            digest = hashlib.sha256(token.encode()).hexdigest()
            (repository / "allowed.txt").write_text(token, encoding="utf-8")
            (repository / "unapproved.txt").write_text(token, encoding="utf-8")
            git(repository, "add", "allowed.txt", "unapproved.txt")
            git(repository, "commit", "-m", "Add same blob at two paths")
            (repository / "allowed.txt").unlink()
            (repository / "unapproved.txt").unlink()
            git(repository, "add", "-u")
            git(repository, "commit", "-m", "Remove fixtures")
            (repository / ".secret-scan-allowlist.json").write_text(
                json.dumps(
                    {
                        "schema": "AnimalTrackingSecretScanAllowlistV1",
                        "entries": [
                            {
                                "rule": "aws_access_key",
                                "match_sha256": digest,
                                "path": "allowed.txt",
                                "justification": "Synthetic one-path allowance",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            git(repository, "add", ".secret-scan-allowlist.json")
            payload = scanner.scan_repository(repository)
            self.assertEqual(payload["allowlisted_match_count"], 1)
            self.assertTrue(
                any(
                    finding["source"] == "reachable_git_history"
                    and finding["path"] == "unapproved.txt"
                    for finding in payload["findings"]
                )
            )

    def test_failed_activation_cleanup_and_retry_are_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bundle.zip"
            content = b"synthetic archive"
            destination.write_bytes(content)
            result = Result(destination, hashlib.sha256(content).hexdigest(), len(content))
            cleanup_failed_activation(result)
            self.assertFalse(destination.exists())
            self.assertFalse(marker_path(destination).exists())

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bundle.zip"
            original = b"synthetic archive"
            destination.write_bytes(original)
            result = Result(destination, hashlib.sha256(original).hexdigest(), len(original))
            destination.write_bytes(b"unrelated replacement")
            with self.assertRaises(RuntimeError):
                cleanup_failed_activation(result)
            self.assertEqual(destination.read_bytes(), b"unrelated replacement")
            self.assertTrue(marker_path(destination).is_file())
            with self.assertRaises(RuntimeError):
                recover_failed_activation(destination)
            self.assertEqual(destination.read_bytes(), b"unrelated replacement")

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bundle.zip"
            content = b"retry archive"
            destination.write_bytes(content)
            result = Result(destination, hashlib.sha256(content).hexdigest(), len(content))
            write_marker(result)
            recover_failed_activation(destination)
            self.assertFalse(destination.exists())
            self.assertFalse(marker_path(destination).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
