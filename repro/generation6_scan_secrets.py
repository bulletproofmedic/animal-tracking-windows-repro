from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_ALLOWLIST_FILENAME = ".secret-scan-allowlist.json"
_SCAN_SCHEMA = "AnimalTrackingSourceSecretScanV3"
_MAX_MATCH_BYTES = 4096


@dataclass(frozen=True, slots=True)
class _Rule:
    name: str
    pattern: re.Pattern[bytes]


@dataclass(frozen=True, slots=True)
class _Finding:
    rule: str
    source: str
    path: str | None
    object_id: str | None
    match_sha256: str
    byte_offset: int

    def as_json(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "source": self.source,
            "path": _privacy_safe_path(self.path),
            "path_sha256": _path_sha256(self.path),
            "object_id": self.object_id,
            "match_sha256": self.match_sha256,
            "byte_offset": self.byte_offset,
        }


_RULES: tuple[_Rule, ...] = (
    _Rule("openai_api_key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    _Rule(
        "github_token",
        re.compile(
            rb"\b(?:"
            rb"gh[pour]_[A-Za-z0-9]{36,}|"
            rb"github_pat_[A-Za-z0-9_]{20,}|"
            rb"ghs_[A-Za-z0-9_.-]{20,}"
            rb")\b"
        ),
    ),
    _Rule("aws_access_key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    _Rule("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    _Rule("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    _Rule(
        "private_key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    _Rule(
        "jwt",
        re.compile(
            rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\."
            rb"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
        ),
    ),
    _Rule(
        "bearer_token",
        re.compile(rb"(?i)\bbearer[ \t]+([A-Za-z0-9._~+/=-]{16,})"),
    ),
    _Rule(
        "credential_assignment",
        re.compile(
            rb"(?ix)\b(?:api[._ -]*key|authorization|credential|password|passwd|"
            rb"private[._ -]*key|secret|session[._ -]*(?:id|token)|token)\b"
            rb"[ \t]*[:=][ \t]*(?:"
            rb"\"([^\"\r\n]{8,4096})\"|"
            rb"'([^'\r\n]{8,4096})'|"
            rb"([A-Za-z0-9._~+/=@#$%^&*:-]{12,4096})"
            rb")"
        ),
    ),
)


def _run_git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Git command failed: {' '.join(arguments)}: {detail}")
    return completed.stdout


def _hash_object(root: Path, payload: bytes) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "hash-object", "--stdin"],
        input=payload,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Git hash-object failed: {detail}")
    return completed.stdout.decode("ascii").strip()


def _git_head(root: Path) -> str:
    return _run_git(root, "rev-parse", "HEAD").decode("ascii").strip()


def _tracked_paths(root: Path) -> tuple[Path, ...]:
    return tuple(
        Path(item.decode("utf-8", errors="surrogateescape"))
        for item in _run_git(root, "ls-files", "-z").split(b"\0")
        if item
    )


def _history_objects(root: Path) -> tuple[tuple[str, str | None], ...]:
    """Preserve every reachable blob/path occurrence for path-scoped policy."""

    objects: list[tuple[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    commits = [
        item.decode("ascii")
        for item in _run_git(root, "rev-list", "HEAD").splitlines()
        if item
    ]
    for commit in commits:
        tree = _run_git(root, "ls-tree", "-r", "-z", commit)
        for raw_entry in tree.split(b"\0"):
            if not raw_entry:
                continue
            metadata, separator, path_raw = raw_entry.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3 or fields[1] != b"blob":
                continue
            oid = fields[2].decode("ascii")
            path = path_raw.decode("utf-8", errors="surrogateescape")
            identity = (oid, path)
            if identity in seen:
                continue
            seen.add(identity)
            objects.append(identity)
    return tuple(objects)


def _batch_blobs(
    root: Path,
    objects: tuple[tuple[str, str | None], ...],
) -> Iterable[tuple[str, str | None, bytes]]:
    process = subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise RuntimeError("Could not open the Git object-reader pipes.")
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    try:
        stdin.write(b"".join(oid.encode("ascii") + b"\n" for oid, _ in objects))
        stdin.close()
        for oid, path in objects:
            header = stdout.readline()
            fields = header.rstrip(b"\n").split(b" ")
            if len(fields) == 2 and fields[1] == b"missing":
                raise RuntimeError(f"Git object is missing: {oid}")
            if len(fields) != 3:
                raise RuntimeError(f"Unexpected git cat-file header for {oid}.")
            object_type = fields[1]
            size = int(fields[2])
            payload = stdout.read(size)
            terminator = stdout.read(1)
            if len(payload) != size or terminator != b"\n":
                raise RuntimeError(f"Incomplete Git object response for {oid}.")
            if object_type == b"blob":
                yield oid, path, payload
        return_code = process.wait(timeout=30)
        if return_code != 0:
            detail = stderr.read().decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"git cat-file failed: {detail}")
    finally:
        if not stdin.closed:
            stdin.close()
        stdout.close()
        stderr.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def _load_allowlist(root: Path) -> tuple[dict[str, str], ...]:
    path = root / _ALLOWLIST_FILENAME
    if not path.exists():
        return ()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("The secret-scan allowlist is unreadable or invalid.") from error
    if not isinstance(payload, dict) or payload.get("schema") != "AnimalTrackingSecretScanAllowlistV1":
        raise RuntimeError("The secret-scan allowlist schema is invalid.")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise RuntimeError("The secret-scan allowlist entries must be a list.")
    normalized: list[dict[str, str]] = []
    allowed_fields = {"rule", "match_sha256", "justification", "path", "object_id"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - allowed_fields:
            raise RuntimeError("Every secret-scan allowlist entry must use only supported fields.")
        required = ("rule", "match_sha256", "justification")
        if any(not isinstance(entry.get(field), str) or not entry[field] for field in required):
            raise RuntimeError("Every allowlist entry requires rule, match_sha256 and justification.")
        for optional in ("path", "object_id"):
            if optional in entry and (
                not isinstance(entry[optional], str) or not entry[optional]
            ):
                raise RuntimeError(f"Allowlist field {optional} must be non-empty text.")
        digest = entry["match_sha256"]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise RuntimeError("An allowlist match_sha256 value is invalid.")
        normalized.append({str(key): str(value) for key, value in entry.items()})
    return tuple(normalized)


def _is_allowlisted(finding: _Finding, allowlist: tuple[dict[str, str], ...]) -> bool:
    for entry in allowlist:
        if entry["rule"] != finding.rule or entry["match_sha256"] != finding.match_sha256:
            continue
        if "path" in entry and entry["path"] != (finding.path or ""):
            continue
        if "object_id" in entry and entry["object_id"] != (finding.object_id or ""):
            continue
        return True
    return False


def _captured_match(match: re.Match[bytes]) -> bytes:
    if match.lastindex:
        for index in range(1, match.lastindex + 1):
            captured = match.group(index)
            if captured is not None:
                return captured
    return match.group(0)


def _scan_bytes(
    payload: bytes,
    *,
    source: str,
    path: str | None,
    object_id: str | None,
) -> Iterable[_Finding]:
    for rule in _RULES:
        for match in rule.pattern.finditer(payload):
            matched = _captured_match(match)
            if not matched or len(matched) > _MAX_MATCH_BYTES:
                continue
            yield _Finding(
                rule=rule.name,
                source=source,
                path=path,
                object_id=object_id,
                match_sha256=hashlib.sha256(matched).hexdigest(),
                byte_offset=match.start(),
            )


def _path_bytes(path: str) -> bytes:
    return path.encode("utf-8", errors="surrogateescape")


def _path_sha256(path: str | None) -> str | None:
    if path is None:
        return None
    return hashlib.sha256(_path_bytes(path)).hexdigest()


def _path_contains_secret(path: str) -> bool:
    return any(
        True
        for _ in _scan_bytes(
            _path_bytes(path),
            source="path_privacy_check",
            path=None,
            object_id=None,
        )
    )


def _privacy_safe_path(path: str | None) -> str | None:
    if path is None:
        return None
    return "<path-redacted>" if _path_contains_secret(path) else path


def _collect(
    iterable: Iterable[_Finding],
    allowlist: tuple[dict[str, str], ...],
    findings: list[_Finding],
    allowlisted: list[_Finding],
) -> None:
    for finding in iterable:
        (allowlisted if _is_allowlisted(finding, allowlist) else findings).append(finding)


def scan_repository(root: Path) -> dict[str, object]:
    resolved = root.expanduser().resolve()
    head = _git_head(resolved)
    allowlist = _load_allowlist(resolved)
    findings: list[_Finding] = []
    allowlisted: list[_Finding] = []

    tracked_paths = _tracked_paths(resolved)
    current_blob_locations: set[tuple[str, str]] = set()
    for relative in tracked_paths:
        relative_text = relative.as_posix()
        path = resolved / relative
        if not path.is_file():
            reference = _path_sha256(relative_text)
            raise RuntimeError(f"Tracked path is not a regular file (path_sha256={reference}).")
        payload = path.read_bytes()
        blob_id = _hash_object(resolved, payload)
        current_blob_locations.add((blob_id, relative_text))
        _collect(
            _scan_bytes(
                _path_bytes(relative_text),
                source="current_tracked_path",
                path=relative_text,
                object_id=blob_id,
            ),
            allowlist,
            findings,
            allowlisted,
        )
        _collect(
            _scan_bytes(
                payload,
                source="current_tracked_content",
                path=relative_text,
                object_id=blob_id,
            ),
            allowlist,
            findings,
            allowlisted,
        )

    history_blob_count = 0
    history_blob_path_count = 0
    for oid, historical_path, payload in _batch_blobs(resolved, _history_objects(resolved)):
        history_blob_path_count += 1
        if historical_path is None:
            continue
        if (oid, historical_path) in current_blob_locations:
            continue
        history_blob_count += 1
        _collect(
            _scan_bytes(
                _path_bytes(historical_path),
                source="reachable_git_history_path",
                path=historical_path,
                object_id=oid,
            ),
            allowlist,
            findings,
            allowlisted,
        )
        _collect(
            _scan_bytes(
                payload,
                source="reachable_git_history",
                path=historical_path,
                object_id=oid,
            ),
            allowlist,
            findings,
            allowlisted,
        )

    deduplicated = {
        (
            finding.rule,
            finding.source,
            finding.path,
            finding.object_id,
            finding.match_sha256,
            finding.byte_offset,
        ): finding
        for finding in findings
    }
    return {
        "schema": _SCAN_SCHEMA,
        "repository_root": ".",
        "head": head,
        "rules": [rule.name for rule in _RULES],
        "current_tracked_file_count": len(tracked_paths),
        "reachable_history_blob_count": history_blob_count,
        "reachable_history_blob_path_count": history_blob_path_count,
        "allowlist_file": _ALLOWLIST_FILENAME if (resolved / _ALLOWLIST_FILENAME).exists() else None,
        "allowlisted_match_count": len(allowlisted),
        "finding_count": len(deduplicated),
        "findings": [finding.as_json() for finding in deduplicated.values()],
        "result": "FAIL" if deduplicated else "PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan current tracked bytes, paths and reachable Git history for credentials."
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    result = scan_repository(arguments.root)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if result["finding_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
