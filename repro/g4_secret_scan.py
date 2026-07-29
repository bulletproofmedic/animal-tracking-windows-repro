from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

RULES = {
    "service_key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "cloud_key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "jwt": re.compile(
        rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\."
        rb"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
    ),
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    source: str
    digest: str


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    )
    return completed.stdout


def _scan(payload: bytes, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, pattern in RULES.items():
        for match in pattern.finditer(payload):
            findings.append(
                Finding(
                    rule=name,
                    source=source,
                    digest=hashlib.sha256(match.group(0)).hexdigest(),
                )
            )
    return findings


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    current_ids: set[str] = set()
    for raw_path in _git(root, "ls-files", "-z").split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8", errors="surrogateescape")
        path = root / relative
        object_id = _git(root, "hash-object", "--", relative).decode("ascii").strip()
        current_ids.add(object_id)
        findings.extend(_scan(path.read_bytes(), "current_tracked_content"))

    objects: list[str] = []
    for line in _git(root, "rev-list", "--objects", "HEAD").splitlines():
        object_id = line.partition(b" ")[0].decode("ascii")
        if object_id not in objects:
            objects.append(object_id)
    process = subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise RuntimeError("object reader pipes unavailable")
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    try:
        stdin.write(b"".join(value.encode("ascii") + b"\n" for value in objects))
        stdin.close()
        for object_id in objects:
            fields = stdout.readline().rstrip(b"\n").split(b" ")
            if len(fields) != 3:
                raise RuntimeError("invalid object response")
            object_type = fields[1]
            size = int(fields[2])
            payload = stdout.read(size)
            if stdout.read(1) != b"\n":
                raise RuntimeError("incomplete object response")
            if object_type == b"blob" and object_id not in current_ids:
                findings.extend(_scan(payload, "reachable_git_history"))
        if process.wait(timeout=30) != 0:
            raise RuntimeError(stderr.read().decode("utf-8", errors="replace"))
    finally:
        if not stdin.closed:
            stdin.close()
        stdout.close()
        stderr.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    return findings
