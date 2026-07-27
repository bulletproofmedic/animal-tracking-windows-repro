from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRECTORIES = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}

FORBIDDEN_SUFFIXES = {
    ".7z",
    ".bak",
    ".bundle",
    ".db",
    ".dump",
    ".gz",
    ".heic",
    ".jpeg",
    ".jpg",
    ".kdbx",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".png",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tif",
    ".tiff",
    ".webp",
    ".zip",
}

FORBIDDEN_FILENAMES = {
    ".env",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
}

FORBIDDEN_FILENAME_TERMS = {
    "backup",
    "orthomosaic",
    "private_export",
    "property_boundary",
    "trail_camera",
}

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub classic token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("OpenAI-style secret", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "private repository clone URL",
        re.compile(r"github\.com[/:]bulletproofmedic/animal-tracking(?:\.git)?\b", re.IGNORECASE),
    ),
)


def iter_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        if path.is_file() or path.is_symlink():
            files.append(path)
    return sorted(files)


def validate(path: Path) -> list[str]:
    relative = path.relative_to(ROOT)
    findings: list[str] = []
    lower_name = path.name.lower()
    lower_relative = relative.as_posix().lower()

    if path.is_symlink():
        return [f"{relative}: symbolic links are not permitted"]

    if lower_name in FORBIDDEN_FILENAMES or lower_name.startswith(".env."):
        findings.append(f"{relative}: forbidden sensitive filename")

    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        findings.append(f"{relative}: forbidden binary/archive/data suffix")

    if any(term in lower_relative for term in FORBIDDEN_FILENAME_TERMS):
        findings.append(f"{relative}: filename indicates private or sensitive project data")

    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        findings.append(f"{relative}: file is {size} bytes; public reproducer limit is {MAX_FILE_BYTES}")
        return findings

    raw = path.read_bytes()
    if b"\x00" in raw:
        findings.append(f"{relative}: binary content is not permitted")
        return findings

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(f"{relative}: content is not valid UTF-8 text")
        return findings

    for label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"{relative}: detected {label}")

    return findings


def main() -> int:
    findings: list[str] = []
    for path in iter_files():
        findings.extend(validate(path))

    if findings:
        print("PUBLIC PAYLOAD CHECK: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    print("PUBLIC PAYLOAD CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
