from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRECTORIES = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}

FORBIDDEN_SUFFIXES = {
    ".7z",
    ".bak",
    ".bundle",
    ".bz2",
    ".cab",
    ".db",
    ".diff",
    ".dll",
    ".dmp",
    ".dump",
    ".exe",
    ".gif",
    ".gz",
    ".heic",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".kdbx",
    ".key",
    ".log",
    ".lz",
    ".lz4",
    ".mbox",
    ".msi",
    ".msix",
    ".nupkg",
    ".p12",
    ".patch",
    ".pdf",
    ".pem",
    ".pfx",
    ".png",
    ".pyc",
    ".rar",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".tif",
    ".tiff",
    ".webp",
    ".whl",
    ".xz",
    ".zip",
    ".zst",
}

FORBIDDEN_FILENAMES = {
    ".env",
    ".gitmodules",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
}

FORBIDDEN_FILENAME_TERMS = {
    "backup",
    "orthomosaic",
    "private_export",
    "property_boundary",
    "recovery_archive",
    "source_archive",
    "trail_camera",
}

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub classic token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("OpenAI-style secret", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "private repository URL",
        re.compile(
            r"(?:(?:https?|ssh)://)?(?:git@)?(?:api\.)?github\.com[/:]"
            r"(?:repos/)?bulletproofmedic/animal-tracking(?:\.git)?"
            r"(?=$|[/?#\s'\"<>])",
            re.IGNORECASE,
        ),
    ),
    (
        "private raw repository URL",
        re.compile(
            r"raw\.githubusercontent\.com/bulletproofmedic/animal-tracking"
            r"(?=$|[/?#\s'\"<>])",
            re.IGNORECASE,
        ),
    ),
    (
        "cloud storage account key",
        re.compile(
            r"DefaultEndpointsProtocol=https;AccountName=[^;\s]+;"
            r"AccountKey=[A-Za-z0-9+/=]{20,}",
            re.IGNORECASE,
        ),
    ),
)

BINARY_SIGNATURES: tuple[tuple[str, tuple[bytes, ...]], ...] = (
    ("7-Zip archive", (b"7z\xbc\xaf'\x1c",)),
    ("bzip2 archive", (b"BZh",)),
    ("ELF executable", (b"\x7fELF",)),
    ("GIF image", (b"GIF87a", b"GIF89a")),
    ("gzip archive", (b"\x1f\x8b",)),
    ("JPEG image", (b"\xff\xd8\xff",)),
    ("OLE compound document", (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)),
    ("PDF document", (b"%PDF-",)),
    ("PNG image", (b"\x89PNG\r\n\x1a\n",)),
    ("RAR archive", (b"Rar!\x1a\x07",)),
    ("SQLite database", (b"SQLite format 3\x00",)),
    ("Windows executable", (b"MZ",)),
    ("XZ archive", (b"\xfd7zXZ\x00",)),
    ("ZIP-compatible archive", (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ("Zstandard archive", (b"\x28\xb5\x2f\xfd",)),
)

BASE64_LINE = re.compile(r"[A-Za-z0-9+/]{256,}={0,2}")
BASE64_WRAPPED_LINE = re.compile(r"[A-Za-z0-9+/]{60,120}={0,2}")
HEX_BLOB = re.compile(r"[0-9A-Fa-f]{1024,}")


def normalize_relative_name(relative: str) -> tuple[str, str, str]:
    portable = relative.replace("\\", "/")
    pure = PurePosixPath(portable)
    lower_name = pure.name.lower()
    lower_relative = portable.lower()
    normalized_relative = re.sub(r"[^a-z0-9]+", "_", lower_relative).strip("_")
    return lower_name, pure.suffix.lower(), normalized_relative


def path_findings(relative: str) -> list[str]:
    lower_name, suffix, normalized_relative = normalize_relative_name(relative)
    findings: list[str] = []

    if lower_name in FORBIDDEN_FILENAMES or lower_name.startswith(".env."):
        findings.append(f"{relative}: forbidden sensitive filename")

    if suffix in FORBIDDEN_SUFFIXES:
        findings.append(f"{relative}: forbidden binary/archive/data suffix")

    if any(term in normalized_relative for term in FORBIDDEN_FILENAME_TERMS):
        findings.append(f"{relative}: filename indicates private or sensitive project data")

    return findings


def detect_encoded_payload(text: str) -> str | None:
    wrapped_total = 0
    for line in text.splitlines():
        candidate = line.strip().strip("'\"")
        if BASE64_LINE.fullmatch(candidate):
            return "long base64 payload"
        if HEX_BLOB.fullmatch(candidate):
            return "long hexadecimal payload"
        if BASE64_WRAPPED_LINE.fullmatch(candidate):
            wrapped_total += len(candidate)
            if wrapped_total >= 1024:
                return "wrapped base64 payload"
        else:
            wrapped_total = 0
    return None


def content_findings(label: str, raw: bytes) -> list[str]:
    findings: list[str] = []
    size = len(raw)

    if size > MAX_FILE_BYTES:
        return [f"{label}: file is {size} bytes; public reproducer limit is {MAX_FILE_BYTES}"]

    for signature_name, signatures in BINARY_SIGNATURES:
        if any(raw.startswith(signature) for signature in signatures):
            findings.append(f"{label}: detected {signature_name}")
            return findings

    if b"\x00" in raw:
        findings.append(f"{label}: binary content is not permitted")
        return findings

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(f"{label}: content is not valid UTF-8 text")
        return findings

    if text.startswith("version https://git-lfs.github.com/spec/v1\n"):
        findings.append(f"{label}: Git LFS pointer is not permitted")

    encoded_payload = detect_encoded_payload(text)
    if encoded_payload is not None:
        findings.append(f"{label}: detected {encoded_payload}")

    for pattern_label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"{label}: detected {pattern_label}")

    return findings


def validate_named_bytes(relative: str, raw: bytes) -> list[str]:
    return path_findings(relative) + content_findings(relative, raw)


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        relative_parts = path.relative_to(root).parts
        if any(part.lower() in SKIP_DIRECTORIES for part in relative_parts):
            continue
        if path.is_file() or path.is_symlink():
            files.append(path)
    return sorted(files)


def scan_working_tree(root: Path) -> list[str]:
    findings: list[str] = []
    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append(f"{relative}: symbolic links are not permitted")
            continue
        findings.extend(validate_named_bytes(relative, path.read_bytes()))
    return findings


def run_git(root: Path, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    )


def history_blob_index(root: Path) -> tuple[dict[str, set[str]], dict[str, int]]:
    objects = run_git(root, "rev-list", "--objects", "--all").stdout.splitlines()
    paths_by_sha: dict[str, set[str]] = {}
    ordered_shas: list[str] = []

    for line in objects:
        sha, separator, relative = line.partition(" ")
        if sha not in paths_by_sha:
            paths_by_sha[sha] = set()
            ordered_shas.append(sha)
        if separator and relative:
            paths_by_sha[sha].add(relative)

    if not ordered_shas:
        return {}, {}

    metadata_text = run_git(
        root,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_text="\n".join(ordered_shas) + "\n",
    ).stdout

    blob_sizes: dict[str, int] = {}
    for line in metadata_text.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] == "blob":
            blob_sizes[fields[0]] = int(fields[2])

    return paths_by_sha, blob_sizes


def iter_git_blobs(
    root: Path, blob_sizes: dict[str, int]
) -> Iterator[tuple[str, bytes]]:
    eligible = {sha: size for sha, size in blob_sizes.items() if size <= MAX_FILE_BYTES}
    if not eligible:
        return

    process = subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    try:
        for sha, expected_size in eligible.items():
            process.stdin.write(f"{sha}\n".encode("ascii"))
            process.stdin.flush()

            header = process.stdout.readline().decode("ascii", errors="replace").rstrip("\n")
            fields = header.split()
            if len(fields) != 3 or fields[0] != sha or fields[1] != "blob":
                raise RuntimeError(f"Unexpected git cat-file header: {header!r}")

            actual_size = int(fields[2])
            if actual_size != expected_size:
                raise RuntimeError(
                    f"Git blob size changed for {sha}: expected {expected_size}, got {actual_size}"
                )

            raw = process.stdout.read(actual_size)
            terminator = process.stdout.read(1)
            if len(raw) != actual_size or terminator != b"\n":
                raise RuntimeError(f"Incomplete git blob read for {sha}")
            yield sha, raw
    finally:
        process.stdin.close()
        return_code = process.wait()
        error = process.stderr.read().decode("utf-8", errors="replace")
        process.stdout.close()
        process.stderr.close()
        if return_code != 0:
            raise RuntimeError(f"git cat-file failed: {error.strip()}")


def scan_git_history(root: Path) -> list[str]:
    try:
        inside = run_git(root, "rev-parse", "--is-inside-work-tree").stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"Git history scan unavailable: {exc}"]

    if inside != "true":
        return ["Git history scan unavailable: repository work tree was not detected"]

    try:
        paths_by_sha, blob_sizes = history_blob_index(root)
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        return [f"Git history scan failed: {exc}"]

    findings: list[str] = []
    for sha, size in blob_sizes.items():
        historical_paths = sorted(paths_by_sha.get(sha) or {f"<unpathed-blob-{sha}>"})
        for relative in historical_paths:
            label = f"history:{sha[:12]}:{relative}"
            findings.extend(path_findings(label))
        if size > MAX_FILE_BYTES:
            findings.append(
                f"history:{sha[:12]}: blob is {size} bytes; "
                f"public reproducer limit is {MAX_FILE_BYTES}"
            )

    try:
        for sha, raw in iter_git_blobs(root, blob_sizes):
            historical_paths = sorted(paths_by_sha.get(sha) or {f"<unpathed-blob-{sha}>"})
            representative = historical_paths[0]
            findings.extend(content_findings(f"history:{sha[:12]}:{representative}", raw))
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        findings.append(f"Git history scan failed: {exc}")

    return findings


def main() -> int:
    findings = scan_working_tree(ROOT)
    findings.extend(scan_git_history(ROOT))
    unique_findings = sorted(set(findings))

    if unique_findings:
        print("PUBLIC PAYLOAD CHECK: FAIL", file=sys.stderr)
        for finding in unique_findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    print("PUBLIC PAYLOAD CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
