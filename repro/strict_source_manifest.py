from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "IMPLEMENTATION_SOURCE_MANIFEST.json"
MANIFEST_RELATIVE = MANIFEST.relative_to(ROOT).as_posix()
SCHEMA_VERSION = 4


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def git_command(*args: str, text: bool = True) -> str | bytes:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required to generate the source manifest.")
    return subprocess.check_output(  # noqa: S603 - resolved trusted Git executable
        [git, *args],
        cwd=ROOT,
        text=text,
    )


def git_head() -> str:
    value = git_command("rev-parse", "HEAD")
    assert isinstance(value, str)
    return value.strip()


def tracked_paths() -> list[Path]:
    raw = git_command("ls-files", "-z", text=False)
    assert isinstance(raw, bytes)
    paths = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        relative = Path(encoded.decode("utf-8"))
        if relative.as_posix() == MANIFEST_RELATIVE:
            continue
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"Tracked path is unavailable from the worktree: {relative}")
        paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def file_rows() -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in tracked_paths()
    ]


def commit_file_rows(commit: str) -> list[dict[str, object]]:
    raw = git_command("ls-tree", "-r", "-z", "--name-only", commit, text=False)
    assert isinstance(raw, bytes)
    rows: list[dict[str, object]] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        relative = encoded.decode("utf-8")
        if relative == MANIFEST_RELATIVE:
            continue
        content = git_command("show", f"{commit}:{relative}", text=False)
        assert isinstance(content, bytes)
        rows.append(
            {
                "path": relative,
                "sha256": sha256_bytes(content),
                "size_bytes": len(content),
            }
        )
    return sorted(rows, key=lambda row: str(row["path"]))


def changed_paths(base: str, head: str) -> list[str]:
    raw = git_command("diff", "--name-only", "-z", base, head, text=False)
    assert isinstance(raw, bytes)
    return sorted(encoded.decode("utf-8") for encoded in raw.split(b"\0") if encoded)


def population_digest(rows: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(str(row["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(row["sha256"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(row["size_bytes"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def generated_payload(*, state: str) -> dict[str, object]:
    rows = file_rows()
    return {
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "content_commit": git_head(),
        "binding_rule": (
            "Every recorded non-manifest tracked file must equal the exact Git tree at "
            "content_commit and the checked worktree; only the manifest may differ between "
            "content_commit and the checked HEAD."
        ),
        "authorized_scope": "Release 1 only",
        "release_authorized": False,
        "tracked_file_count": len(rows),
        "tracked_content_sha256": population_digest(rows),
        "files": rows,
    }


def load_manifest() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read source manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("The source manifest root must be a JSON object.")
    return value


def recorded_file_rows(manifest: dict[str, Any]) -> list[dict[str, object]]:
    value = manifest.get("files")
    if not isinstance(value, list):
        raise RuntimeError("Source manifest files must be a list.")

    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeError("Every source-manifest row must be an object.")
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if not isinstance(path, str) or not path:
            raise RuntimeError("Every source-manifest row requires a non-empty string path.")
        if path == MANIFEST_RELATIVE:
            raise RuntimeError("The source manifest cannot include itself.")
        if path in seen:
            raise RuntimeError(f"Duplicate source-manifest path: {path}")
        if not isinstance(digest, str) or len(digest) != 64:
            raise RuntimeError(f"Invalid SHA-256 value for source-manifest path: {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RuntimeError(f"Invalid size_bytes value for source-manifest path: {path}")
        seen.add(path)
        rows.append({"path": path, "sha256": digest, "size_bytes": size})

    if [str(row["path"]) for row in rows] != sorted(str(row["path"]) for row in rows):
        raise RuntimeError("Source-manifest rows must be sorted by path.")
    return rows


def row_mismatches(
    *,
    expected: list[dict[str, object]],
    recorded: list[dict[str, object]],
) -> tuple[list[str], list[str], list[str]]:
    expected_by_path = {str(row["path"]): row for row in expected}
    recorded_by_path = {str(row["path"]): row for row in recorded}
    missing = sorted(set(expected_by_path) - set(recorded_by_path))
    extra = sorted(set(recorded_by_path) - set(expected_by_path))
    changed = sorted(
        path
        for path in set(expected_by_path) & set(recorded_by_path)
        if expected_by_path[path] != recorded_by_path[path]
    )
    return missing, extra, changed


def require_rows_match(
    *,
    expected: list[dict[str, object]],
    recorded: list[dict[str, object]],
    source: str,
) -> None:
    missing, extra, changed = row_mismatches(expected=expected, recorded=recorded)
    if missing or extra or changed:
        raise RuntimeError(
            f"Source manifest does not match {source}: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )


def validate_manifest() -> dict[str, object]:
    manifest = load_manifest()
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"Source manifest schema must be {SCHEMA_VERSION}; "
            f"found {manifest.get('schema_version')!r}."
        )

    recorded_rows = recorded_file_rows(manifest)
    current_rows = file_rows()

    content_commit = manifest.get("content_commit")
    if not isinstance(content_commit, str) or len(content_commit) != 40:
        raise RuntimeError("Source manifest content_commit must be a full Git identity.")

    head = git_head()
    try:
        git_command("merge-base", "--is-ancestor", content_commit, head)
        committed_rows = commit_file_rows(content_commit)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "Source manifest content_commit is unavailable or is not an ancestor of HEAD."
        ) from exc

    require_rows_match(
        expected=committed_rows,
        recorded=recorded_rows,
        source=f"the exact Git tree at content_commit {content_commit}",
    )
    require_rows_match(
        expected=current_rows,
        recorded=recorded_rows,
        source="the current tracked worktree population",
    )

    non_manifest_changes = [
        path for path in changed_paths(content_commit, head) if path != MANIFEST_RELATIVE
    ]
    if non_manifest_changes:
        raise RuntimeError(
            "Non-manifest tracked files changed after content_commit: "
            f"{non_manifest_changes}"
        )

    digest = population_digest(recorded_rows)
    if manifest.get("tracked_file_count") != len(recorded_rows):
        raise RuntimeError("Source manifest tracked_file_count is stale.")
    if manifest.get("tracked_content_sha256") != digest:
        raise RuntimeError("Source manifest tracked_content_sha256 is stale.")

    return {
        "result": "PASS",
        "schema_version": SCHEMA_VERSION,
        "tracked_files": len(recorded_rows),
        "tracked_content_sha256": digest,
        "content_commit": content_commit,
        "checked_head": head,
        "post_content_commit_changes": changed_paths(content_commit, head),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--state")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        result = validate_manifest()
    else:
        payload = generated_payload(state=args.state)
        MANIFEST.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        result = {
            "result": "PASS",
            "generated": MANIFEST_RELATIVE,
            "tracked_files": payload["tracked_file_count"],
            "tracked_content_sha256": payload["tracked_content_sha256"],
            "content_commit": payload["content_commit"],
            "state": payload["state"],
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
