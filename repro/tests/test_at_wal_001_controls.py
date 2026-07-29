from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from repro.at_wal_001_controls import (
    IntervalRecord,
    ReviewRecord,
    assign_reviewed_species,
    enumerate_commit_tree,
    replace_interval,
    validate_manifest_rows,
    worktree_status,
)


def _run_git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_bytes,
        capture_output=True,
        check=True,
    ).stdout


def _wait_for(path: Path, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out waiting for {path}")
        time.sleep(0.05)


def _worker_command(mode: str, root: Path, result: Path, *extra: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "repro.at_wal_001_controls",
        mode,
        "--lock",
        str(root / "external" / "startup.lock"),
        "--data-root",
        str(root / "governed"),
        "--result",
        str(result),
        *extra,
    ]


def test_two_process_cold_start_has_one_secret_and_no_loser_mutation(tmp_path: Path) -> None:
    ready = tmp_path / "owner-ready.json"
    release = tmp_path / "release.signal"
    owner_result = tmp_path / "owner-result.json"
    contender_result = tmp_path / "contender-result.json"
    restart_result = tmp_path / "restart-result.json"

    owner = subprocess.Popen(
        _worker_command(
            "owner",
            tmp_path,
            owner_result,
            "--ready",
            str(ready),
            "--release",
            str(release),
        )
    )
    try:
        _wait_for(ready)
        contender = subprocess.run(
            _worker_command("contender", tmp_path, contender_result),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert json.loads(contender_result.read_text(encoding="utf-8"))["status"] == "BLOCKED"
        assert not (tmp_path / "governed").exists()

        release.write_text("continue\n", encoding="utf-8")
        assert owner.wait(timeout=15) == 0
    finally:
        if owner.poll() is None:
            owner.kill()

    first = json.loads(owner_result.read_text(encoding="utf-8"))
    assert first["status"] == "OWNER"
    assert not (tmp_path / "governed" / "contender-created.txt").exists()

    restart = subprocess.run(
        _worker_command("restart", tmp_path, restart_result),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert restart.returncode == 0, restart.stderr
    second = json.loads(restart_result.read_text(encoding="utf-8"))
    persisted = (tmp_path / "governed" / "config" / "service.secret").read_text(
        encoding="ascii"
    ).strip()
    assert first["secret"] == second["secret"] == persisted


def test_interval_replacement_enforces_chronology_identity_and_rollback() -> None:
    current = IntervalRecord("OPERATING", "deployment-a", 10, 20)
    with pytest.raises(ValueError, match="end precedes"):
        replace_interval(
            current,
            interval_type="OPERATING",
            deployment_id="deployment-a",
            start=30,
            end=29,
        )
    assert (current.status, current.is_current) == ("FINAL", True)

    for interval_type, deployment_id in (
        ("BEARING", "deployment-a"),
        ("OPERATING", "deployment-b"),
    ):
        with pytest.raises(ValueError, match="mismatch"):
            replace_interval(
                current,
                interval_type=interval_type,
                deployment_id=deployment_id,
                start=20,
                end=30,
            )

    with pytest.raises(ValueError, match="overlaps"):
        replace_interval(
            current,
            interval_type="OPERATING",
            deployment_id="deployment-a",
            start=20,
            end=30,
            overlap_rejected=True,
        )
    assert (current.status, current.is_current) == ("FINAL", True)

    successor = replace_interval(
        current,
        interval_type="OPERATING",
        deployment_id="deployment-a",
        start=20,
        end=30,
    )
    assert (current.status, current.is_current) == ("SUPERSEDED", False)
    assert (successor.status, successor.is_current) == ("FINAL", True)


def test_review_resolution_rejects_bypasses_and_records_actual_before_state() -> None:
    for record, property_id in (
        (ReviewRecord("property-a", "DEER", "ACCEPTED", "ACCEPTED"), "property-a"),
        (ReviewRecord("property-a", "UNKNOWN", "NEEDS_REVIEW", "VOID"), "property-a"),
        (ReviewRecord("property-a", "UNKNOWN", "NEEDS_REVIEW", "DUPLICATE"), "property-a"),
        (ReviewRecord("property-a", "UNKNOWN", "NEEDS_REVIEW", "NEEDS_REVIEW"), "property-b"),
    ):
        with pytest.raises(ValueError):
            assign_reviewed_species(
                record,
                property_id=property_id,
                resolved_species_code="DEER",
            )

    record = ReviewRecord("property-a", "UNKNOWN", "NEEDS_REVIEW", "NEEDS_REVIEW")
    before, after = assign_reviewed_species(
        record,
        property_id="property-a",
        resolved_species_code="DEER",
    )
    assert before == {
        "species_code": "UNKNOWN",
        "observation_status": "NEEDS_REVIEW",
        "event_status": "NEEDS_REVIEW",
    }
    assert after == {
        "species_code": "DEER",
        "observation_status": "ACCEPTED",
        "event_status": "ACCEPTED",
    }


def _initialize_git_fixture(repo: Path) -> bytes:
    repo.mkdir()
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.name", "Public Diagnostic")
    _run_git(repo, "config", "user.email", "diagnostic@example.invalid")
    authority = b"alpha\nbeta\n"
    (repo / "authority.txt").write_bytes(authority)
    (repo / "tool.py").write_text("print('synthetic')\n", encoding="utf-8")
    (repo / "pointer.txt").write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "size 1\n",
        encoding="utf-8",
    )
    _run_git(repo, "add", "authority.txt", "tool.py", "pointer.txt")
    _run_git(repo, "commit", "-qm", "initial synthetic tree")
    _run_git(repo, "update-index", "--chmod=+x", "tool.py")
    _run_git(repo, "commit", "-qm", "mark executable")

    target_blob = _run_git(repo, "hash-object", "-w", "--stdin", input_bytes=b"authority.txt").strip()
    _run_git(
        repo,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{target_blob.decode('ascii')},alias",
    )
    _run_git(repo, "commit", "-qm", "add synthetic symlink entry")

    head = _run_git(repo, "rev-parse", "HEAD").strip().decode("ascii")
    _run_git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},nested")
    _run_git(repo, "commit", "-qm", "add synthetic gitlink")
    return authority


def test_manifest_validation_uses_committed_blob_not_windows_worktree_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    authority = _initialize_git_fixture(repo)
    expected = {
        "path": "authority.txt",
        "size": len(authority),
        "sha256": hashlib.sha256(authority).hexdigest(),
    }

    (repo / "authority.txt").write_bytes(authority.replace(b"\n", b"\r\n"))
    assert validate_manifest_rows(repo, [expected]) == []

    wrong = dict(expected)
    wrong["size"] = len(authority) + 1
    wrong["sha256"] = "0" * 64
    assert validate_manifest_rows(repo, [wrong]) == [
        "authority.txt: size mismatch",
        "authority.txt: hash mismatch",
    ]


def test_commit_tree_population_is_deterministic_and_separate_from_worktree(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _initialize_git_fixture(repo)
    (repo / "untracked.txt").write_text("synthetic\n", encoding="utf-8")

    first = enumerate_commit_tree(repo)
    second = enumerate_commit_tree(repo)
    assert first == second
    by_path = {entry.path: entry for entry in first}
    assert "untracked.txt" not in by_path
    assert by_path["tool.py"].classification == "EXECUTABLE"
    assert by_path["alias"].classification == "SYMLINK"
    assert by_path["nested"].classification == "SUBMODULE"
    assert by_path["pointer.txt"].classification == "LFS_POINTER"
    assert any(item.endswith("untracked.txt") for item in worktree_status(repo))
