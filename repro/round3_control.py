from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar
from uuid import UUID

_CHECKPOINT_INTERVAL = 64
_T = TypeVar("_T")


class ControlError(ValueError):
    pass


class Cancelled(RuntimeError):
    pass


class CancelAfter:
    def __init__(self, calls: int) -> None:
        self.remaining = calls

    def raise_if_cancelled(self) -> None:
        self.remaining -= 1
        if self.remaining <= 0:
            raise Cancelled("cancelled")


class Checkpoints:
    def __init__(self, token: object) -> None:
        self.token = token
        self.calls = 0
        self.rows_seen = 0

    def check(self) -> None:
        self.token.raise_if_cancelled()  # type: ignore[attr-defined]
        self.calls += 1

    def rows(self, values: Iterable[_T]) -> Iterable[_T]:
        for index, value in enumerate(values, start=1):
            self.rows_seen += 1
            if index % _CHECKPOINT_INTERVAL == 0:
                self.check()
            yield value

    def materialize(self, values: Iterable[_T]) -> tuple[_T, ...]:
        self.check()
        result = tuple(self.rows(values))
        self.check()
        return result


@dataclass(frozen=True)
class Configuration:
    stable_id: UUID
    revision: int


@dataclass(frozen=True)
class SelectedRow:
    entity_type: str
    stable_id: UUID
    revision: int
    disposition: str


@dataclass(frozen=True)
class Exclusion:
    entity_type: str
    stable_id: UUID
    revision: int
    disposition: str


def validate_configuration_population(rows: Iterable[Configuration]) -> None:
    identities: set[UUID] = set()
    for row in rows:
        if row.stable_id in identities:
            raise ControlError("configuration stable identities must be unique across revisions")
        identities.add(row.stable_id)


def selection_counts(
    events: Iterable[SelectedRow],
    observations: Iterable[SelectedRow],
    exclusions: Iterable[Exclusion],
    checkpoints: Checkpoints,
) -> dict[str, int]:
    represented: set[tuple[str, UUID, int]] = set()
    counts = {"included": 0, "partial": 0, "excluded": 0}

    checkpoints.check()
    for row in checkpoints.rows(events):
        represented.add((row.entity_type, row.stable_id, row.revision))
        counts[row.disposition] += 1
    checkpoints.check()
    for row in checkpoints.rows(observations):
        represented.add((row.entity_type, row.stable_id, row.revision))
        counts[row.disposition] += 1
    checkpoints.check()
    for row in checkpoints.rows(exclusions):
        identity = (row.entity_type, row.stable_id, row.revision)
        if identity not in represented:
            counts[row.disposition] += 1
    checkpoints.check()
    counts["considered"] = sum(counts.values())
    return counts


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ControlError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def validate_git_binding(
    root: Path,
    *,
    expected_execution_commit: str,
    expected_source_commit: str,
    expected_source_tree: str,
    expected_base_commit: str,
    expected_changed_paths: set[str],
) -> dict[str, object]:
    execution_commit = _git(root, "rev-parse", "HEAD")
    execution_tree = _git(root, "rev-parse", "HEAD^{tree}")
    source_tree = _git(root, "rev-parse", f"{expected_source_commit}^{{tree}}")
    merge_base = _git(root, "merge-base", expected_base_commit, expected_source_commit)
    tracked_status = _git(root, "status", "--porcelain", "--untracked-files=no")
    changed_paths = {
        line
        for line in _git(
            root,
            "diff",
            "--name-only",
            f"{expected_base_commit}...{expected_source_commit}",
        ).splitlines()
        if line
    }

    if execution_commit != expected_execution_commit:
        raise ControlError("execution commit mismatch")
    if execution_tree != expected_source_tree or source_tree != expected_source_tree:
        raise ControlError("source tree mismatch")
    if merge_base != expected_base_commit:
        raise ControlError("merge base mismatch")
    if tracked_status:
        raise ControlError("tracked worktree is not clean")
    if changed_paths != expected_changed_paths:
        raise ControlError("changed-path population mismatch")

    return {
        "execution_commit": execution_commit,
        "execution_tree": execution_tree,
        "source_commit": expected_source_commit,
        "source_tree": source_tree,
        "merge_base": merge_base,
        "changed_paths": sorted(changed_paths),
        "tracked_worktree_clean": True,
    }


def create_synthetic_repository() -> tuple[tempfile.TemporaryDirectory[str], Path, str, str, str]:
    holder = tempfile.TemporaryDirectory()
    root = Path(holder.name)
    _git(root, "init")
    _git(root, "config", "user.email", "synthetic@example.invalid")
    _git(root, "config", "user.name", "Synthetic Control")
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    _git(root, "add", "base.txt")
    _git(root, "commit", "-m", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "control.txt").write_text("controlled\n", encoding="utf-8")
    _git(root, "add", "control.txt")
    _git(root, "commit", "-m", "target")
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    return holder, root, base, head, tree


def run_mutation_probes(probes: Mapping[str, Callable[[], bool]]) -> dict[str, object]:
    results = []
    for mutation_id, probe in sorted(probes.items()):
        killed = bool(probe())
        results.append(
            {
                "mutation_id": mutation_id,
                "status": "KILLED" if killed else "SURVIVED",
            }
        )
    killed_count = sum(item["status"] == "KILLED" for item in results)
    return {
        "killed": killed_count,
        "total": len(results),
        "score": killed_count / len(results),
        "results": results,
    }


def _raises(exception_type: type[BaseException], callback: Callable[[], object]) -> bool:
    try:
        callback()
    except exception_type:
        return True
    return False


def producer_evidence() -> dict[str, object]:
    shared = UUID("00000000-0000-7000-8000-000000000001")

    def collision(order: tuple[int, int]) -> bool:
        rows = tuple(Configuration(shared, revision) for revision in order)
        return _raises(ControlError, lambda: validate_configuration_population(rows))

    def stream_cancel() -> bool:
        checkpoints = Checkpoints(CancelAfter(3))
        return _raises(Cancelled, lambda: checkpoints.materialize(range(1000)))

    def counts_cancel() -> bool:
        checkpoints = Checkpoints(CancelAfter(2))
        rows = (
            SelectedRow("EVENT", UUID(int=index + 1), 1, "included")
            for index in range(1000)
        )
        return _raises(Cancelled, lambda: selection_counts(rows, (), (), checkpoints))

    def typed_identity() -> bool:
        checkpoints = Checkpoints(CancelAfter(100))
        event = SelectedRow("EVENT", shared, 1, "included")
        observation = SelectedRow("OBSERVATION", shared, 1, "included")
        return selection_counts((event,), (observation,), (), checkpoints)["considered"] == 2

    holder, root, base, head, tree = create_synthetic_repository()
    try:
        def wrong_head() -> bool:
            return _raises(
                ControlError,
                lambda: validate_git_binding(
                    root,
                    expected_execution_commit="0" * 40,
                    expected_source_commit=head,
                    expected_source_tree=tree,
                    expected_base_commit=base,
                    expected_changed_paths={"control.txt"},
                ),
            )

        evidence = run_mutation_probes(
            {
                "configuration_collision_forward": lambda: collision((1, 2)),
                "configuration_collision_reverse": lambda: collision((2, 1)),
                "builder_stream_cancellation": stream_cancel,
                "selection_count_cancellation": counts_cancel,
                "selection_identity_entity_type": typed_identity,
                "validator_wrong_head": wrong_head,
            }
        )
    finally:
        holder.cleanup()
    return evidence


if __name__ == "__main__":
    result = producer_evidence()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["score"] == 1.0 else 1)
