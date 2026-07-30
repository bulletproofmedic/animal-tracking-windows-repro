from __future__ import annotations

import heapq
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
_POPULATIONS = (
    "EVENT",
    "OBSERVATION",
    "SITE",
    "DEVICE",
    "DEPLOYMENT",
    "SPECIES",
    "CONFIGURATION_INTERVAL",
)


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

    def sorted_values(
        self,
        values: Iterable[_T],
        *,
        key: Callable[[_T], object],
    ) -> tuple[_T, ...]:
        chunks: list[tuple[_T, ...]] = []
        chunk: list[_T] = []
        for value in self.rows(values):
            chunk.append(value)
            if len(chunk) == _CHECKPOINT_INTERVAL:
                chunks.append(tuple(sorted(chunk, key=key)))
                chunk.clear()
                self.check()
        if chunk:
            chunks.append(tuple(sorted(chunk, key=key)))
            self.check()
        return () if not chunks else tuple(self.rows(heapq.merge(*chunks, key=key)))


@dataclass(frozen=True)
class PopulationRow:
    entity_type: str
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


def validate_stable_population(rows: Iterable[PopulationRow]) -> None:
    seen: set[UUID] = set()
    for row in rows:
        if row.stable_id in seen:
            raise ControlError(
                f"{row.entity_type} stable identities must be unique across revisions"
            )
        seen.add(row.stable_id)


def selection_counts(
    selected: Iterable[SelectedRow],
    exclusions: Iterable[Exclusion],
    checkpoints: Checkpoints,
) -> dict[str, int]:
    represented: set[tuple[str, UUID, int]] = set()
    counts = {"included": 0, "partial": 0, "excluded": 0}
    checkpoints.check()
    for row in checkpoints.rows(selected):
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


def require_selection_counts(
    selected: Iterable[SelectedRow],
    exclusions: Iterable[Exclusion],
    supplied: Mapping[str, int],
) -> None:
    expected = selection_counts(
        selected,
        exclusions,
        Checkpoints(CancelAfter(1000)),
    )
    if dict(supplied) != expected:
        raise ControlError("selection counts do not reconcile to the typed graph")


def validate_payload(
    rows: Iterable[PopulationRow],
    checkpoints: Checkpoints,
) -> tuple[PopulationRow, ...]:
    populations: dict[str, set[UUID]] = {
        entity_type: set() for entity_type in _POPULATIONS
    }
    checkpoints.check()
    for row in checkpoints.rows(rows):
        if row.entity_type not in populations:
            raise ControlError("undeclared population")
        if row.stable_id in populations[row.entity_type]:
            raise ControlError("duplicate stable identity")
        populations[row.entity_type].add(row.stable_id)
    checkpoints.check()
    ordered = checkpoints.sorted_values(
        (
            PopulationRow(entity_type, identity, 1)
            for entity_type, identities in populations.items()
            for identity in identities
        ),
        key=lambda row: (row.entity_type, str(row.stable_id), row.revision),
    )
    if len(ordered) != sum(len(identities) for identities in populations.values()):
        raise ControlError("payload population mismatch")
    checkpoints.check()
    return ordered


class Snapshot:
    def __init__(self, rows: Iterable[PopulationRow]) -> None:
        self.rows = tuple(rows)
        self.closed = False

    def __enter__(self) -> Snapshot:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True


class CancelAfterSnapshotClose:
    def __init__(self, snapshot: Snapshot, calls: int) -> None:
        self.snapshot = snapshot
        self.remaining = calls

    def raise_if_cancelled(self) -> None:
        if not self.snapshot.closed:
            return
        self.remaining -= 1
        if self.remaining <= 0:
            raise Cancelled("cancelled during payload validation")


def build_payload(snapshot: Snapshot, token: object) -> tuple[PopulationRow, ...]:
    checkpoints = Checkpoints(token)
    with snapshot:
        rows = checkpoints.materialize(snapshot.rows)
    return validate_payload(rows, checkpoints)


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


def create_shallow_repository() -> tuple[
    tempfile.TemporaryDirectory[str],
    Path,
    str,
    str,
    str,
]:
    holder = tempfile.TemporaryDirectory()
    root = Path(holder.name)
    source = root / "source"
    remote = root / "remote.git"
    checkout = root / "checkout"
    source.mkdir()
    _git(source, "init", "-b", "main")
    _git(source, "config", "user.email", "synthetic@example.invalid")
    _git(source, "config", "user.name", "Synthetic Control")
    (source / "base.txt").write_text("base\n", encoding="utf-8")
    _git(source, "add", "base.txt")
    _git(source, "commit", "-m", "base")
    base = _git(source, "rev-parse", "HEAD")
    (source / "control.txt").write_text("controlled\n", encoding="utf-8")
    _git(source, "add", "control.txt")
    _git(source, "commit", "-m", "target")
    head = _git(source, "rev-parse", "HEAD")
    tree = _git(source, "rev-parse", "HEAD^{tree}")
    subprocess.run(
        ["git", "clone", "--bare", str(source), str(remote)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "clone", "--depth=1", remote.as_uri(), str(checkout)],
        check=True,
        capture_output=True,
        text=True,
    )
    return holder, checkout, base, head, tree


def ensure_complete_history(
    root: Path,
    *,
    expected_base_commit: str,
    expected_source_commit: str,
) -> None:
    if _git(root, "rev-parse", "--is-shallow-repository") == "true":
        _git(root, "fetch", "--no-tags", "--unshallow", "origin")
    else:
        _git(root, "fetch", "--no-tags", "origin")
    for commit in (expected_base_commit, expected_source_commit):
        _git(root, "cat-file", "-e", f"{commit}^{{commit}}")


def run_mutation_probes(
    probes: Mapping[str, Callable[[], bool]],
) -> dict[str, object]:
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

    def all_population_collisions() -> bool:
        for entity_type in _POPULATIONS:
            for revisions in ((1, 2), (2, 1)):
                rows = (
                    PopulationRow(entity_type, shared, revisions[0]),
                    PopulationRow(entity_type, shared, revisions[1]),
                )
                if not _raises(
                    ControlError,
                    lambda rows=rows: validate_stable_population(rows),
                ):
                    return False
        return True

    def typed_exclusion() -> bool:
        selected = (SelectedRow("EVENT", shared, 1, "included"),)
        exclusions = (Exclusion("SPECIES", shared, 1, "excluded"),)
        result = selection_counts(
            selected,
            exclusions,
            Checkpoints(CancelAfter(100)),
        )
        return result == {
            "included": 1,
            "partial": 0,
            "excluded": 1,
            "considered": 2,
        }

    def undercount_rejected() -> bool:
        return _raises(
            ControlError,
            lambda: require_selection_counts(
                (SelectedRow("EVENT", shared, 1, "included"),),
                (Exclusion("SPECIES", shared, 1, "excluded"),),
                {
                    "included": 1,
                    "partial": 0,
                    "excluded": 0,
                    "considered": 1,
                },
            ),
        )

    def validation_cancel() -> bool:
        rows = tuple(
            PopulationRow("EVENT", UUID(int=index + 1), 1)
            for index in range(2000)
        )
        snapshot = Snapshot(rows)
        return _raises(
            Cancelled,
            lambda: build_payload(
                snapshot,
                CancelAfterSnapshotClose(snapshot, calls=3),
            ),
        )

    def validation_exception_preserved() -> bool:
        duplicate = PopulationRow("EVENT", shared, 1)
        snapshot = Snapshot((duplicate, duplicate))
        try:
            build_payload(snapshot, CancelAfterSnapshotClose(snapshot, calls=1000))
        except ControlError as error:
            return str(error) == "duplicate stable identity"
        return False

    def shallow_history_repaired() -> bool:
        holder, root, base, head, tree = create_shallow_repository()
        try:
            if _git(root, "rev-parse", "--is-shallow-repository") != "true":
                return False
            ensure_complete_history(
                root,
                expected_base_commit=base,
                expected_source_commit=head,
            )
            result = validate_git_binding(
                root,
                expected_execution_commit=head,
                expected_source_commit=head,
                expected_source_tree=tree,
                expected_base_commit=base,
                expected_changed_paths={"control.txt"},
            )
            return (
                result["merge_base"] == base
                and _git(root, "rev-parse", "--is-shallow-repository") == "false"
            )
        finally:
            holder.cleanup()

    return run_mutation_probes(
        {
            "all_population_stable_id_collisions": all_population_collisions,
            "typed_cross_entity_exclusion": typed_exclusion,
            "typed_selection_undercount": undercount_rejected,
            "payload_validation_cancellation": validation_cancel,
            "validation_exception_preservation": validation_exception_preserved,
            "shallow_history_acquisition": shallow_history_repaired,
        }
    )


if __name__ == "__main__":
    result = producer_evidence()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["score"] == 1.0 else 1)
