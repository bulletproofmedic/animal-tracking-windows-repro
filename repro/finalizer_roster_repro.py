from __future__ import annotations

from dataclasses import dataclass

ROSTER_VERSION = 1


class RosterError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FinalizerIdentity:
    finalizer_id: str
    finalizer_version: str


def canonical_roster(finalizers: tuple[FinalizerIdentity, ...]) -> list[dict[str, str]]:
    ordered = sorted(finalizers, key=lambda row: (row.finalizer_id, row.finalizer_version))
    seen: set[str] = set()
    roster: list[dict[str, str]] = []
    for finalizer in ordered:
        if not finalizer.finalizer_id or not finalizer.finalizer_version:
            raise RosterError("empty finalizer identity")
        if finalizer.finalizer_id in seen:
            raise RosterError("duplicate finalizer identity")
        seen.add(finalizer.finalizer_id)
        roster.append(
            {
                "finalizer_id": finalizer.finalizer_id,
                "finalizer_version": finalizer.finalizer_version,
            }
        )
    return roster


def required_roster(journal: dict[str, object]) -> tuple[tuple[str, str], ...]:
    if journal.get("post_restore_finalizer_roster_version") != ROSTER_VERSION:
        raise RosterError("unsupported roster version")
    raw_roster = journal.get("required_post_restore_finalizers")
    if not isinstance(raw_roster, list):
        raise RosterError("malformed roster")

    roster: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_row in raw_roster:
        if not isinstance(raw_row, dict) or set(raw_row) != {
            "finalizer_id",
            "finalizer_version",
        }:
            raise RosterError("malformed roster entry")
        finalizer_id = raw_row.get("finalizer_id")
        finalizer_version = raw_row.get("finalizer_version")
        if (
            not isinstance(finalizer_id, str)
            or not finalizer_id
            or not isinstance(finalizer_version, str)
            or not finalizer_version
        ):
            raise RosterError("malformed finalizer identity")
        if finalizer_id in seen:
            raise RosterError("duplicate required finalizer identity")
        seen.add(finalizer_id)
        roster.append((finalizer_id, finalizer_version))

    if roster != sorted(roster):
        raise RosterError("noncanonical roster")
    return tuple(roster)


def validate_runtime_roster(
    journal: dict[str, object],
    runtime_finalizers: tuple[FinalizerIdentity, ...],
) -> None:
    expected = required_roster(journal)
    actual = tuple(
        (row["finalizer_id"], row["finalizer_version"])
        for row in canonical_roster(runtime_finalizers)
    )
    if actual != expected:
        raise RosterError("finalizer roster changed after staging")
