from __future__ import annotations

from dataclasses import dataclass, field

PRIVATE_TARGET_SHA = "28e6f2b1b1ccf28c8336398e09f50c4387b337ac"


class InjectedInterruption(RuntimeError):
    pass


@dataclass
class TerminalCommitState:
    phase: str = "READY"
    rollback_exists: bool = True
    active_exists: bool = True
    outcome_persisted: bool = False
    lineage_persisted: bool = False
    readback_verified: bool = False
    history_archived: bool = False
    journal_closed: bool = False
    events: list[str] = field(default_factory=list)

    def begin(self) -> None:
        if self.phase != "READY":
            raise RuntimeError("terminal commit requires READY")
        if not self.rollback_exists:
            raise RuntimeError("rollback authority is missing")
        self.phase = "FINALIZE_PENDING"
        self.events.append("begin")

    def _interrupt(self, point: str, interrupt_after: str | None) -> None:
        if interrupt_after == point:
            raise InjectedInterruption(point)

    def commit(self, *, interrupt_after: str | None = None) -> None:
        if self.phase not in {"FINALIZE_PENDING", "FINALIZED"}:
            raise RuntimeError("terminal commit is not pending")
        if not self.active_exists:
            raise RuntimeError("active authority is missing")
        if self.phase == "FINALIZE_PENDING" and not self.rollback_exists:
            raise RuntimeError("rollback authority was released prematurely")

        if not self.outcome_persisted:
            self.outcome_persisted = True
            self.events.append("persist_outcome")
        self._interrupt("persist_outcome", interrupt_after)

        if not self.lineage_persisted:
            self.lineage_persisted = True
            self.events.append("persist_lineage")
        self._interrupt("persist_lineage", interrupt_after)

        if not self.readback_verified:
            if not self.outcome_persisted or not self.lineage_persisted:
                raise RuntimeError("durable readback failed")
            self.readback_verified = True
            self.events.append("verify_readback")
        self._interrupt("verify_readback", interrupt_after)

        if self.phase != "FINALIZED":
            self.phase = "FINALIZED"
            self.events.append("mark_finalized")
        self._interrupt("mark_finalized", interrupt_after)

        if not self.history_archived:
            self.history_archived = True
            self.events.append("archive_journal")
        self._interrupt("archive_journal", interrupt_after)

        if self.rollback_exists:
            if not (
                self.outcome_persisted
                and self.lineage_persisted
                and self.readback_verified
                and self.history_archived
            ):
                raise RuntimeError("rollback release preconditions are incomplete")
            self.rollback_exists = False
            self.events.append("release_rollback")
        self._interrupt("release_rollback", interrupt_after)

        if not self.journal_closed:
            self.journal_closed = True
            self.events.append("close_journal")
        self._interrupt("close_journal", interrupt_after)

    def restart(self) -> None:
        self.events.append("restart")
        if self.phase == "FINALIZE_PENDING" and not self.rollback_exists:
            raise RuntimeError("restart detected premature rollback loss")
        self.commit()


def run_matrix() -> dict[str, object]:
    points = (
        "persist_outcome",
        "persist_lineage",
        "verify_readback",
        "mark_finalized",
        "archive_journal",
        "release_rollback",
        "close_journal",
    )
    results: dict[str, str] = {}
    for point in points:
        state = TerminalCommitState()
        state.begin()
        try:
            state.commit(interrupt_after=point)
        except InjectedInterruption:
            pass

        if point in {
            "persist_outcome",
            "persist_lineage",
            "verify_readback",
            "mark_finalized",
            "archive_journal",
        } and not state.rollback_exists:
            raise AssertionError(f"rollback authority released before safe boundary: {point}")

        state.restart()
        if not (
            state.phase == "FINALIZED"
            and state.outcome_persisted
            and state.lineage_persisted
            and state.readback_verified
            and state.history_archived
            and not state.rollback_exists
            and state.journal_closed
        ):
            raise AssertionError(f"restart did not complete deterministically: {point}")
        results[point] = "PASS"

    return {
        "result": "PASS",
        "private_target_sha": PRIVATE_TARGET_SHA,
        "matrix": results,
        "claim_boundary": "SANITIZED_ORDERING_ALGORITHM_ONLY",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_matrix(), indent=2, sort_keys=True))
