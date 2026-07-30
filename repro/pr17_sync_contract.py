from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from typing import Iterable

CHECK_INTERVAL = 256


class Cancelled(RuntimeError):
    pass


class ContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceState:
    epoch: str
    revision: int


@dataclass(frozen=True)
class Row:
    record_type: str
    stable_id: str
    revision: int


class CancellationToken:
    def __init__(self, cancel_after_checks: int | None = None) -> None:
        self.cancel_after_checks = cancel_after_checks
        self.checks = 0

    def check(self) -> None:
        self.checks += 1
        if self.cancel_after_checks is not None and self.checks >= self.cancel_after_checks:
            raise Cancelled("cancelled")


class Snapshot:
    def __init__(
        self,
        *,
        session_id: str,
        initial_state: SourceState,
        final_state: SourceState | None = None,
        event_rows: Iterable[Row] = (),
        observation_rows: Iterable[Row] = (),
        fail_stream: bool = False,
    ) -> None:
        self.session_id = session_id
        self.initial_state = initial_state
        self.final_state = final_state or initial_state
        self.event_rows = tuple(event_rows)
        self.observation_rows = tuple(observation_rows)
        self.fail_stream = fail_stream
        self.state_reads = 0
        self.close_calls = 0
        self.closed = False
        self.method_sessions: list[str] = []

    @property
    def source_state(self) -> SourceState:
        self._touch()
        self.state_reads += 1
        return self.initial_state if self.state_reads == 1 else self.final_state

    def stream_event_rows(self) -> Iterable[Row]:
        self._touch()
        if self.fail_stream:
            raise ContractError("stream failure")
        return iter(self.event_rows)

    def stream_observation_rows(self) -> Iterable[Row]:
        self._touch()
        return iter(self.observation_rows)

    def load_dimensions(self) -> tuple[str, ...]:
        self._touch()
        return ("synthetic",)

    def _touch(self) -> None:
        if self.closed:
            raise ContractError("closed snapshot used")
        self.method_sessions.append(self.session_id)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.close_calls += 1

    def __enter__(self) -> "Snapshot":
        self._touch()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class Repository:
    def __init__(self, snapshot: Snapshot) -> None:
        self.snapshot = snapshot
        self.open_calls = 0

    def open_snapshot(self) -> Snapshot:
        self.open_calls += 1
        if self.open_calls != 1:
            raise ContractError("second session opened")
        return self.snapshot


def _materialize(values: Iterable[Row], token: CancellationToken) -> tuple[Row, ...]:
    token.check()
    result: list[Row] = []
    for index, value in enumerate(values, start=1):
        result.append(value)
        if index % CHECK_INTERVAL == 0:
            token.check()
    token.check()
    return tuple(result)


def build_dataset(
    repository: Repository,
    token: CancellationToken,
    *,
    fail_post_read_validation: bool = False,
) -> dict[str, object]:
    token.check()
    with repository.open_snapshot() as snapshot:
        initial_state = snapshot.source_state
        events = _materialize(snapshot.stream_event_rows(), token)
        observations = _materialize(snapshot.stream_observation_rows(), token)
        dimensions = snapshot.load_dimensions()
        final_state = snapshot.source_state
        if final_state != initial_state:
            raise ContractError("source state changed during snapshot")

        typed_identities = {
            (row.record_type, row.stable_id, row.revision)
            for row in (*events, *observations)
        }

    if fail_post_read_validation:
        raise ContractError("post-read validation failed")

    token.check()
    return {
        "source_state": initial_state,
        "typed_identity_count": len(typed_identities),
        "dimensions": dimensions,
    }


class SynchronizationContractTests(unittest.TestCase):
    def state(self, revision: int = 7) -> SourceState:
        return SourceState("synthetic-epoch", revision)

    def test_one_session_success_and_typed_identity_separation(self) -> None:
        shared_id = "00000000-0000-7000-8000-000000000001"
        snapshot = Snapshot(
            session_id="session-1",
            initial_state=self.state(),
            event_rows=(Row("EVENT", shared_id, 1),),
            observation_rows=(Row("OBSERVATION", shared_id, 1),),
        )
        repository = Repository(snapshot)

        result = build_dataset(repository, CancellationToken())

        self.assertEqual(repository.open_calls, 1)
        self.assertEqual(snapshot.close_calls, 1)
        self.assertTrue(snapshot.closed)
        self.assertEqual(set(snapshot.method_sessions), {"session-1"})
        self.assertEqual(result["typed_identity_count"], 2)

    def test_source_state_change_is_rejected_and_closed(self) -> None:
        snapshot = Snapshot(
            session_id="session-2",
            initial_state=self.state(7),
            final_state=self.state(8),
        )
        repository = Repository(snapshot)

        with self.assertRaisesRegex(ContractError, "source state changed"):
            build_dataset(repository, CancellationToken())

        self.assertEqual(repository.open_calls, 1)
        self.assertEqual(snapshot.close_calls, 1)

    def test_cancellation_at_256_rows_closes_once(self) -> None:
        rows = tuple(Row("EVENT", f"id-{index}", 1) for index in range(256))
        snapshot = Snapshot(
            session_id="session-3",
            initial_state=self.state(),
            event_rows=rows,
        )
        repository = Repository(snapshot)

        with self.assertRaises(Cancelled):
            build_dataset(repository, CancellationToken(cancel_after_checks=3))

        self.assertEqual(repository.open_calls, 1)
        self.assertEqual(snapshot.close_calls, 1)

    def test_stream_failure_closes_without_fallback_session(self) -> None:
        snapshot = Snapshot(
            session_id="session-4",
            initial_state=self.state(),
            fail_stream=True,
        )
        repository = Repository(snapshot)

        with self.assertRaisesRegex(ContractError, "stream failure"):
            build_dataset(repository, CancellationToken())

        self.assertEqual(repository.open_calls, 1)
        self.assertEqual(snapshot.close_calls, 1)

    def test_post_read_validation_failure_occurs_after_close(self) -> None:
        snapshot = Snapshot(session_id="session-5", initial_state=self.state())
        repository = Repository(snapshot)

        with self.assertRaisesRegex(ContractError, "post-read validation failed"):
            build_dataset(
                repository,
                CancellationToken(),
                fail_post_read_validation=True,
            )

        self.assertTrue(snapshot.closed)
        self.assertEqual(snapshot.close_calls, 1)
        self.assertEqual(repository.open_calls, 1)

    def test_close_is_idempotent(self) -> None:
        snapshot = Snapshot(session_id="session-6", initial_state=self.state())
        snapshot.close()
        snapshot.close()
        self.assertEqual(snapshot.close_calls, 1)

    def test_cancelled_build_never_opens_second_session(self) -> None:
        snapshot = Snapshot(session_id="session-7", initial_state=self.state())
        repository = Repository(snapshot)

        with self.assertRaises(Cancelled):
            build_dataset(repository, CancellationToken(cancel_after_checks=1))

        self.assertEqual(repository.open_calls, 0)
        self.assertEqual(snapshot.close_calls, 0)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SynchronizationContractTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "schema_version": "1.0",
        "control_class": "PR17_AT_WAL_008_SYNCHRONIZATION_COMPATIBILITY",
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "total": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "result": "PASS" if result.wasSuccessful() else "FAIL",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
