from __future__ import annotations

import heapq
import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, TypeVar

INTERVAL = 256
T = TypeVar("T")
CHECKER: ContextVar[Callable[[], None] | None] = ContextVar("checker", default=None)


class Cancelled(RuntimeError):
    pass


class CancelAfter:
    def __init__(self, calls: int) -> None:
        self.remaining = calls

    def check(self) -> None:
        self.remaining -= 1
        if self.remaining <= 0:
            raise Cancelled("cancelled during bounded result validation")


def checkpoint() -> None:
    checker = CHECKER.get()
    if checker is not None:
        checker()


def rows(values: Iterable[T]) -> Iterator[T]:
    for index, value in enumerate(values, start=1):
        if index % INTERVAL == 0:
            checkpoint()
        yield value


def sorted_values(values: Iterable[T], *, key: Callable[[T], object]) -> tuple[T, ...]:
    chunks: list[tuple[T, ...]] = []
    chunk: list[T] = []
    for value in rows(values):
        chunk.append(value)
        if len(chunk) == INTERVAL:
            chunks.append(tuple(sorted(chunk, key=key)))
            chunk.clear()
            checkpoint()
    if chunk:
        chunks.append(tuple(sorted(chunk, key=key)))
        checkpoint()
    return () if not chunks else tuple(rows(heapq.merge(*chunks, key=key)))


class CheckpointedTuple(tuple[T, ...]):
    def __iter__(self) -> Iterator[T]:
        for index, value in enumerate(super().__iter__(), start=1):
            if index % INTERVAL == 0:
                checkpoint()
            yield value


@contextmanager
def validation_checkpoints(checker: Callable[[], None]) -> Iterator[None]:
    token = CHECKER.set(checker)
    checker()
    try:
        yield
    finally:
        CHECKER.reset(token)


@dataclass(frozen=True)
class ResultRow:
    key: str
    value: int
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResultTable:
    rows: tuple[ResultRow, ...]


def validate_result_table(table: ResultTable) -> ResultTable:
    seen: set[str] = set()
    for row in rows(table.rows):
        if row.key in seen:
            raise ValueError("duplicate row key")
        seen.add(row.key)
    checkpoint()
    ordered = CheckpointedTuple(sorted_values(table.rows, key=lambda row: row.key))
    checkpoint()

    for row in ordered:
        for warning in row.warnings:
            if warning != "ZERO_VERIFIED_DENOMINATOR":
                raise ValueError("unknown warning")
    checkpoint()
    return ResultTable(ordered)


def boundary_probe(row_count: int) -> bool:
    table = ResultTable(
        tuple(ResultRow(f"row-{index:04d}", index) for index in range(row_count))
    )
    token = CancelAfter(4)
    try:
        with validation_checkpoints(token.check):
            validate_result_table(table)
    except Cancelled:
        return CHECKER.get() is None
    return False


def downstream_iteration_probe() -> bool:
    table = ResultTable(
        tuple(ResultRow(f"row-{index:04d}", index) for index in range(300))
    )
    token = CancelAfter(7)
    try:
        with validation_checkpoints(token.check):
            validate_result_table(table)
    except Cancelled:
        return CHECKER.get() is None
    return False


def success_probe() -> bool:
    table = ResultTable(
        (
            ResultRow("row-0002", 2),
            ResultRow("row-0001", 1),
        )
    )
    with validation_checkpoints(lambda: None):
        validated = validate_result_table(table)
    return tuple(row.key for row in validated.rows) == ("row-0001", "row-0002")


def duplicate_probe() -> bool:
    table = ResultTable((ResultRow("same", 1), ResultRow("same", 2)))
    try:
        with validation_checkpoints(lambda: None):
            validate_result_table(table)
    except ValueError:
        return CHECKER.get() is None
    return False


def main() -> int:
    controls = {
        "boundary_255": boundary_probe(255),
        "boundary_256": boundary_probe(256),
        "boundary_257": boundary_probe(257),
        "downstream_retained_tuple_iteration": downstream_iteration_probe(),
        "successful_bounded_sort": success_probe(),
        "duplicate_rejection_and_context_reset": duplicate_probe(),
    }
    passed = sum(controls.values())
    result = {
        "schema_version": "1.0",
        "control_class": "AT-WAL-008-F-008-result-validation-cancellation",
        "passed": passed,
        "total": len(controls),
        "score": passed / len(controls),
        "controls": controls,
    }
    print(json.dumps(result, indent=2))
    return 0 if passed == len(controls) else 1


if __name__ == "__main__":
    raise SystemExit(main())
