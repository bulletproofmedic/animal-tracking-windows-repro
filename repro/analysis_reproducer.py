from __future__ import annotations

import heapq
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from typing import Protocol, TypeVar

T = TypeVar("T")
CHECKPOINT_INTERVAL = 64
SECONDS_PER_DAY = 86_400


class Measure(Enum):
    EVENT = "event"
    RATE = "events_per_100_active_days"


@dataclass(frozen=True)
class Event:
    event_id: int
    included_measures: tuple[Measure, ...]


@dataclass(frozen=True)
class Observation:
    observation_id: int
    event_id: int


class CancellationToken(Protocol):
    def raise_if_cancelled(self) -> None: ...


@dataclass
class Checkpoints:
    token: CancellationToken
    check_count: int = 0
    processed_rows: int = 0

    def check(self) -> None:
        self.token.raise_if_cancelled()
        self.check_count += 1

    def rows(self, values: Iterable[T]) -> Iterator[T]:
        for index, value in enumerate(values, start=1):
            self.processed_rows += 1
            if index % CHECKPOINT_INTERVAL == 0:
                self.check()
            yield value

    def sorted_values(
        self,
        values: Iterable[T],
        *,
        key: Callable[[T], object],
    ) -> tuple[T, ...]:
        chunks: list[tuple[T, ...]] = []
        chunk: list[T] = []
        for value in self.rows(values):
            chunk.append(value)
            if len(chunk) == CHECKPOINT_INTERVAL:
                chunks.append(tuple(sorted(chunk, key=key)))
                chunk.clear()
                self.check()
        if chunk:
            chunks.append(tuple(sorted(chunk, key=key)))
            self.check()
        if not chunks:
            return ()
        return tuple(self.rows(heapq.merge(*chunks, key=key)))


def legacy_rate_numerator(events: Iterable[Event], checkpoints: Checkpoints) -> int:
    """Negative control: derived rate incorrectly inherits raw-event permission."""
    return sum(
        1
        for event in checkpoints.rows(events)
        if Measure.EVENT in event.included_measures
    )


def candidate_rate_numerator(events: Iterable[Event], checkpoints: Checkpoints) -> int:
    """Candidate behavior: the derived rate uses its own inclusion permission."""
    return sum(
        1
        for event in checkpoints.rows(events)
        if Measure.RATE in event.included_measures
    )


def normalized_rate(
    events: Iterable[Event],
    active_seconds: int,
    checkpoints: Checkpoints,
) -> Fraction:
    if active_seconds <= 0:
        raise ValueError("active_seconds must be positive")
    numerator = candidate_rate_numerator(events, checkpoints)
    return Fraction(numerator * 100 * SECONDS_PER_DAY, active_seconds)


def legacy_observation_index(
    observations: Iterable[Observation],
    checkpoints: Checkpoints,
) -> dict[int, tuple[Observation, ...]]:
    """Negative control: no cancellation checks occur inside preprocessing."""
    grouped: dict[int, list[Observation]] = defaultdict(list)
    for row in observations:
        checkpoints.processed_rows += 1
        grouped[row.event_id].append(row)
    return {
        event_id: tuple(sorted(rows, key=lambda row: row.observation_id))
        for event_id, rows in grouped.items()
    }


def candidate_observation_index(
    observations: Iterable[Observation],
    checkpoints: Checkpoints,
) -> dict[int, tuple[Observation, ...]]:
    grouped: dict[int, list[Observation]] = defaultdict(list)
    for row in checkpoints.rows(observations):
        grouped[row.event_id].append(row)

    ordered_groups = checkpoints.sorted_values(
        grouped.items(),
        key=lambda item: item[0],
    )
    return {
        event_id: checkpoints.sorted_values(
            rows,
            key=lambda row: row.observation_id,
        )
        for event_id, rows in ordered_groups
    }
