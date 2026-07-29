from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence

ACCEPTED = "ACCEPTED"
COUNT_CLASSES = ("EXACT", "MINIMUM", "ESTIMATED", "UNKNOWN")
EVENT_SCHEMA = (
    "event_id",
    "status",
    "site",
    "source_state_id",
    "analysis_revision",
)
OBSERVATION_SCHEMA = (
    "observation_id",
    "event_id",
    "status",
    "species",
    "direction",
    "count_value",
    "count_classification",
    "source_state_id",
    "analysis_revision",
)
MAX_REPORT_EVENTS = 5_000
MAX_EXPORT_EVENTS = 10_000


class InvalidQuery(ValueError):
    pass


class PopulationLimitExceeded(ValueError):
    pass


class SourceStateChanged(RuntimeError):
    pass


class UnsupportedComparison(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    source_state_id: str
    analysis_revision: int


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    status: str
    species: str
    direction: str
    count_value: int
    count_classification: str


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    status: str
    site: str
    observations: tuple[Observation, ...]


@dataclass(frozen=True, slots=True)
class CountBreakdown:
    exact: int = 0
    minimum: int = 0
    estimated: int = 0
    unknown: int = 0


@dataclass(frozen=True, slots=True)
class SearchResult:
    event_id: str
    species: tuple[str, ...]
    directions: tuple[str, ...]
    counts: CountBreakdown
    excluded_nonaccepted_rows: int


def validate_query(*, start: int | None, end: int | None) -> None:
    if start is not None and end is not None and end < start:
        raise InvalidQuery("The query was not run because the end precedes the start.")


def accepted_matching_observations(
    event: Event,
    *,
    species: frozenset[str] = frozenset(),
    directions: frozenset[str] = frozenset(),
) -> tuple[Observation, ...]:
    rows = tuple(row for row in event.observations if row.status == ACCEPTED)
    if species:
        rows = tuple(row for row in rows if row.species in species)
    if directions:
        rows = tuple(row for row in rows if row.direction in directions)
    return tuple(sorted(rows, key=lambda row: row.observation_id))


def event_matches(
    event: Event,
    *,
    species: frozenset[str] = frozenset(),
    directions: frozenset[str] = frozenset(),
) -> bool:
    return bool(
        accepted_matching_observations(event, species=species, directions=directions)
    )


def classified_counts(rows: Iterable[Observation]) -> CountBreakdown:
    values = {name: 0 for name in COUNT_CLASSES}
    for row in rows:
        classification = row.count_classification
        if classification not in values:
            classification = "UNKNOWN"
        values[classification] += row.count_value
    return CountBreakdown(
        exact=values["EXACT"],
        minimum=values["MINIMUM"],
        estimated=values["ESTIMATED"],
        unknown=values["UNKNOWN"],
    )


def project_event(
    event: Event,
    *,
    species: frozenset[str] = frozenset(),
    directions: frozenset[str] = frozenset(),
) -> SearchResult:
    matching = accepted_matching_observations(
        event, species=species, directions=directions
    )
    excluded = sum(row.status != ACCEPTED for row in event.observations)
    return SearchResult(
        event_id=event.event_id,
        species=tuple(sorted({row.species for row in matching})),
        directions=tuple(sorted({row.direction for row in matching})),
        counts=classified_counts(matching),
        excluded_nonaccepted_rows=excluded,
    )


def paginate(events: Sequence[Event], *, page: int, page_size: int) -> tuple[Event, ...]:
    if page < 1 or page_size < 1:
        raise ValueError("page and page_size must be positive")
    start = (page - 1) * page_size
    return tuple(events[start : start + page_size])


def enforce_population_limit(count: int, *, operation: str) -> None:
    limit = MAX_REPORT_EVENTS if operation == "report" else MAX_EXPORT_EVENTS
    if count > limit:
        raise PopulationLimitExceeded(
            f"{operation} population {count} exceeds the supported bound {limit}"
        )


def bind_snapshot(before: SourceSnapshot, after: SourceSnapshot) -> SourceSnapshot:
    if before != after:
        raise SourceStateChanged("Source state changed while output was generated")
    return before


def event_report(
    events: Sequence[Event],
    *,
    group_by: str,
    snapshot_before: SourceSnapshot,
    snapshot_after: SourceSnapshot,
) -> tuple[dict[str, int], str]:
    enforce_population_limit(len(events), operation="report")
    snapshot = bind_snapshot(snapshot_before, snapshot_after)
    if group_by in {"species", "direction"}:
        raise UnsupportedComparison(
            "Event-level child-derived groupings are not valid partitions"
        )
    if group_by not in {"site", "status"}:
        raise ValueError(f"unsupported grouping: {group_by}")
    buckets: dict[str, int] = {}
    for event in sorted(events, key=lambda row: row.event_id):
        key = event.site if group_by == "site" else event.status
        buckets[key] = buckets.get(key, 0) + 1
    ordered = {key: buckets[key] for key in sorted(buckets)}
    payload = {
        "buckets": ordered,
        "source_state_id": snapshot.source_state_id,
        "analysis_revision": snapshot.analysis_revision,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ordered, digest


def exposure_comparison(*, normalized_exposure_available: bool) -> None:
    if not normalized_exposure_available:
        raise UnsupportedComparison(
            "Site/deployment comparison requires verified active-exposure denominators"
        )


def csv_bytes(fieldnames: Sequence[str], rows: Iterable[dict[str, object]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    return stream.getvalue().encode("utf-8")


def export_csv(
    events: Sequence[Event],
    *,
    snapshot_before: SourceSnapshot,
    snapshot_after: SourceSnapshot,
) -> tuple[bytes, bytes]:
    enforce_population_limit(len(events), operation="export")
    snapshot = bind_snapshot(snapshot_before, snapshot_after)
    event_rows: list[dict[str, object]] = []
    observation_rows: list[dict[str, object]] = []
    for event in sorted(events, key=lambda row: row.event_id):
        accepted = accepted_matching_observations(event)
        event_rows.append(
            {
                "event_id": event.event_id,
                "status": event.status,
                "site": event.site,
                "source_state_id": snapshot.source_state_id,
                "analysis_revision": snapshot.analysis_revision,
            }
        )
        for row in accepted:
            observation_rows.append(
                {
                    "observation_id": row.observation_id,
                    "event_id": event.event_id,
                    "status": row.status,
                    "species": row.species,
                    "direction": row.direction,
                    "count_value": row.count_value,
                    "count_classification": row.count_classification,
                    "source_state_id": snapshot.source_state_id,
                    "analysis_revision": snapshot.analysis_revision,
                }
            )
    observation_rows.sort(key=lambda row: str(row["observation_id"]))
    return (
        csv_bytes(EVENT_SCHEMA, event_rows),
        csv_bytes(OBSERVATION_SCHEMA, observation_rows),
    )


def canonical_result_payload(result: SearchResult) -> str:
    return json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
