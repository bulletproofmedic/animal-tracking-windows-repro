from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence

ACCEPTED = "ACCEPTED"
DEFAULT_EVENT_STATUSES = (ACCEPTED,)
MAX_EVENTS = 10_000
MAX_OBSERVATIONS = 100_000
MAX_BYTES = 64 * 1024 * 1024


class PopulationLimitExceeded(ValueError):
    pass


class SourceStateChanged(RuntimeError):
    pass


class ConstructionFailed(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    source_state_id: str
    analysis_revision: int


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    status: str
    species_id: str
    species_code: str
    species_label: str
    species_unknown: bool
    direction: str
    direction_source: str
    count_value: int
    count_classification: str


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    status: str
    capture_time: str
    observations: tuple[Observation, ...]


def normalize_statuses(statuses: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(statuses)) or DEFAULT_EVENT_STATUSES


def accepted_matching(
    event: Event,
    *,
    species_ids: frozenset[str] = frozenset(),
    directions: frozenset[str] = frozenset(),
) -> tuple[Observation, ...]:
    rows = tuple(row for row in event.observations if row.status == ACCEPTED)
    if species_ids:
        rows = tuple(row for row in rows if row.species_id in species_ids)
    if directions:
        rows = tuple(row for row in rows if row.direction in directions)
    return tuple(sorted(rows, key=lambda row: row.observation_id))


def selected_events(
    events: Sequence[Event], statuses: Sequence[str]
) -> tuple[Event, ...]:
    normalized = frozenset(normalize_statuses(statuses))
    return tuple(row for row in events if row.status in normalized)


def enforce_bounds(events: Sequence[Event], observation_count: int) -> None:
    if len(events) > MAX_EVENTS:
        raise PopulationLimitExceeded("event population exceeds bound")
    if observation_count > MAX_OBSERVATIONS:
        raise PopulationLimitExceeded("accepted observation population exceeds bound")


def bound_snapshot(
    before: SourceSnapshot | None, after: SourceSnapshot | None
) -> SourceSnapshot:
    if before is None or after is None:
        raise SourceStateChanged("an exact current SourceState is required")
    if before != after:
        raise SourceStateChanged("source state changed")
    return before


def canonical_event(event: Event) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "status": event.status,
        "capture_time": event.capture_time,
        "observations": [asdict(row) for row in accepted_matching(event)],
    }


def report_input_sha256(
    events: Sequence[Event],
    *,
    statuses: Sequence[str],
    before: SourceSnapshot | None,
    after: SourceSnapshot | None,
) -> str:
    snapshot = bound_snapshot(before, after)
    selected = selected_events(events, statuses)
    observation_count = sum(len(accepted_matching(event)) for event in selected)
    enforce_bounds(selected, observation_count)
    payload = {
        "schema_version": "1.1.0",
        "statuses": sorted(normalize_statuses(statuses)),
        "snapshot": asdict(snapshot),
        "events": [
            canonical_event(event)
            for event in sorted(selected, key=lambda row: row.event_id)
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def staged_snapshot_validation(
    before: SourceSnapshot | None,
    snapshots: Sequence[SourceSnapshot | None],
) -> None:
    if before is None:
        raise SourceStateChanged("an exact current SourceState is required")
    for snapshot in snapshots:
        bound_snapshot(before, snapshot)


def csv_spool(
    fieldnames: Sequence[str],
    rows: Iterable[dict[str, object]],
    *,
    spool_factory: object = tempfile.SpooledTemporaryFile,
) -> tuple[bytes, int, str]:
    try:
        stream = spool_factory(max_size=1024 * 1024, mode="w+b")
    except OSError as exc:
        raise ConstructionFailed("no partial download was produced") from exc
    text = io.TextIOWrapper(stream, encoding="utf-8", newline="", write_through=True)
    count = 0
    try:
        writer = csv.DictWriter(text, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})
            count += 1
            text.flush()
            if stream.tell() > MAX_BYTES:
                raise PopulationLimitExceeded("CSV byte bound exceeded")
        text.flush()
        text.detach()
        stream.seek(0)
        content = stream.read()
        return content, count, hashlib.sha256(content).hexdigest()
    except BaseException:
        try:
            text.detach()
        except (ValueError, OSError):
            pass
        stream.close()
        raise
    finally:
        stream.close()


def exact_blob_manifest_rejects(
    expected: dict[str, str],
    actual: dict[str, str],
) -> bool:
    return expected != actual
