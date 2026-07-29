from __future__ import annotations

import hashlib
import heapq
import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, Self
from uuid import UUID

CHECKPOINT_INTERVAL = 64


class ValidationError(ValueError):
    pass


class Cancelled(RuntimeError):
    pass


class Disposition(StrEnum):
    INCLUDED = "INCLUDED"
    PARTIAL = "PARTIAL"
    EXCLUDED = "EXCLUDED"


class ExposureDisposition(StrEnum):
    USABLE = "USABLE"
    PARTIAL = "PARTIAL"
    UNUSABLE = "UNUSABLE"


class Measure(StrEnum):
    EVENT = "EVENT"
    RATE = "EVENTS_PER_100_ACTIVE_CAMERA_DAYS"


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValidationError("nonfinite decimal")
        rendered = format(value, "f").rstrip("0").rstrip(".")
        return rendered or "0"
    if isinstance(value, UUID):
        return str(value).lower()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.isoformat()
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {key: _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple | list):
        return [_normalize(item) for item in value]
    raise ValidationError(f"unsupported canonical value: {type(value).__name__}")


def _freeze(value: Any) -> Any:
    normalized = _normalize(value)
    if isinstance(normalized, dict):
        return MappingProxyType({key: _freeze(item) for key, item in normalized.items()})
    if isinstance(normalized, list):
        return tuple(_freeze(item) for item in normalized)
    return normalized


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class SourceState:
    project_id: UUID
    epoch_id: UUID
    state_id: UUID

    def is_current_against(self, current: Self) -> bool:
        if not isinstance(current, SourceState):
            raise ValidationError("qualified source state required")
        return (
            self.project_id == current.project_id
            and self.epoch_id == current.epoch_id
            and self.state_id == current.state_id
        )


@dataclass(frozen=True)
class Temporal:
    status: str
    precision: str
    local_value: datetime | None = None
    utc_value: datetime | None = None
    offset_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.precision in {"EXACT", "ESTIMATED"}:
            if self.status not in {"PARSED", "CORRECTED"}:
                raise ValidationError("groupable precision must be parsed or corrected")
            if self.local_value is None or self.utc_value is None or self.offset_seconds is None:
                raise ValidationError("groupable time is incomplete")
            resolved = self.local_value.replace(
                tzinfo=__import__("datetime").timezone(
                    __import__("datetime").timedelta(seconds=self.offset_seconds)
                )
            ).astimezone(UTC)
            if resolved != self.utc_value.astimezone(UTC):
                raise ValidationError("local, offset, and UTC values disagree")
        elif self.utc_value is not None or self.offset_seconds is not None:
            raise ValidationError("unresolved precision cannot claim a UTC instant")


@dataclass(frozen=True)
class Event:
    event_id: UUID
    revision: int
    deployment_id: UUID
    included_measures: tuple[Measure, ...]
    disposition: Disposition = Disposition.INCLUDED


@dataclass(frozen=True)
class Observation:
    observation_id: UUID
    revision: int
    event_id: UUID
    event_revision: int
    species_id: UUID
    species_revision: int
    disposition: Disposition = Disposition.INCLUDED


@dataclass(frozen=True)
class RevisionedDimension:
    record_id: UUID
    revision: int


@dataclass(frozen=True)
class Exposure:
    deployment_id: UUID
    deployment_revision: int
    start: Temporal
    end: Temporal
    active_seconds: int
    offline_seconds: int
    maintenance_seconds: int
    unknown_seconds: int
    denominator_seconds: int
    disposition: ExposureDisposition

    def __post_init__(self) -> None:
        if self.start.utc_value is None or self.end.utc_value is None:
            raise ValidationError("exposure bounds must be resolved")
        duration = int((self.end.utc_value - self.start.utc_value).total_seconds())
        if duration <= 0:
            raise ValidationError("exposure must be a nonempty half-open interval")
        if (
            self.active_seconds
            + self.offline_seconds
            + self.maintenance_seconds
            + self.unknown_seconds
            != duration
        ):
            raise ValidationError("exposure seconds do not reconcile")
        if self.denominator_seconds > self.active_seconds:
            raise ValidationError("denominator exceeds active seconds")
        if self.disposition is ExposureDisposition.USABLE:
            if self.denominator_seconds <= 0 or self.unknown_seconds:
                raise ValidationError("usable exposure is not fully verified")
        if self.disposition is ExposureDisposition.UNUSABLE and self.denominator_seconds:
            raise ValidationError("unusable exposure must have zero denominator")


@dataclass(frozen=True)
class SelectionCounts:
    considered: int
    included: int
    partial: int
    excluded: int

    def __post_init__(self) -> None:
        if self.included + self.partial + self.excluded != self.considered:
            raise ValidationError("selection counts do not sum")


@dataclass(frozen=True)
class Dataset:
    request_filter: Mapping[str, Any]
    events: tuple[Event, ...]
    observations: tuple[Observation, ...]
    deployments: tuple[RevisionedDimension, ...]
    species: tuple[RevisionedDimension, ...]
    exposures: tuple[Exposure, ...]
    counts: SelectionCounts

    def __post_init__(self) -> None:
        unknown = set(self.request_filter) - {"site_ids", "deployment_ids", "species_ids"}
        if unknown:
            raise ValidationError(f"unknown filter keys: {sorted(unknown)}")
        object.__setattr__(self, "request_filter", _freeze(self.request_filter))
        object.__setattr__(
            self,
            "events",
            tuple(sorted(self.events, key=lambda row: (str(row.event_id), row.revision))),
        )
        object.__setattr__(
            self,
            "observations",
            tuple(
                sorted(
                    self.observations,
                    key=lambda row: (
                        str(row.event_id),
                        str(row.observation_id),
                        row.revision,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "deployments",
            tuple(sorted(self.deployments, key=lambda row: (str(row.record_id), row.revision))),
        )
        object.__setattr__(
            self,
            "species",
            tuple(sorted(self.species, key=lambda row: (str(row.record_id), row.revision))),
        )
        event_index = {row.event_id: row for row in self.events}
        deployment_index = {row.record_id: row for row in self.deployments}
        species_index = {row.record_id: row for row in self.species}
        if len(event_index) != len(self.events):
            raise ValidationError("duplicate event identity")
        for event in self.events:
            if event.deployment_id not in deployment_index:
                raise ValidationError("event has missing deployment")
        for row in self.observations:
            event = event_index.get(row.event_id)
            if event is None or event.revision != row.event_revision:
                raise ValidationError("observation has wrong event revision")
            species = species_index.get(row.species_id)
            if species is None or species.revision != row.species_revision:
                raise ValidationError("observation has wrong species revision")
        for exposure in self.exposures:
            deployment = deployment_index.get(exposure.deployment_id)
            if deployment is None or deployment.revision != exposure.deployment_revision:
                raise ValidationError("exposure has wrong deployment revision")
        rows = (*self.events, *self.observations)
        included = sum(row.disposition is Disposition.INCLUDED for row in rows)
        partial = sum(row.disposition is Disposition.PARTIAL for row in rows)
        excluded = sum(row.disposition is Disposition.EXCLUDED for row in rows)
        if self.counts != SelectionCounts(included + partial + excluded, included, partial, excluded):
            raise ValidationError("selection counts do not match graph")


class CancellationToken(Protocol):
    def raise_if_cancelled(self) -> None: ...


@dataclass
class Checkpoints:
    token: CancellationToken
    calls: int = 0
    rows_seen: int = 0

    def check(self) -> None:
        self.token.raise_if_cancelled()
        self.calls += 1

    def rows(self, values: Iterable[Any]) -> Iterable[Any]:
        for index, value in enumerate(values, 1):
            self.rows_seen += 1
            if index % CHECKPOINT_INTERVAL == 0:
                self.check()
            yield value

    def sorted_values(
        self,
        values: Iterable[Any],
        *,
        key: Callable[[Any], object],
    ) -> tuple[Any, ...]:
        chunks: list[tuple[Any, ...]] = []
        chunk: list[Any] = []
        for value in self.rows(values):
            chunk.append(value)
            if len(chunk) == CHECKPOINT_INTERVAL:
                chunks.append(tuple(sorted(chunk, key=key)))
                chunk.clear()
                self.check()
        if chunk:
            chunks.append(tuple(sorted(chunk, key=key)))
            self.check()
        return tuple(self.rows(heapq.merge(*chunks, key=key))) if chunks else ()


def rate_numerator(events: Iterable[Event], checkpoints: Checkpoints) -> int:
    return sum(
        1
        for event in checkpoints.rows(events)
        if event.disposition is not Disposition.EXCLUDED
        and Measure.RATE in event.included_measures
    )


def normalized_rate(events: Iterable[Event], active_seconds: int, checkpoints: Checkpoints) -> str | None:
    if active_seconds == 0:
        return None
    value = Decimal(rate_numerator(events, checkpoints)) * Decimal(100 * 86400) / Decimal(
        active_seconds
    )
    return format(value.quantize(Decimal("0.000001")), "f").rstrip("0").rstrip(".")


@dataclass(frozen=True)
class ResultColumn:
    column_id: str
    role: str
    logical_type: str
    nullable: bool
    semantic_key: str
    unit: str | None = None

    def __post_init__(self) -> None:
        combined = " ".join(
            item.casefold().replace("-", "_")
            for item in (self.column_id, self.semantic_key, self.unit or "")
        )
        prohibited = {"population", "occupancy", "confirmed_route", "speed"}
        if any(token in combined for token in prohibited):
            raise ValidationError("prohibited result meaning")
        if self.logical_type not in {"string", "integer", "decimal_string"}:
            raise ValidationError("unregistered logical type")
        if self.role == "MEASURE" and not self.unit:
            raise ValidationError("measure unit required")


@dataclass(frozen=True)
class ResultTable:
    table_id: str
    grouping_keys: tuple[str, ...]
    columns: tuple[ResultColumn, ...]
    rows: tuple[tuple[Mapping[str, Any], tuple[Any, ...]], ...]

    def __post_init__(self) -> None:
        if any(token in self.table_id for token in ("population", "confirmed_route", "speed")):
            raise ValidationError("prohibited table meaning")
        expected_keys = set(self.grouping_keys)
        for row_key, values in self.rows:
            if set(row_key) != expected_keys or len(values) != len(self.columns):
                raise ValidationError("row schema mismatch")
            for value, column in zip(values, self.columns, strict=True):
                if value is None and not column.nullable:
                    raise ValidationError("nonnullable value is null")
                if value is not None and column.logical_type == "integer" and (
                    isinstance(value, bool) or not isinstance(value, int)
                ):
                    raise ValidationError("integer type mismatch")
                if value is not None and column.logical_type == "decimal_string" and not isinstance(
                    value, str
                ):
                    raise ValidationError("decimal type mismatch")


class ReadSnapshot(Protocol):
    source_state: SourceState

    def events(self) -> Iterable[Event]: ...

    def observations(self) -> Iterable[Observation]: ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, *args: object) -> bool | None: ...


class Repository(Protocol):
    def open_snapshot(self, project_id: UUID) -> ReadSnapshot: ...
