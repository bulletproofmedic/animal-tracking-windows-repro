from __future__ import annotations

import hashlib
import json
import unicodedata
import warnings
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, Self
from uuid import UUID
from zoneinfo import ZoneInfo

WORK_BUDGET = 64
FILTER_LIMIT = 4096
ENTITY_ALIASES = {
    "EVENT": "EVENT",
    "ObservationEvent": "EVENT",
    "SPECIES": "SPECIES",
    "Species": "SPECIES",
    "CONFIGURATION_INTERVAL": "CONFIGURATION_INTERVAL",
    "CameraConfigurationInterval": "CONFIGURATION_INTERVAL",
}
RESULT_REGISTRY = {
    "measure_event": ("EVENT", "integer", False, "events"),
    "measure_rate": ("RATE", "decimal_string", True, "events_per_100_active_camera_days"),
}


class ValidationError(ValueError):
    pass


class Cancelled(RuntimeError):
    pass


class EventStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    VOID = "VOID"


class CountClass(StrEnum):
    EXACT = "EXACT"
    UNKNOWN = "UNKNOWN"


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        raise ValidationError("binary float prohibited")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Decimal):
        rendered = format(value, "f").rstrip("0").rstrip(".")
        return rendered or "0"
    if isinstance(value, UUID):
        return str(value).lower()
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize({field.name: getattr(value, field.name) for field in fields(value)})
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | memoryview):
        return [_normalize(item) for item in value]
    raise ValidationError(f"unsupported canonical value: {type(value).__name__}")


def freeze(value: Any) -> Any:
    normalized = _normalize(value)
    if isinstance(normalized, dict):
        return MappingProxyType({key: freeze(item) for key, item in normalized.items()})
    if isinstance(normalized, list):
        return tuple(freeze(item) for item in normalized)
    return normalized


def validate_filter(value: Mapping[str, Any]) -> Mapping[str, Any]:
    allowed = {
        "event_ids",
        "event_statuses",
        "count_classes",
        "include_unresolved",
        "start_date",
        "end_date",
        "start_instant",
        "end_instant",
    }
    if set(value) - allowed:
        raise ValidationError("unknown filter key")
    if "event_ids" in value:
        raw = value["event_ids"]
        if not isinstance(raw, list) or not 1 <= len(raw) <= FILTER_LIMIT:
            raise ValidationError("invalid id collection")
        parsed = [str(UUID(item)).lower() for item in raw if isinstance(item, str)]
        if len(parsed) != len(raw) or parsed != raw or parsed != sorted(set(parsed)):
            raise ValidationError("ids must be canonical unique sorted UUIDs")
    for key, enum in (("event_statuses", EventStatus), ("count_classes", CountClass)):
        if key in value:
            raw = value[key]
            allowed_values = {item.value for item in enum}
            if (
                not isinstance(raw, list)
                or not raw
                or any(item not in allowed_values for item in raw)
                or raw != sorted(set(raw))
            ):
                raise ValidationError("invalid enum collection")
    if "include_unresolved" in value and not isinstance(value["include_unresolved"], bool):
        raise ValidationError("boolean flag required")
    for lower_name, upper_name, parser in (("start_date", "end_date", date.fromisoformat),):
        present = (lower_name in value, upper_name in value)
        if present[0] != present[1]:
            raise ValidationError("paired bounds required")
        if present[0]:
            lower_raw, upper_raw = value[lower_name], value[upper_name]
            if not isinstance(lower_raw, str) or not isinstance(upper_raw, str):
                raise ValidationError("date text required")
            try:
                lower, upper = parser(lower_raw), parser(upper_raw)
            except ValueError as exc:
                raise ValidationError("canonical date required") from exc
            if lower.isoformat() != lower_raw or upper.isoformat() != upper_raw or lower >= upper:
                raise ValidationError("nonempty canonical half-open bounds required")
    instant_present = ("start_instant" in value, "end_instant" in value)
    if instant_present[0] != instant_present[1]:
        raise ValidationError("paired instant bounds required")
    if instant_present[0]:
        if "start_date" in value:
            raise ValidationError("one temporal family only")
        parsed = []
        for key in ("start_instant", "end_instant"):
            raw = value[key]
            if not isinstance(raw, str) or not raw.endswith("Z"):
                raise ValidationError("canonical UTC instant required")
            parsed.append(datetime.fromisoformat(raw[:-1] + "+00:00"))
        if parsed[0] >= parsed[1]:
            raise ValidationError("nonempty instant bounds required")
    return freeze(value)


def zone_candidates(local_value: datetime, zone_name: str) -> tuple[tuple[int, datetime], ...]:
    zone = ZoneInfo(zone_name)
    candidates: set[tuple[int, datetime]] = set()
    for fold in (0, 1):
        aware = local_value.replace(tzinfo=zone, fold=fold)
        offset = aware.utcoffset()
        if offset is None:
            continue
        utc_value = aware.astimezone(UTC)
        if utc_value.astimezone(zone).replace(tzinfo=None) == local_value:
            candidates.add((int(offset.total_seconds()), utc_value))
    return tuple(sorted(candidates))


def validate_resolved_time(
    local_value: datetime,
    zone_name: str,
    offset_seconds: int,
    utc_value: datetime,
) -> None:
    candidates = zone_candidates(local_value, zone_name)
    if not candidates:
        raise ValidationError("nonexistent local wall time")
    if (offset_seconds, utc_value.astimezone(UTC)) not in candidates:
        raise ValidationError("selected fold does not round-trip")


@dataclass(frozen=True)
class TypedRef:
    entity_type: str
    record_id: UUID
    revision: int

    def __post_init__(self) -> None:
        try:
            canonical = ENTITY_ALIASES[self.entity_type]
        except KeyError as exc:
            raise ValidationError("unknown entity type") from exc
        object.__setattr__(self, "entity_type", canonical)


@dataclass(frozen=True)
class Configuration:
    record_id: UUID
    revision: int
    deployment_id: UUID
    start: datetime
    end: datetime | None


@dataclass(frozen=True)
class WarningRef:
    references: tuple[TypedRef, ...]


@dataclass(frozen=True)
class Dataset:
    events: tuple[TypedRef, ...]
    species: tuple[TypedRef, ...]
    configurations: tuple[Configuration, ...]
    warnings: tuple[WarningRef, ...]

    def __post_init__(self) -> None:
        for name, rows in (("event", self.events), ("species", self.species)):
            identities = tuple((row.entity_type, row.record_id, row.revision) for row in rows)
            if len(identities) != len(set(identities)):
                raise ValidationError(f"duplicate {name} identity")
        config_ids = tuple((row.record_id, row.revision) for row in self.configurations)
        if len(config_ids) != len(set(config_ids)):
            raise ValidationError("duplicate configuration identity")
        grouped: dict[UUID, list[Configuration]] = {}
        for row in self.configurations:
            grouped.setdefault(row.deployment_id, []).append(row)
        for rows in grouped.values():
            terminal = False
            for row in sorted(rows, key=lambda item: item.start):
                if terminal:
                    raise ValidationError("open-ended configuration must be terminal")
                terminal = row.end is None
        known = {
            (row.entity_type, row.record_id, row.revision)
            for row in (*self.events, *self.species)
        } | {
            ("CONFIGURATION_INTERVAL", row.record_id, row.revision)
            for row in self.configurations
        }
        for warning in self.warnings:
            refs = tuple((row.entity_type, row.record_id, row.revision) for row in warning.references)
            if len(refs) != len(set(refs)) or any(ref not in known for ref in refs):
                raise ValidationError("warning typed reference does not resolve")


@dataclass(frozen=True)
class ResultRow:
    row_key: Mapping[str, Any]
    values: tuple[Any, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "row_key", freeze(self.row_key))
        object.__setattr__(self, "values", tuple(freeze(item) for item in self.values))


@dataclass(frozen=True)
class ResultTable:
    table_id: str
    title_key: str
    logical_type: str
    nullable: bool
    unit: str

    def __post_init__(self) -> None:
        try:
            measure, logical_type, nullable, unit = RESULT_REGISTRY[self.table_id]
        except KeyError as exc:
            raise ValidationError("unregistered table") from exc
        if (
            self.title_key != f"analysis.table.{measure.lower()}"
            or self.logical_type != logical_type
            or self.nullable is not nullable
            or self.unit != unit
        ):
            raise ValidationError("result schema does not match registry")


@dataclass(frozen=True)
class SourceState:
    project_id: UUID
    epoch_id: UUID
    state_id: UUID

    def is_current_against(self, state_id: UUID) -> bool:
        warnings.warn("identity-only comparison is deprecated", DeprecationWarning, stacklevel=2)
        return self.state_id == state_id

    def is_current_against_ref(self, current: Self) -> bool:
        return (
            isinstance(current, SourceState)
            and self.project_id == current.project_id
            and self.epoch_id == current.epoch_id
            and self.state_id == current.state_id
        )


class Snapshot(Protocol):
    source_state: SourceState

    def rows(self) -> Iterable[TypedRef]: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, exc_type, exc_value, traceback) -> bool | None: ...


class Repository(Protocol):
    def open_snapshot(self) -> Snapshot: ...


def build_from_snapshot(repository: Repository) -> tuple[SourceState, tuple[TypedRef, ...]]:
    with repository.open_snapshot() as snapshot:
        initial = snapshot.source_state
        rows = tuple(snapshot.rows())
        final = snapshot.source_state
        if not initial.is_current_against_ref(final):
            raise ValidationError("source state changed during snapshot")
    return initial, rows


class Checkpoints:
    def __init__(self, token: Any) -> None:
        self.token = token
        self.pending = 0

    def consume(self, units: int = 1) -> None:
        self.pending += units
        if self.pending >= WORK_BUDGET:
            self.token.raise_if_cancelled()
            self.pending = 0

    def check(self) -> None:
        self.token.raise_if_cancelled()


def cancellable_hash(value: Any, checkpoints: Checkpoints) -> str:
    hasher = hashlib.sha256()

    def walk(item: Any) -> None:
        checkpoints.consume()
        if isinstance(item, Mapping):
            hasher.update(b"{")
            for key in sorted(item):
                walk(str(key))
                walk(item[key])
            hasher.update(b"}")
        elif isinstance(item, Sequence) and not isinstance(item, str | bytes | bytearray):
            hasher.update(b"[")
            for child in item:
                walk(child)
            hasher.update(b"]")
        else:
            data = json.dumps(_normalize(item), sort_keys=True, separators=(",", ":")).encode()
            for start in range(0, len(data), 65536):
                hasher.update(data[start : start + 65536])
                checkpoints.check()

    walk(value)
    checkpoints.check()
    return hasher.hexdigest()


class ContractClass:
    __hardened_identity__: tuple[str, str] | None = None


class ContractModule:
    def __init__(self) -> None:
        self.Request = type("Request", (ContractClass,), {})

    def reload(self) -> None:
        self.Request = type("Request", (ContractClass,), {})
        install(self)


def install(module: ContractModule) -> None:
    module.Request.__hardened_identity__ = (module.Request.__module__, module.Request.__qualname__)


def assert_installed(module: ContractModule) -> None:
    expected = (module.Request.__module__, module.Request.__qualname__)
    if module.Request.__hardened_identity__ != expected:
        raise ValidationError("current contract class is not hardened")
