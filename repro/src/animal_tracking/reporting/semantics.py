from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from itertools import pairwise
from typing import Final, Iterable

SEASON_DEFINITION_VERSION: Final[str] = "AT-SEASONS-METEOROLOGICAL-NORTH-1"
EXPOSURE_POLICY_VERSION: Final[str] = "AT-EXPOSURE-FINAL-INTERVALS-1"
SECONDS_PER_DAY: Final[int] = 86_400
RATE_SCALE: Final[Decimal] = Decimal("0.000001")


@dataclass(frozen=True, slots=True)
class ExposureIntervalValue:
    record_id: str
    revision: int
    start: datetime | None
    end: datetime | None
    start_precision: str
    end_precision: str
    state: str


@dataclass(frozen=True, slots=True)
class ExposureSummary:
    verified_active_seconds: int
    offline_seconds: int
    maintenance_seconds: int
    unknown_seconds: int
    unknown_interval_count: int
    conflicting_overlap_seconds: int

    @property
    def verified_active_days(self) -> str:
        with localcontext() as context:
            context.prec = 28
            context.rounding = ROUND_HALF_EVEN
            value = Decimal(self.verified_active_seconds) / Decimal(SECONDS_PER_DAY)
            return format(value.quantize(RATE_SCALE), "f")


@dataclass(frozen=True, slots=True)
class SeasonBucket:
    key: str
    label: str


def season_bucket(value: datetime) -> SeasonBucket:
    """Return the frozen northern-hemisphere meteorological season bucket."""

    month = value.month
    year = value.year
    if month == 12:
        return SeasonBucket(
            key=f"{year}-{year + 1}-WINTER",
            label=f"Winter {year}–{year + 1}",
        )
    if month in {1, 2}:
        return SeasonBucket(
            key=f"{year - 1}-{year}-WINTER",
            label=f"Winter {year - 1}–{year}",
        )
    if month in {3, 4, 5}:
        return SeasonBucket(key=f"{year}-SPRING", label=f"Spring {year}")
    if month in {6, 7, 8}:
        return SeasonBucket(key=f"{year}-SUMMER", label=f"Summer {year}")
    return SeasonBucket(key=f"{year}-AUTUMN", label=f"Autumn {year}")


def events_per_100_active_camera_days(
    event_count: int,
    verified_active_seconds: int,
) -> str | None:
    """Calculate the canonical six-decimal exposure-normalized event rate."""

    if event_count < 0:
        raise ValueError("Event count cannot be negative.")
    if verified_active_seconds <= 0:
        return None
    with localcontext() as context:
        context.prec = 28
        context.rounding = ROUND_HALF_EVEN
        active_days = Decimal(verified_active_seconds) / Decimal(SECONDS_PER_DAY)
        value = Decimal(event_count) * Decimal(100) / active_days
        return format(value.quantize(RATE_SCALE), "f")


def summarize_exposure(
    intervals: Iterable[ExposureIntervalValue],
    *,
    window_start: datetime,
    window_end: datetime,
) -> ExposureSummary:
    """Summarize FINAL operational intervals without double counting.

    Exact intervals are normalized to UTC and clipped to the half-open report
    window. Gaps, exact intervals with unknown states, and overlaps containing
    conflicting states are classified as unknown time. Intervals without exact
    usable bounds are counted but do not invent a duration.
    """

    if window_start.tzinfo is None or window_end.tzinfo is None:
        raise ValueError("Exposure window bounds must be timezone-aware.")
    window_start = window_start.astimezone(UTC)
    window_end = window_end.astimezone(UTC)
    if window_end <= window_start:
        raise ValueError("Exposure window end must follow its start.")

    usable: list[tuple[datetime, datetime, str]] = []
    unknown_interval_count = 0
    for interval in intervals:
        if (
            interval.start is None
            or interval.end is None
            or interval.start.tzinfo is None
            or interval.end.tzinfo is None
            or interval.start_precision != "EXACT"
            or interval.end_precision != "EXACT"
        ):
            unknown_interval_count += 1
            continue
        interval_start = interval.start.astimezone(UTC)
        interval_end = interval.end.astimezone(UTC)
        if interval_end <= interval_start:
            unknown_interval_count += 1
            continue
        start = max(interval_start, window_start)
        end = min(interval_end, window_end)
        if end <= start:
            continue
        usable.append((start, end, interval.state.upper()))

    boundaries = {window_start, window_end}
    for start, end, _state in usable:
        boundaries.add(start)
        boundaries.add(end)
    ordered_boundaries = sorted(boundaries)

    active_seconds = 0
    offline_seconds = 0
    maintenance_seconds = 0
    unknown_seconds = 0
    conflicting_overlap_seconds = 0

    for start, end in pairwise(ordered_boundaries):
        seconds = int((end - start).total_seconds())
        if seconds <= 0:
            continue
        states = {
            state
            for interval_start, interval_end, state in usable
            if interval_start < end and interval_end > start
        }
        if not states:
            unknown_seconds += seconds
        elif len(states) > 1:
            unknown_seconds += seconds
            conflicting_overlap_seconds += seconds
        else:
            state = next(iter(states))
            if state == "ACTIVE":
                active_seconds += seconds
            elif state == "OFFLINE":
                offline_seconds += seconds
            elif state == "MAINTENANCE":
                maintenance_seconds += seconds
            else:
                unknown_seconds += seconds

    return ExposureSummary(
        verified_active_seconds=active_seconds,
        offline_seconds=offline_seconds,
        maintenance_seconds=maintenance_seconds,
        unknown_seconds=unknown_seconds,
        unknown_interval_count=unknown_interval_count,
        conflicting_overlap_seconds=conflicting_overlap_seconds,
    )
