from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from animal_tracking.reporting.semantics import (
    ExposureIntervalValue,
    events_per_100_active_camera_days,
    season_bucket,
    summarize_exposure,
)

ZONE = ZoneInfo("America/Toronto")


@pytest.mark.parametrize(
    ("value", "key", "label"),
    [
        (datetime(2025, 12, 1, tzinfo=ZONE), "2025-2026-WINTER", "Winter 2025–2026"),
        (datetime(2026, 1, 1, tzinfo=ZONE), "2025-2026-WINTER", "Winter 2025–2026"),
        (datetime(2026, 2, 28, tzinfo=ZONE), "2025-2026-WINTER", "Winter 2025–2026"),
        (datetime(2024, 2, 29, tzinfo=ZONE), "2023-2024-WINTER", "Winter 2023–2024"),
        (datetime(2026, 3, 1, tzinfo=ZONE), "2026-SPRING", "Spring 2026"),
        (datetime(2026, 6, 1, tzinfo=ZONE), "2026-SUMMER", "Summer 2026"),
        (datetime(2026, 9, 1, tzinfo=ZONE), "2026-AUTUMN", "Autumn 2026"),
    ],
)
def test_meteorological_season_boundaries(
    value: datetime,
    key: str,
    label: str,
) -> None:
    bucket = season_bucket(value)
    assert bucket.key == key
    assert bucket.label == label


def test_exposure_summary_classifies_gaps_overlap_and_states() -> None:
    start = datetime(2026, 7, 20, tzinfo=ZONE)
    end = start + timedelta(hours=8)
    intervals = (
        ExposureIntervalValue(
            record_id="1",
            revision=1,
            start=start,
            end=start + timedelta(hours=2),
            start_precision="EXACT",
            end_precision="EXACT",
            state="ACTIVE",
        ),
        ExposureIntervalValue(
            record_id="2",
            revision=1,
            start=start + timedelta(hours=1),
            end=start + timedelta(hours=3),
            start_precision="EXACT",
            end_precision="EXACT",
            state="OFFLINE",
        ),
        ExposureIntervalValue(
            record_id="3",
            revision=2,
            start=start + timedelta(hours=4),
            end=start + timedelta(hours=5),
            start_precision="EXACT",
            end_precision="EXACT",
            state="MAINTENANCE",
        ),
        ExposureIntervalValue(
            record_id="4",
            revision=1,
            start=start + timedelta(hours=5),
            end=None,
            start_precision="EXACT",
            end_precision="UNKNOWN",
            state="ACTIVE",
        ),
    )

    summary = summarize_exposure(intervals, window_start=start, window_end=end)

    assert summary.verified_active_seconds == 60 * 60
    assert summary.offline_seconds == 60 * 60
    assert summary.maintenance_seconds == 60 * 60
    assert summary.conflicting_overlap_seconds == 60 * 60
    assert summary.unknown_seconds == 5 * 60 * 60
    assert summary.unknown_interval_count == 1


def test_exposure_overlap_with_same_state_is_not_double_counted() -> None:
    start = datetime(2026, 7, 20, tzinfo=ZONE)
    intervals = (
        ExposureIntervalValue(
            "1", 1, start, start + timedelta(hours=3), "EXACT", "EXACT", "ACTIVE"
        ),
        ExposureIntervalValue(
            "2",
            1,
            start + timedelta(hours=1),
            start + timedelta(hours=2),
            "EXACT",
            "EXACT",
            "ACTIVE",
        ),
    )
    summary = summarize_exposure(
        intervals,
        window_start=start,
        window_end=start + timedelta(hours=3),
    )
    assert summary.verified_active_seconds == 3 * 60 * 60
    assert summary.unknown_seconds == 0
    assert summary.conflicting_overlap_seconds == 0


def test_normalized_rate_uses_exact_six_decimal_rounding_and_zero_is_null() -> None:
    assert events_per_100_active_camera_days(3, 86_400) == "300.000000"
    assert events_per_100_active_camera_days(1, 43_200) == "200.000000"
    assert events_per_100_active_camera_days(1, 0) is None
    with pytest.raises(ValueError):
        events_per_100_active_camera_days(-1, 86_400)
