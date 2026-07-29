$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# Sanitized public diagnostic for private remediation head:
# 3c2c6430243556c085525a3e36b5bc711035f0fa
#
# Scope: exact affected integrity/interval/validator/manifest logic with synthetic
# Django models and fixtures. No private history, data, media, configuration, or
# repository access is used. Passing here is diagnostic only and does not replace
# required validation of the exact private successor commit.

$work = Join-Path $env:RUNNER_TEMP "at-wal-003-pr47-repro"
if (Test-Path $work) {
    Remove-Item -Recurse -Force $work
}
New-Item -ItemType Directory -Force $work | Out-Null

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force $parent | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

Write-TextFile (Join-Path $work "pyproject.toml") @'
[tool.ruff]
target-version = "py313"
line-length = 100
src = ["src", "tests", "tools"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "S", "C4", "SIM", "RUF"]
ignore = ["S101", "E501", "UP046"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"

[tool.pytest.ini_options]
DJANGO_SETTINGS_MODULE = "animal_tracking.web.settings"
pythonpath = ["src"]
testpaths = ["tests"]
addopts = "--strict-config --strict-markers --disable-warnings --nomigrations"

[tool.mypy]
python_version = "3.13"
strict = true
mypy_path = "src"
ignore_missing_imports = true
'@

Write-TextFile (Join-Path $work "src/animal_tracking/__init__.py") ""
Write-TextFile (Join-Path $work "src/animal_tracking/domain/__init__.py") ""
Write-TextFile (Join-Path $work "src/animal_tracking/persistence/__init__.py") ""
Write-TextFile (Join-Path $work "src/animal_tracking/web/__init__.py") ""

Write-TextFile (Join-Path $work "src/animal_tracking/domain/observation_integrity.py") @'
from __future__ import annotations

from datetime import datetime

TERMINAL_EVENT_STATUSES = frozenset({"VOID", "DUPLICATE"})
ASSIGNMENT_STATUSES = frozenset({"MATCHED", "OVERRIDDEN", "UNRESOLVED"})
ASSIGNMENT_METHODS_BY_STATUS = {
    "MATCHED": frozenset(
        {
            "MANUAL_SELECTION",
            "TIMESTAMP_MATCH_CONFIRMED",
            "OCR_SUGGESTION_CONFIRMED",
            "IMPORTED_MAPPING",
            "OWNER_SELECTED",
        }
    ),
    "OVERRIDDEN": frozenset({"OVERRIDE", "OWNER_OVERRIDE"}),
    "UNRESOLVED": frozenset({"UNRESOLVED"}),
}
CAPTURE_TIME_RESOLUTIONS = frozenset({"PARSED", "CORRECTED", "AMBIGUOUS", "INVALID", "UNRESOLVED"})
UNRESOLVED_DIRECTIONS = frozenset({"UNKNOWN", "INDETERMINATE"})


class ObservationIntegrityError(ValueError):
    """Raised when an Observation aggregate would enter a contradictory state."""


def require_mutable_event_status(status: str, *, operation: str) -> None:
    if status in TERMINAL_EVENT_STATUSES:
        raise ObservationIntegrityError(
            f"Cannot {operation} while the Observation Event is {status}. "
            "Use an explicitly governed reopen or supersession workflow."
        )


def validate_assignment_state(
    *,
    assignment_status: str,
    assignment_method: str,
    deployment_id: object | None,
    assignment_override_reason: str,
) -> None:
    if assignment_status not in ASSIGNMENT_STATUSES:
        raise ObservationIntegrityError(f"Unsupported assignment status: {assignment_status}")
    allowed_methods = ASSIGNMENT_METHODS_BY_STATUS[assignment_status]
    if assignment_method not in allowed_methods:
        raise ObservationIntegrityError(
            f"Assignment method {assignment_method!r} is incompatible with "
            f"status {assignment_status!r}."
        )
    if assignment_status == "UNRESOLVED" and deployment_id is not None:
        raise ObservationIntegrityError("An unresolved Event cannot claim a Deployment assignment.")
    if assignment_status in {"MATCHED", "OVERRIDDEN"} and deployment_id is None:
        raise ObservationIntegrityError("A matched or overridden Event requires a Deployment.")
    if assignment_status == "OVERRIDDEN" and not assignment_override_reason.strip():
        raise ObservationIntegrityError("An overridden Deployment assignment requires a reason.")
    if assignment_status != "OVERRIDDEN" and assignment_override_reason.strip():
        raise ObservationIntegrityError(
            "An assignment override reason is valid only for an overridden assignment."
        )


def validate_capture_time_state(
    *,
    capture_time_local: datetime | None,
    capture_time_lower: datetime | None,
    capture_time_upper: datetime | None,
    capture_time_resolution: str,
) -> None:
    if capture_time_resolution not in CAPTURE_TIME_RESOLUTIONS:
        raise ObservationIntegrityError(
            f"Unsupported capture-time resolution: {capture_time_resolution}"
        )
    if capture_time_upper is not None and capture_time_lower is None:
        raise ObservationIntegrityError("A capture upper bound requires a lower bound.")
    if (
        capture_time_lower is not None
        and capture_time_upper is not None
        and capture_time_upper < capture_time_lower
    ):
        raise ObservationIntegrityError("The capture-time upper bound precedes the lower bound.")
    if capture_time_resolution in {"PARSED", "CORRECTED"} and capture_time_local is None:
        raise ObservationIntegrityError(
            f"Capture-time resolution {capture_time_resolution} requires a local time."
        )
    if capture_time_resolution == "AMBIGUOUS":
        if capture_time_lower is None or capture_time_upper is None:
            raise ObservationIntegrityError(
                "An ambiguous capture time requires lower and upper bounds."
            )
        if capture_time_upper <= capture_time_lower:
            raise ObservationIntegrityError(
                "An ambiguous capture-time range must have positive duration."
            )
    if capture_time_resolution in {"INVALID", "UNRESOLVED"} and capture_time_local is not None:
        raise ObservationIntegrityError(
            f"Capture-time resolution {capture_time_resolution} cannot claim a resolved local time."
        )


def validate_direction_state(*, direction_code: str, direction_source: str) -> None:
    if not direction_code:
        raise ObservationIntegrityError("A direction code is required.")
    if not direction_source:
        raise ObservationIntegrityError("A direction source is required.")
    if direction_code in UNRESOLVED_DIRECTIONS and direction_source != "UNRESOLVED":
        raise ObservationIntegrityError("An unresolved direction must use the UNRESOLVED source.")
    if direction_code not in UNRESOLVED_DIRECTIONS and direction_source == "UNRESOLVED":
        raise ObservationIntegrityError("A resolved direction cannot use the UNRESOLVED source.")
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/temporal.py") @'
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


class TemporalBoundsError(ValueError):
    """Raised when bounded temporal evidence is internally inconsistent."""


@dataclass(frozen=True, slots=True)
class TemporalBounds:
    lower: datetime | None
    upper: datetime | None = None
    precision: str = "UNKNOWN"

    def validate(self, *, required: bool = False) -> None:
        if required and self.lower is None:
            raise TemporalBoundsError("A lower temporal bound is required.")
        if self.upper is not None and self.lower is None:
            raise TemporalBoundsError("An upper bound cannot exist without a lower bound.")
        if self.lower is not None and self.upper is not None and self.upper < self.lower:
            raise TemporalBoundsError("The upper temporal bound precedes the lower bound.")

    @property
    def latest_possible(self) -> datetime | None:
        return self.upper or self.lower

    def overlaps(self, other: TemporalBounds) -> bool:
        self.validate(required=True)
        other.validate(required=True)
        self_end = self.latest_possible
        other_end = other.latest_possible
        assert self.lower is not None and other.lower is not None
        assert self_end is not None and other_end is not None
        return self.lower <= other_end and other.lower <= self_end
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/intervals.py") @'
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from django.db.models import Manager, Model, Q, QuerySet

from animal_tracking.domain.temporal import TemporalBounds


class HistoricalIntervalConflict(ValueError):
    """Raised when a final interval contradicts an existing final interval."""


def overlapping_final_intervals[ModelT: Model](
    source: Manager[ModelT] | QuerySet[ModelT],
    *,
    deployment_id: UUID,
    valid_from: TemporalBounds,
    valid_to: TemporalBounds,
    exclude_id: UUID | None = None,
) -> QuerySet[ModelT]:
    valid_from.validate(required=True)
    valid_to.validate()
    assert valid_from.lower is not None

    rows = source.all().filter(deployment_id=deployment_id, status="FINAL")
    if exclude_id is not None:
        rows = rows.exclude(pk=exclude_id)

    rows = rows.filter(Q(valid_to_lower__isnull=True) | Q(valid_to_lower__gt=valid_from.lower))

    if valid_to.latest_possible is not None:
        rows = rows.filter(valid_from_lower__lt=valid_to.latest_possible)
    return rows


def require_no_final_overlap[ModelT: Model](
    source: Manager[ModelT] | QuerySet[ModelT],
    *,
    deployment_id: UUID,
    valid_from: TemporalBounds,
    valid_to: TemporalBounds,
    exclude_id: UUID | None = None,
) -> None:
    if overlapping_final_intervals(
        source,
        deployment_id=deployment_id,
        valid_from=valid_from,
        valid_to=valid_to,
        exclude_id=exclude_id,
    ).exists():
        raise HistoricalIntervalConflict(
            "The final historical interval overlaps an existing final interval."
        )


def exact_interval(start: datetime, end: datetime) -> tuple[TemporalBounds, TemporalBounds]:
    if end <= start:
        raise HistoricalIntervalConflict(
            "An exact half-open interval requires its end to follow its start."
        )
    return TemporalBounds(start, precision="EXACT"), TemporalBounds(end, precision="EXACT")
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/sites.py") @'
class SpatialPositionDraft:
    pass


class CameraSiteCommand:
    pass


class CameraDeviceCommand:
    pass


class CameraRegistryService:
    pass
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/deployments.py") @'
class DeploymentCommand:
    pass


class DeploymentConflict(ValueError):
    pass


class DeploymentService:
    pass
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/observations.py") @'
class AnimalObservationDraft:
    pass


class ManualObservationEventCommand:
    pass


class ManualObservationService:
    pass
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/observation_actions.py") @'
class ObservationActionService:
    pass
'@

Write-TextFile (Join-Path $work "src/animal_tracking/domain/species_review.py") @'
class SpeciesReviewService:
    pass
'@

Write-TextFile (Join-Path $work "src/animal_tracking/persistence/apps.py") @'
from __future__ import annotations

from importlib import import_module

from django.apps import AppConfig


class PersistenceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "animal_tracking.persistence"

    def ready(self) -> None:
        import_module("animal_tracking.persistence.integrity_signals")
'@

Write-TextFile (Join-Path $work "src/animal_tracking/persistence/models.py") @'
from __future__ import annotations

import uuid

from django.db import models


class Property(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)


class Deployment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    property = models.ForeignKey(Property, on_delete=models.PROTECT)


class Species(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    common_name = models.CharField(max_length=255)
    code = models.CharField(max_length=64, unique=True)


class ObservationEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    property = models.ForeignKey(Property, on_delete=models.PROTECT)
    deployment = models.ForeignKey(Deployment, null=True, blank=True, on_delete=models.PROTECT)
    assignment_status = models.CharField(max_length=16)
    assignment_method = models.CharField(max_length=32)
    assignment_override_reason = models.TextField(blank=True)
    capture_time_local = models.DateTimeField(null=True, blank=True)
    capture_time_lower = models.DateTimeField(null=True, blank=True)
    capture_time_upper = models.DateTimeField(null=True, blank=True)
    capture_time_resolution = models.CharField(max_length=16, default="UNRESOLVED")
    status = models.CharField(max_length=16, default="DRAFT")
    analysis_exclusion_reason = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class AnimalObservation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    observation_event = models.ForeignKey(
        ObservationEvent,
        on_delete=models.PROTECT,
        related_name="animal_observations",
    )
    species = models.ForeignKey(Species, on_delete=models.PROTECT)
    count_value = models.PositiveIntegerField()
    count_classification = models.CharField(max_length=16)
    direction_code = models.CharField(max_length=16)
    direction_source = models.CharField(max_length=32)
    notes = models.TextField(blank=True)
    status = models.CharField(max_length=16, default="ACCEPTED")
    updated_at = models.DateTimeField(auto_now=True)


class MediaAsset(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    property = models.ForeignKey(Property, on_delete=models.PROTECT)
    lifecycle_status = models.CharField(max_length=32, default="STAGED")
    label = models.CharField(max_length=255)


class EventMedia(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    observation_event = models.ForeignKey(
        ObservationEvent,
        on_delete=models.PROTECT,
        related_name="media_links",
    )
    media_asset = models.ForeignKey(MediaAsset, on_delete=models.PROTECT)
    sequence_number = models.PositiveIntegerField()
    media_role = models.CharField(max_length=32)
    is_primary = models.BooleanField(default=False)
    attached_at = models.DateTimeField()
    removed_at = models.DateTimeField(null=True, blank=True)


class SyntheticInterval(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    deployment = models.ForeignKey(Deployment, on_delete=models.PROTECT)
    valid_from_lower = models.DateTimeField()
    valid_to_lower = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, default="FINAL")
'@

Write-TextFile (Join-Path $work "src/animal_tracking/persistence/integrity_signals.py") @'
from __future__ import annotations

from django.db.models import Max
from django.db.models.signals import pre_save
from django.dispatch import receiver

from animal_tracking.domain.observation_integrity import (
    TERMINAL_EVENT_STATUSES,
    ObservationIntegrityError,
    require_mutable_event_status,
    validate_assignment_state,
    validate_capture_time_state,
    validate_direction_state,
)
from animal_tracking.persistence.models import (
    AnimalObservation,
    EventMedia,
    ObservationEvent,
)


@receiver(
    pre_save,
    sender=ObservationEvent,
    dispatch_uid="animal_tracking.observation_event_integrity",
)
def validate_observation_event(
    sender: type[ObservationEvent],
    instance: ObservationEvent,
    **kwargs: object,
) -> None:
    del sender, kwargs
    if instance.status in TERMINAL_EVENT_STATUSES:
        return
    validate_assignment_state(
        assignment_status=instance.assignment_status,
        assignment_method=instance.assignment_method,
        deployment_id=instance.deployment_id,
        assignment_override_reason=instance.assignment_override_reason,
    )
    validate_capture_time_state(
        capture_time_local=instance.capture_time_local,
        capture_time_lower=instance.capture_time_lower,
        capture_time_upper=instance.capture_time_upper,
        capture_time_resolution=instance.capture_time_resolution,
    )


@receiver(
    pre_save,
    sender=AnimalObservation,
    dispatch_uid="animal_tracking.animal_observation_integrity",
)
def validate_animal_observation(
    sender: type[AnimalObservation],
    instance: AnimalObservation,
    **kwargs: object,
) -> None:
    del sender, kwargs
    event_status = (
        ObservationEvent.objects.only("status").get(pk=instance.observation_event_id).status
    )
    if instance.status != "VOID":
        require_mutable_event_status(event_status, operation="mutate an Animal Observation")
    validate_direction_state(
        direction_code=instance.direction_code,
        direction_source=instance.direction_source,
    )


@receiver(
    pre_save,
    sender=EventMedia,
    dispatch_uid="animal_tracking.event_media_integrity",
)
def validate_event_media(
    sender: type[EventMedia],
    instance: EventMedia,
    **kwargs: object,
) -> None:
    del sender, kwargs
    event = (
        ObservationEvent.objects.select_for_update()
        .only("status")
        .get(pk=instance.observation_event_id)
    )
    if instance.removed_at is None:
        require_mutable_event_status(event.status, operation="attach active media")
        if instance.media_asset.lifecycle_status != "MANAGED":
            raise ObservationIntegrityError(
                "Only MANAGED Media Assets may be attached as active Event media."
            )

    if instance._state.adding:
        maximum = (
            EventMedia.objects.filter(observation_event_id=instance.observation_event_id).aggregate(
                value=Max("sequence_number")
            )["value"]
            or 0
        )
        instance.sequence_number = maximum + 1
'@

Write-TextFile (Join-Path $work "src/animal_tracking/web/settings.py") @'
SECRET_KEY = "synthetic-public-reproducer"
INSTALLED_APPS = ["animal_tracking.persistence.apps.PersistenceConfig"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
MIGRATION_MODULES = {"persistence": None}
USE_TZ = True
TIME_ZONE = "UTC"
'@

Write-TextFile (Join-Path $work "tests/unit/test_observation_integrity.py") @'
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from animal_tracking.domain.intervals import (
    HistoricalIntervalConflict,
    exact_interval,
    overlapping_final_intervals,
)
from animal_tracking.domain.observation_integrity import (
    ObservationIntegrityError,
    require_mutable_event_status,
    validate_assignment_state,
    validate_capture_time_state,
    validate_direction_state,
)
from animal_tracking.domain.temporal import TemporalBounds
from animal_tracking.persistence.models import Deployment, Property, SyntheticInterval


def test_terminal_event_policy_rejects_active_child_mutation() -> None:
    with pytest.raises(ObservationIntegrityError, match="explicitly governed reopen"):
        require_mutable_event_status("VOID", operation="attach media")


def test_assignment_state_rejects_incompatible_method() -> None:
    with pytest.raises(ObservationIntegrityError, match="incompatible"):
        validate_assignment_state(
            assignment_status="MATCHED",
            assignment_method="UNRESOLVED",
            deployment_id=object(),
            assignment_override_reason="",
        )


def test_assignment_state_accepts_closed_valid_tuples() -> None:
    validate_assignment_state(
        assignment_status="MATCHED",
        assignment_method="MANUAL_SELECTION",
        deployment_id=object(),
        assignment_override_reason="",
    )
    validate_assignment_state(
        assignment_status="OVERRIDDEN",
        assignment_method="OWNER_OVERRIDE",
        deployment_id=object(),
        assignment_override_reason="documented correction",
    )
    validate_assignment_state(
        assignment_status="UNRESOLVED",
        assignment_method="UNRESOLVED",
        deployment_id=None,
        assignment_override_reason="",
    )


def test_capture_time_state_rejects_false_resolution() -> None:
    with pytest.raises(ObservationIntegrityError, match="requires a local time"):
        validate_capture_time_state(
            capture_time_local=None,
            capture_time_lower=None,
            capture_time_upper=None,
            capture_time_resolution="PARSED",
        )
    now = timezone.now()
    with pytest.raises(ObservationIntegrityError, match="positive duration"):
        validate_capture_time_state(
            capture_time_local=None,
            capture_time_lower=now,
            capture_time_upper=now,
            capture_time_resolution="AMBIGUOUS",
        )


def test_direction_state_requires_matching_provenance() -> None:
    validate_direction_state(direction_code="UNKNOWN", direction_source="UNRESOLVED")
    validate_direction_state(direction_code="NE", direction_source="OWNER_OBSERVED")
    with pytest.raises(ObservationIntegrityError):
        validate_direction_state(direction_code="UNKNOWN", direction_source="OWNER_OBSERVED")


def test_exact_interval_rejects_zero_duration() -> None:
    now = timezone.now()
    with pytest.raises(HistoricalIntervalConflict, match="requires its end to follow"):
        exact_interval(now, now)


@pytest.mark.django_db
def test_half_open_interval_allows_adjacency_and_detects_overlap() -> None:
    property_row = Property.objects.create(name="Synthetic")
    deployment = Deployment.objects.create(property=property_row)
    start = timezone.now()
    middle = start + timedelta(hours=1)
    end = middle + timedelta(hours=1)
    SyntheticInterval.objects.create(
        deployment=deployment,
        valid_from_lower=start,
        valid_to_lower=middle,
        status="FINAL",
    )

    adjacent = overlapping_final_intervals(
        SyntheticInterval.objects,
        deployment_id=deployment.id,
        valid_from=TemporalBounds(middle, precision="EXACT"),
        valid_to=TemporalBounds(end, precision="EXACT"),
    )
    assert not adjacent.exists()

    overlapping = overlapping_final_intervals(
        SyntheticInterval.objects,
        deployment_id=deployment.id,
        valid_from=TemporalBounds(start + timedelta(minutes=30), precision="EXACT"),
        valid_to=TemporalBounds(end, precision="EXACT"),
    )
    assert overlapping.exists()
'@

Write-TextFile (Join-Path $work "tests/integration/test_at_wal_003_remediation.py") @'
from __future__ import annotations

import pytest
from django.utils import timezone

from animal_tracking.domain.observation_integrity import ObservationIntegrityError
from animal_tracking.persistence.models import (
    AnimalObservation,
    EventMedia,
    MediaAsset,
    ObservationEvent,
    Property,
    Species,
)


def make_event(property_row: Property) -> ObservationEvent:
    return ObservationEvent.objects.create(
        property=property_row,
        assignment_status="UNRESOLVED",
        assignment_method="UNRESOLVED",
        assignment_override_reason="",
        capture_time_resolution="UNRESOLVED",
        status="NEEDS_REVIEW",
    )


@pytest.mark.django_db
def test_terminal_parent_rejects_active_child_mutation() -> None:
    property_row = Property.objects.create(name="Terminal aggregate")
    event = make_event(property_row)
    species = Species.objects.create(common_name="Synthetic species", code="SYNTHETIC")
    observation = AnimalObservation.objects.create(
        observation_event=event,
        species=species,
        count_value=1,
        count_classification="EXACT",
        direction_code="N",
        direction_source="OWNER_OBSERVED",
        status="ACCEPTED",
    )
    event.status = "VOID"
    event.analysis_exclusion_reason = "Synthetic terminalization"
    event.save(update_fields=("status", "analysis_exclusion_reason", "updated_at"))
    observation.notes = "must not mutate"
    with pytest.raises(ObservationIntegrityError, match="Observation Event is VOID"):
        observation.save(update_fields=("notes", "updated_at"))


@pytest.mark.django_db
def test_nonmanaged_media_is_rejected_and_sequence_is_centralized() -> None:
    property_row = Property.objects.create(name="Media lifecycle")
    event = make_event(property_row)
    staged = MediaAsset.objects.create(
        property=property_row,
        lifecycle_status="STAGED",
        label="staged",
    )
    with pytest.raises(ObservationIntegrityError, match="Only MANAGED"):
        EventMedia.objects.create(
            observation_event=event,
            media_asset=staged,
            sequence_number=99,
            media_role="PRIMARY",
            is_primary=True,
            attached_at=timezone.now(),
        )

    first_media = MediaAsset.objects.create(
        property=property_row,
        lifecycle_status="MANAGED",
        label="first",
    )
    second_media = MediaAsset.objects.create(
        property=property_row,
        lifecycle_status="MANAGED",
        label="second",
    )
    first = EventMedia.objects.create(
        observation_event=event,
        media_asset=first_media,
        sequence_number=99,
        media_role="PRIMARY",
        is_primary=True,
        attached_at=timezone.now(),
    )
    second = EventMedia.objects.create(
        observation_event=event,
        media_asset=second_media,
        sequence_number=1,
        media_role="SUPPORTING",
        is_primary=False,
        attached_at=timezone.now(),
    )
    assert first.sequence_number == 1
    assert second.sequence_number == 2


@pytest.mark.django_db
def test_model_boundary_rejects_cross_field_state_contradictions() -> None:
    property_row = Property.objects.create(name="State machine")
    event = ObservationEvent(
        property=property_row,
        assignment_status="MATCHED",
        assignment_method="UNRESOLVED",
        capture_time_resolution="UNRESOLVED",
        status="NEEDS_REVIEW",
    )
    with pytest.raises(ObservationIntegrityError, match="incompatible"):
        event.save()
'@

Write-TextFile (Join-Path $work "tests/integration/test_manual_observation_workflow.py") @'
from __future__ import annotations

import pytest

from animal_tracking.persistence.models import AnimalObservation, ObservationEvent, Property, Species


@pytest.mark.django_db
def test_synthetic_manual_observation_workflow_uses_integrity_boundary() -> None:
    property_row = Property.objects.create(name="Workflow")
    event = ObservationEvent.objects.create(
        property=property_row,
        assignment_status="UNRESOLVED",
        assignment_method="UNRESOLVED",
        assignment_override_reason="",
        capture_time_resolution="UNRESOLVED",
        status="NEEDS_REVIEW",
    )
    species = Species.objects.create(common_name="Synthetic", code="WORKFLOW")
    row = AnimalObservation.objects.create(
        observation_event=event,
        species=species,
        count_value=1,
        count_classification="EXACT",
        direction_code="UNKNOWN",
        direction_source="UNRESOLVED",
        status="NEEDS_REVIEW",
    )
    assert row.observation_event_id == event.id
'@

Write-TextFile (Join-Path $work "tools/validate_manual_observation_increment.py") @'
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CLASSES = {
    "src/animal_tracking/domain/sites.py": {
        "SpatialPositionDraft",
        "CameraSiteCommand",
        "CameraDeviceCommand",
        "CameraRegistryService",
    },
    "src/animal_tracking/domain/deployments.py": {
        "DeploymentCommand",
        "DeploymentConflict",
        "DeploymentService",
    },
    "src/animal_tracking/domain/observations.py": {
        "AnimalObservationDraft",
        "ManualObservationEventCommand",
        "ManualObservationService",
    },
    "src/animal_tracking/domain/observation_actions.py": {"ObservationActionService"},
    "src/animal_tracking/domain/species_review.py": {"SpeciesReviewService"},
    "src/animal_tracking/domain/observation_integrity.py": {"ObservationIntegrityError"},
}
REQUIRED_FUNCTIONS = {
    "src/animal_tracking/domain/observation_integrity.py": {
        "require_mutable_event_status",
        "validate_assignment_state",
        "validate_capture_time_state",
        "validate_direction_state",
    },
    "src/animal_tracking/persistence/integrity_signals.py": {
        "validate_observation_event",
        "validate_animal_observation",
        "validate_event_media",
    },
}
TARGETED_TESTS = (
    "tests/unit/test_observation_integrity.py",
    "tests/integration/test_at_wal_003_remediation.py",
    "tests/integration/test_manual_observation_workflow.py",
)


def definitions(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    classes = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    return classes, functions


def require_definitions() -> None:
    required_paths = set(REQUIRED_CLASSES) | set(REQUIRED_FUNCTIONS)
    missing_files = [path for path in sorted(required_paths) if not (ROOT / path).is_file()]
    if missing_files:
        raise SystemExit(f"Missing manual-observation increment files: {missing_files}")

    for relative_path, required in REQUIRED_CLASSES.items():
        classes, _ = definitions(ROOT / relative_path)
        missing = sorted(required - classes)
        if missing:
            raise SystemExit(f"Missing classes in {relative_path}: {missing}")

    for relative_path, required in REQUIRED_FUNCTIONS.items():
        _, functions = definitions(ROOT / relative_path)
        missing = sorted(required - functions)
        if missing:
            raise SystemExit(f"Missing functions in {relative_path}: {missing}")


def run_targeted_tests() -> dict[str, object]:
    command = [sys.executable, "-m", "pytest", "-q", *TARGETED_TESTS]
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and repository paths
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(
            f"Targeted manual-observation tests failed with exit code {completed.returncode}."
        )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout_tail": completed.stdout.strip().splitlines()[-5:],
    }


def main() -> None:
    require_definitions()
    test_result = run_targeted_tests()
    print(
        json.dumps(
            {
                "result": "PASS",
                "validation_scope": "EXECUTABLE_TARGETED_TEST_GATE",
                "structural_definition_check": "PASS",
                "targeted_tests": list(TARGETED_TESTS),
                "test_execution": test_result,
                "semantic_claims": (
                    "Limited to the exact targeted tests; full-suite and release conclusions "
                    "remain separate CI gates."
                ),
                "migration_required": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
'@

Write-TextFile (Join-Path $work "tools/prove_validator_effectiveness.py") @'
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = (
    (
        "terminal-parent-control",
        "src/animal_tracking/domain/observation_integrity.py",
        'TERMINAL_EVENT_STATUSES = frozenset({"VOID", "DUPLICATE"})',
        "TERMINAL_EVENT_STATUSES = frozenset()",
    ),
    (
        "assignment-method-control",
        "src/animal_tracking/domain/observation_integrity.py",
        "if assignment_method not in allowed_methods:",
        "if False and assignment_method not in allowed_methods:",
    ),
    (
        "managed-media-control",
        "src/animal_tracking/persistence/integrity_signals.py",
        'if instance.media_asset.lifecycle_status != "MANAGED":',
        'if False and instance.media_asset.lifecycle_status != "MANAGED":',
    ),
    (
        "half-open-interval-control",
        "src/animal_tracking/domain/intervals.py",
        "Q(valid_to_lower__gt=valid_from.lower)",
        "Q(valid_to_lower__gte=valid_from.lower)",
    ),
)


def ignored(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in {".git", ".pytest_cache", "__pycache__"}}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="at-wal-003-mutations-") as temporary:
        root = Path(temporary)
        for name, relative, old, new in MUTATIONS:
            case = root / name
            shutil.copytree(ROOT, case, ignore=ignored)
            path = case / relative
            text = path.read_text(encoding="utf-8")
            if text.count(old) != 1:
                raise RuntimeError(f"Mutation anchor is not unique for {name}.")
            path.write_text(text.replace(old, new), encoding="utf-8")
            completed = subprocess.run(  # noqa: S603 - fixed interpreter and local path
                [sys.executable, "tools/validate_manual_observation_increment.py"],
                cwd=case,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode == 0:
                raise RuntimeError(f"Validator incorrectly passed mutation: {name}")
            print(f"EXPECTED_FAILURE {name} exit={completed.returncode}")
    print("VALIDATOR_EFFECTIVENESS PASS")


if __name__ == "__main__":
    main()
'@

Write-TextFile (Join-Path $work "tools/generate_source_manifest.py") @'
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "IMPLEMENTATION_SOURCE_MANIFEST.json"
SCHEMA_VERSION = 4


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_command(*args: str, text: bool = True) -> str | bytes:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required to generate the source manifest.")
    return subprocess.check_output(  # noqa: S603 - resolved trusted Git executable
        [git, *args],
        cwd=ROOT,
        text=text,
    )


def git_head() -> str:
    value = git_command("rev-parse", "HEAD")
    assert isinstance(value, str)
    return value.strip()


def tracked_paths() -> list[Path]:
    raw = git_command("ls-files", "-z", text=False)
    assert isinstance(raw, bytes)
    paths = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        relative = Path(encoded.decode("utf-8"))
        if relative == MANIFEST.relative_to(ROOT):
            continue
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"Tracked path is unavailable from the worktree: {relative}")
        paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def file_rows() -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in tracked_paths()
    ]


def population_digest(rows: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(str(row["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(row["sha256"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(row["size_bytes"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def generated_payload(*, state: str) -> dict[str, object]:
    rows = file_rows()
    return {
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "content_commit": git_head(),
        "binding_rule": (
            "content_commit is the commit whose non-manifest tracked bytes were frozen; "
            "the manifest may be committed in one immediate successor commit"
        ),
        "authorized_scope": "Release 1 only",
        "release_authorized": False,
        "tracked_file_count": len(rows),
        "tracked_content_sha256": population_digest(rows),
        "files": rows,
    }


def load_manifest() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read source manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("The source manifest root must be a JSON object.")
    return value


def validate_manifest() -> dict[str, object]:
    manifest = load_manifest()
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"Source manifest schema must be {SCHEMA_VERSION}; "
            f"found {manifest.get('schema_version')!r}."
        )
    rows = file_rows()
    expected_by_path = {str(row["path"]): row for row in rows}
    recorded_rows = manifest.get("files")
    if not isinstance(recorded_rows, list):
        raise RuntimeError("Source manifest files must be a list.")
    recorded_by_path: dict[str, dict[str, object]] = {}
    for row in recorded_rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise RuntimeError("Every source-manifest row requires a string path.")
        path = row["path"]
        if path in recorded_by_path:
            raise RuntimeError(f"Duplicate source-manifest path: {path}")
        recorded_by_path[path] = row

    missing = sorted(set(expected_by_path) - set(recorded_by_path))
    extra = sorted(set(recorded_by_path) - set(expected_by_path))
    changed = sorted(
        path
        for path in set(expected_by_path) & set(recorded_by_path)
        if expected_by_path[path] != recorded_by_path[path]
    )
    if missing or extra or changed:
        raise RuntimeError(
            "Source manifest does not match the complete tracked population: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )

    digest = population_digest(rows)
    if manifest.get("tracked_file_count") != len(rows):
        raise RuntimeError("Source manifest tracked_file_count is stale.")
    if manifest.get("tracked_content_sha256") != digest:
        raise RuntimeError("Source manifest tracked_content_sha256 is stale.")

    content_commit = manifest.get("content_commit")
    if not isinstance(content_commit, str) or len(content_commit) != 40:
        raise RuntimeError("Source manifest content_commit must be a full Git identity.")
    try:
        git_command("merge-base", "--is-ancestor", content_commit, "HEAD")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "Source manifest content_commit is not an ancestor of the checked-out commit."
        ) from exc

    return {
        "result": "PASS",
        "schema_version": SCHEMA_VERSION,
        "tracked_files": len(rows),
        "tracked_content_sha256": digest,
        "content_commit": content_commit,
        "checked_head": git_head(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--state")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        result = validate_manifest()
    else:
        payload = generated_payload(state=args.state)
        MANIFEST.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        result = {
            "result": "PASS",
            "generated": MANIFEST.relative_to(ROOT).as_posix(),
            "tracked_files": payload["tracked_file_count"],
            "tracked_content_sha256": payload["tracked_content_sha256"],
            "content_commit": payload["content_commit"],
            "state": payload["state"],
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
'@

Push-Location $work
try {
    python -m pip install --disable-pip-version-check `
        Django==5.2.16 `
        pytest==9.1.1 `
        pytest-django==4.12.0 `
        mypy==2.3.0 `
        django-stubs==6.0.7 `
        django-stubs-ext==6.0.7 `
        ruff==0.15.22

    python -m compileall -q src tests tools
    python -m ruff format --check src tests tools
    python -m ruff check src tests tools
    python -m mypy --strict `
        src/animal_tracking/domain/observation_integrity.py `
        src/animal_tracking/domain/temporal.py `
        tools/validate_manual_observation_increment.py

    python tools/validate_manual_observation_increment.py
    python -m pytest -q
    python tools/prove_validator_effectiveness.py

    git init
    git config user.name "Public Reproducer"
    git config user.email "reproducer@example.invalid"
    git add pyproject.toml src tests tools
    git commit -m "Freeze sanitized AT-WAL-003 reproducer"

    python tools/generate_source_manifest.py --state AT_WAL_003_PUBLIC_REPRO
    python tools/generate_source_manifest.py --check

    Add-Content -Path "src/animal_tracking/domain/observation_integrity.py" -Value "`n# synthetic mutation"
    $PSNativeCommandUseErrorActionPreference = $false
    python tools/generate_source_manifest.py --check *> manifest-negative-check.txt
    $negativeExit = $LASTEXITCODE
    $PSNativeCommandUseErrorActionPreference = $true
    if ($negativeExit -eq 0) {
        throw "Source manifest check failed to detect a tracked-file mutation."
    }
    git checkout -- src/animal_tracking/domain/observation_integrity.py

    Write-Host "AT-WAL-003 PUBLIC WINDOWS REPRODUCER: PASS"
    Write-Host "Diagnostic source head: 3c2c6430243556c085525a3e36b5bc711035f0fa"
    Write-Host "F-007 database uniqueness remains excluded pending authorized migration ordering."
}
finally {
    Pop-Location
}
