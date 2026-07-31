from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


class ControlError(ValueError):
    pass


class PointRole(StrEnum):
    CONTROL = "CONTROL"
    VALIDATION = "VALIDATION"


class CrsKind(StrEnum):
    PROJECTED_LINEAR = "PROJECTED_LINEAR"
    GEOGRAPHIC_ANGULAR = "GEOGRAPHIC_ANGULAR"
    LOCAL_PIXEL = "LOCAL_PIXEL"


class Unit(StrEnum):
    METRE = "METRE"
    INTERNATIONAL_FOOT = "INTERNATIONAL_FOOT"
    DEGREE = "DEGREE"
    PIXEL = "PIXEL"

    @property
    def metres_per_unit(self) -> float | None:
        if self is Unit.METRE:
            return 1.0
        if self is Unit.INTERNATIONAL_FOOT:
            return 0.3048
        return None


@dataclass(frozen=True)
class Point:
    x: float
    y: float

    def __post_init__(self) -> None:
        if not math.isfinite(self.x) or not math.isfinite(self.y):
            raise ControlError("coordinates must be finite")


@dataclass(frozen=True)
class CalibrationPoint:
    point_id: str
    role: PointRole
    source: Point
    target: Point


@dataclass(frozen=True)
class Affine:
    a: float
    b: float
    c: float
    d: float
    e: float
    f: float

    def forward(self, point: Point) -> Point:
        return Point(
            self.a * point.x + self.b * point.y + self.c,
            self.d * point.x + self.e * point.y + self.f,
        )

    def inverse(self, point: Point) -> Point:
        determinant = self.a * self.e - self.b * self.d
        if abs(determinant) <= 1e-12:
            raise ControlError("transform is not invertible")
        x = point.x - self.c
        y = point.y - self.f
        return Point(
            (self.e * x - self.b * y) / determinant,
            (-self.d * x + self.a * y) / determinant,
        )


@dataclass(frozen=True)
class CalibrationResult:
    transform: Affine
    validation_rmse_m: float
    validation_max_m: float
    tolerance_m: float

    @property
    def passes(self) -> bool:
        return (
            self.validation_rmse_m <= self.tolerance_m
            and self.validation_max_m <= self.tolerance_m
        )


@dataclass(frozen=True)
class ProjectionContext:
    asset_id: str
    asset_version: str
    asset_status: str
    calibration_id: str
    calibration_version: str
    calibration_status: str
    target_crs: str
    crs_kind: CrsKind
    unit: Unit
    transform_version: str
    evidence_reference: str
    coordinate_space_id: str
    transform: Affine

    def require(
        self,
        *,
        asset_id: str,
        asset_version: str,
        calibration_id: str,
        calibration_version: str,
    ) -> None:
        if (
            asset_id != self.asset_id
            or asset_version != self.asset_version
            or calibration_id != self.calibration_id
            or calibration_version != self.calibration_version
        ):
            raise ControlError("projection identity mismatch")
        if self.asset_status != "ACTIVE":
            raise ControlError("asset version is not active")
        if self.calibration_status != "ACCEPTED":
            raise ControlError("calibration is not accepted")
        if self.crs_kind is not CrsKind.PROJECTED_LINEAR:
            raise ControlError("target CRS is not projected linear")
        if self.unit.metres_per_unit is None:
            raise ControlError("target unit cannot be converted to metres")
        if self.transform_version != self.calibration_version:
            raise ControlError("transform version mismatch")
        required = (
            self.target_crs,
            self.evidence_reference,
            self.coordinate_space_id,
        )
        if any(not value.strip() for value in required):
            raise ControlError("projection evidence is incomplete")


def validate_local_tile_template(template: str) -> str:
    if not template or any(ord(ch) < 32 or ord(ch) == 127 for ch in template):
        raise ControlError("tile route contains control characters")
    if "\\" in template or "?" in template or "#" in template:
        raise ControlError("tile route contains an ambiguous separator")
    parsed = urlsplit(template)
    if parsed.scheme or parsed.netloc or template.startswith("//"):
        raise ControlError("tile route must be application-local")
    decoded = unquote(unquote(template))
    if decoded != template:
        raise ControlError("encoded tile route forms are not accepted")
    pure = PurePosixPath(template)
    if not template.startswith("/map-tiles/") or any(part in {"", ".", ".."} for part in pure.parts[1:]):
        raise ControlError("tile route is outside the local map namespace")
    expected_tail = ("{z}", "{x}", "{y}.png")
    if tuple(pure.parts[-3:]) != expected_tail:
        raise ControlError("tile route template coordinates are malformed")
    return template


def _solve3(matrix: list[list[float]], vector: list[float]) -> tuple[float, float, float]:
    rows = [[*matrix[index], vector[index]] for index in range(3)]
    for pivot in range(3):
        best = max(range(pivot, 3), key=lambda index: abs(rows[index][pivot]))
        if abs(rows[best][pivot]) <= 1e-12:
            raise ControlError("control geometry is unstable")
        rows[pivot], rows[best] = rows[best], rows[pivot]
        divisor = rows[pivot][pivot]
        rows[pivot] = [value / divisor for value in rows[pivot]]
        for index in range(3):
            if index == pivot:
                continue
            factor = rows[index][pivot]
            rows[index] = [
                rows[index][column] - factor * rows[pivot][column]
                for column in range(4)
            ]
    return rows[0][3], rows[1][3], rows[2][3]


def _least_squares(rows: list[tuple[float, float, float]], values: list[float]) -> tuple[float, float, float]:
    normal = [[0.0] * 3 for _ in range(3)]
    right = [0.0] * 3
    for row, value in zip(rows, values, strict=True):
        for i in range(3):
            right[i] += row[i] * value
            for j in range(3):
                normal[i][j] += row[i] * row[j]
    return _solve3(normal, right)


def fit_calibration(
    points: list[CalibrationPoint],
    *,
    target_crs: str,
    crs_kind: CrsKind,
    unit: Unit,
    tolerance_m: float,
) -> CalibrationResult:
    if not target_crs.strip() or crs_kind is not CrsKind.PROJECTED_LINEAR:
        raise ControlError("calibration requires a projected linear CRS")
    conversion = unit.metres_per_unit
    if conversion is None:
        raise ControlError("calibration unit cannot be converted to metres")
    if not math.isfinite(tolerance_m) or tolerance_m <= 0:
        raise ControlError("tolerance must be positive")
    if len({point.point_id for point in points}) != len(points):
        raise ControlError("point identities must be unique")
    controls = [point for point in points if point.role is PointRole.CONTROL]
    validations = [point for point in points if point.role is PointRole.VALIDATION]
    if len(controls) < 3 or not validations:
        raise ControlError("independent controls and validation are required")
    design = [(point.source.x, point.source.y, 1.0) for point in controls]
    x_terms = _least_squares(design, [point.target.x for point in controls])
    y_terms = _least_squares(design, [point.target.y for point in controls])
    transform = Affine(*x_terms, *y_terms)
    distances_m = []
    for point in validations:
        projected = transform.forward(point.source)
        distances_m.append(math.hypot(projected.x - point.target.x, projected.y - point.target.y) * conversion)
    rmse = math.sqrt(sum(value * value for value in distances_m) / len(distances_m))
    return CalibrationResult(transform, rmse, max(distances_m), tolerance_m)


def derivative_identity(
    *,
    parent_id: str,
    parent_sha256: str,
    role: str,
    profile: str,
    rendered_sha256: str,
) -> str:
    payload = {
        "parent_id": parent_id,
        "parent_sha256": parent_sha256,
        "profile": profile,
        "rendered_sha256": rendered_sha256,
        "role": role,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_derivative(
    recorded_identity: str,
    *,
    parent_id: str,
    parent_sha256: str,
    role: str,
    profile: str,
    rendered_sha256: str,
) -> None:
    expected = derivative_identity(
        parent_id=parent_id,
        parent_sha256=parent_sha256,
        role=role,
        profile=profile,
        rendered_sha256=rendered_sha256,
    )
    if recorded_identity != expected:
        raise ControlError("derivative lineage mismatch")


@dataclass
class ActivationJournal:
    phase: str
    final_name: str
    temporary_name: str
    sha256: str
    size: int


class StagedPublisher:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.journal_path = self.root / "activation.json"

    def _write_journal(self, journal: ActivationJournal) -> None:
        temp = self.journal_path.with_suffix(".tmp")
        temp.write_text(json.dumps(asdict(journal), sort_keys=True), encoding="utf-8")
        with temp.open("r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(temp, self.journal_path)

    def _read_journal(self) -> ActivationJournal:
        return ActivationJournal(**json.loads(self.journal_path.read_text(encoding="utf-8")))

    @staticmethod
    def _identity(path: Path) -> tuple[str, int]:
        raw = path.read_bytes()
        return hashlib.sha256(raw).hexdigest(), len(raw)

    def publish(self, name: str, payload: bytes, *, fault: str | None = None) -> None:
        final = self.root / name
        temporary = self.root / f"{name}.part"
        if final.exists() or temporary.exists():
            raise ControlError("publication target already exists")
        temporary.write_bytes(payload)
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        digest, size = self._identity(temporary)
        journal = ActivationJournal("STAGING", name, temporary.name, digest, size)
        self._write_journal(journal)
        if fault == "before_replace":
            raise RuntimeError(fault)
        os.replace(temporary, final)
        if fault == "after_replace":
            raise RuntimeError(fault)
        if self._identity(final) != (digest, size):
            raise ControlError("published bytes changed")
        if fault == "before_commit":
            raise RuntimeError(fault)
        journal.phase = "ACTIVE"
        self._write_journal(journal)
        if fault == "after_commit":
            raise RuntimeError(fault)

    def reconcile(self) -> str:
        journal = self._read_journal()
        final = self.root / journal.final_name
        temporary = self.root / journal.temporary_name
        expected = (journal.sha256, journal.size)
        if journal.phase == "ACTIVE":
            if not final.is_file() or self._identity(final) != expected:
                raise ControlError("active publication is missing or corrupt")
            return "ACTIVE"
        if journal.phase != "STAGING":
            raise ControlError("journal phase is invalid")
        if final.is_file():
            if self._identity(final) != expected:
                raise ControlError("final publication is corrupt")
        elif temporary.is_file():
            if self._identity(temporary) != expected:
                raise ControlError("staged publication is corrupt")
            os.replace(temporary, final)
        else:
            raise ControlError("publication bytes are missing")
        journal.phase = "ACTIVE"
        self._write_journal(journal)
        return "ACTIVE"


@dataclass(frozen=True)
class CandidateRequest:
    asset_id: str
    asset_version: str
    calibration_id: str
    calibration_version: str
    target_crs: str
    evidence_reference: str
    stored_transform: Affine


def validate_candidate(
    request: CandidateRequest,
    *,
    expected_asset_id: str,
    expected_asset_version: str,
    expected_calibration_id: str,
    expected_calibration_version: str,
    expected_target_crs: str,
    expected_evidence_reference: str,
    points: list[CalibrationPoint],
    unit: Unit,
    tolerance_m: float,
) -> CalibrationResult:
    actual = (
        request.asset_id,
        request.asset_version,
        request.calibration_id,
        request.calibration_version,
        request.target_crs,
        request.evidence_reference,
    )
    expected = (
        expected_asset_id,
        expected_asset_version,
        expected_calibration_id,
        expected_calibration_version,
        expected_target_crs,
        expected_evidence_reference,
    )
    if actual != expected:
        raise ControlError("candidate identity or evidence mismatch")
    result = fit_calibration(
        points,
        target_crs=expected_target_crs,
        crs_kind=CrsKind.PROJECTED_LINEAR,
        unit=unit,
        tolerance_m=tolerance_m,
    )
    if not result.passes:
        raise ControlError("independent validation tolerance failed")
    actual_parameters = tuple(request.stored_transform.__dict__.values())
    expected_parameters = tuple(result.transform.__dict__.values())
    if any(abs(left - right) > 1e-9 for left, right in zip(actual_parameters, expected_parameters, strict=True)):
        raise ControlError("stored transform does not match point evidence")
    return result


def accept_production(*, authority_text: str | None = None) -> None:
    del authority_text
    raise ControlError("production calibration acceptance remains unauthorized")
