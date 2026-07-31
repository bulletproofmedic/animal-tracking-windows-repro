from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import map_calibration_model as model


def synthetic_points(*, validation_offset: float = 0.0) -> list[model.CalibrationPoint]:
    transform = model.Affine(2.0, 0.25, 10.0, -0.5, 3.0, 20.0)
    controls = [model.Point(0, 0), model.Point(10, 0), model.Point(0, 10), model.Point(10, 10)]
    points = [
        model.CalibrationPoint(f"c{index}", model.PointRole.CONTROL, point, transform.forward(point))
        for index, point in enumerate(controls)
    ]
    source = model.Point(4, 7)
    target = transform.forward(source)
    points.append(
        model.CalibrationPoint(
            "v1",
            model.PointRole.VALIDATION,
            source,
            model.Point(target.x + validation_offset, target.y),
        )
    )
    return points


class RouteControls(unittest.TestCase):
    def test_accepts_normalized_local_route(self) -> None:
        route = "/map-tiles/asset-a/v1/{z}/{x}/{y}.png"
        self.assertEqual(model.validate_local_tile_template(route), route)

    def test_rejects_external_and_protocol_relative_routes(self) -> None:
        for route in ("https://example.invalid/{z}/{x}/{y}.png", "//example.invalid/{z}/{x}/{y}.png"):
            with self.subTest(route=route), self.assertRaises(model.ControlError):
                model.validate_local_tile_template(route)

    def test_rejects_encoded_traversal_backslash_query_fragment_and_controls(self) -> None:
        routes = (
            "/map-tiles/%2e%2e/v1/{z}/{x}/{y}.png",
            "/map-tiles/asset\\v1/{z}/{x}/{y}.png",
            "/map-tiles/asset/v1/{z}/{x}/{y}.png?token=x",
            "/map-tiles/asset/v1/{z}/{x}/{y}.png#x",
            "/map-tiles/asset/v1/{z}/{x}/{y}.png\n",
        )
        for route in routes:
            with self.subTest(route=route), self.assertRaises(model.ControlError):
                model.validate_local_tile_template(route)


class CalibrationControls(unittest.TestCase):
    def test_independent_validation_points_pass(self) -> None:
        result = model.fit_calibration(
            synthetic_points(),
            target_crs="SYNTHETIC:1000",
            crs_kind=model.CrsKind.PROJECTED_LINEAR,
            unit=model.Unit.METRE,
            tolerance_m=0.01,
        )
        self.assertTrue(result.passes)
        self.assertLess(result.validation_rmse_m, 1e-9)

    def test_failed_tolerance_is_visible(self) -> None:
        result = model.fit_calibration(
            synthetic_points(validation_offset=2.0),
            target_crs="SYNTHETIC:1000",
            crs_kind=model.CrsKind.PROJECTED_LINEAR,
            unit=model.Unit.METRE,
            tolerance_m=1.0,
        )
        self.assertFalse(result.passes)

    def test_international_foot_is_converted_to_metres(self) -> None:
        result = model.fit_calibration(
            synthetic_points(validation_offset=1.0),
            target_crs="SYNTHETIC:FT",
            crs_kind=model.CrsKind.PROJECTED_LINEAR,
            unit=model.Unit.INTERNATIONAL_FOOT,
            tolerance_m=0.31,
        )
        self.assertAlmostEqual(result.validation_rmse_m, 0.3048, places=8)
        self.assertTrue(result.passes)

    def test_angular_and_pixel_units_are_rejected(self) -> None:
        for unit in (model.Unit.DEGREE, model.Unit.PIXEL):
            with self.subTest(unit=unit), self.assertRaises(model.ControlError):
                model.fit_calibration(
                    synthetic_points(),
                    target_crs="SYNTHETIC:BAD",
                    crs_kind=model.CrsKind.PROJECTED_LINEAR,
                    unit=unit,
                    tolerance_m=1.0,
                )

    def test_unstable_controls_are_rejected(self) -> None:
        points = [
            model.CalibrationPoint("c1", model.PointRole.CONTROL, model.Point(0, 0), model.Point(0, 0)),
            model.CalibrationPoint("c2", model.PointRole.CONTROL, model.Point(1, 1), model.Point(2, 2)),
            model.CalibrationPoint("c3", model.PointRole.CONTROL, model.Point(2, 2), model.Point(4, 4)),
            model.CalibrationPoint("v1", model.PointRole.VALIDATION, model.Point(3, 3), model.Point(6, 6)),
        ]
        with self.assertRaises(model.ControlError):
            model.fit_calibration(
                points,
                target_crs="SYNTHETIC:1000",
                crs_kind=model.CrsKind.PROJECTED_LINEAR,
                unit=model.Unit.METRE,
                tolerance_m=1.0,
            )

    def test_projection_context_requires_exact_identity_and_versions(self) -> None:
        transform = model.Affine(1, 0, 0, 0, 1, 0)
        context = model.ProjectionContext(
            asset_id="asset-a",
            asset_version="v1",
            asset_status="ACTIVE",
            calibration_id="cal-a",
            calibration_version="c1",
            calibration_status="ACCEPTED",
            target_crs="SYNTHETIC:1000",
            crs_kind=model.CrsKind.PROJECTED_LINEAR,
            unit=model.Unit.METRE,
            transform_version="c1",
            evidence_reference="synthetic-evidence",
            coordinate_space_id="space-a",
            transform=transform,
        )
        context.require(asset_id="asset-a", asset_version="v1", calibration_id="cal-a", calibration_version="c1")
        with self.assertRaises(model.ControlError):
            context.require(asset_id="asset-a", asset_version="v2", calibration_id="cal-a", calibration_version="c1")

    def test_projection_context_rejects_unaccepted_or_stale_status(self) -> None:
        base = dict(
            asset_id="asset-a",
            asset_version="v1",
            calibration_id="cal-a",
            calibration_version="c1",
            target_crs="SYNTHETIC:1000",
            crs_kind=model.CrsKind.PROJECTED_LINEAR,
            unit=model.Unit.METRE,
            transform_version="c1",
            evidence_reference="synthetic-evidence",
            coordinate_space_id="space-a",
            transform=model.Affine(1, 0, 0, 0, 1, 0),
        )
        for asset_status, calibration_status in (("RETIRED", "ACCEPTED"), ("ACTIVE", "CANDIDATE")):
            context = model.ProjectionContext(
                asset_status=asset_status,
                calibration_status=calibration_status,
                **base,
            )
            with self.subTest(asset_status=asset_status, calibration_status=calibration_status), self.assertRaises(model.ControlError):
                context.require(asset_id="asset-a", asset_version="v1", calibration_id="cal-a", calibration_version="c1")


class DerivativeControls(unittest.TestCase):
    def test_identical_render_from_two_sources_has_distinct_identity(self) -> None:
        rendered = hashlib.sha256(b"same-render").hexdigest()
        first = model.derivative_identity(
            parent_id="asset-a",
            parent_sha256="a" * 64,
            role="DISPLAY",
            profile="display-v2",
            rendered_sha256=rendered,
        )
        second = model.derivative_identity(
            parent_id="asset-b",
            parent_sha256="b" * 64,
            role="DISPLAY",
            profile="display-v2",
            rendered_sha256=rendered,
        )
        self.assertNotEqual(first, second)

    def test_parent_role_or_profile_mismatch_is_rejected(self) -> None:
        rendered = hashlib.sha256(b"render").hexdigest()
        identity = model.derivative_identity(
            parent_id="asset-a",
            parent_sha256="a" * 64,
            role="DISPLAY",
            profile="display-v2",
            rendered_sha256=rendered,
        )
        for role, profile in (("TILE", "display-v2"), ("DISPLAY", "display-v3")):
            with self.subTest(role=role, profile=profile), self.assertRaises(model.ControlError):
                model.verify_derivative(
                    identity,
                    parent_id="asset-a",
                    parent_sha256="a" * 64,
                    role=role,
                    profile=profile,
                    rendered_sha256=rendered,
                )


class ActivationControls(unittest.TestCase):
    def _fault_case(self, fault: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = model.StagedPublisher(Path(directory))
            with self.assertRaises(RuntimeError):
                publisher.publish("synthetic.bin", b"payload", fault=fault)
            self.assertEqual(publisher.reconcile(), "ACTIVE")
            self.assertEqual((Path(directory) / "synthetic.bin").read_bytes(), b"payload")

    def test_restart_reconciles_every_activation_boundary(self) -> None:
        for fault in ("before_replace", "after_replace", "before_commit", "after_commit"):
            with self.subTest(fault=fault):
                self._fault_case(fault)

    def test_missing_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = model.StagedPublisher(Path(directory))
            with self.assertRaises(RuntimeError):
                publisher.publish("synthetic.bin", b"payload", fault="before_replace")
            (Path(directory) / "synthetic.bin.part").unlink()
            with self.assertRaises(model.ControlError):
                publisher.reconcile()

    def test_corrupt_final_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = model.StagedPublisher(Path(directory))
            with self.assertRaises(RuntimeError):
                publisher.publish("synthetic.bin", b"payload", fault="after_replace")
            (Path(directory) / "synthetic.bin").write_bytes(b"changed")
            with self.assertRaises(model.ControlError):
                publisher.reconcile()

    def test_existing_destination_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "synthetic.bin").write_bytes(b"existing")
            publisher = model.StagedPublisher(root)
            with self.assertRaises(model.ControlError):
                publisher.publish("synthetic.bin", b"new")
            self.assertEqual((root / "synthetic.bin").read_bytes(), b"existing")


class AcceptanceControls(unittest.TestCase):
    def _request(self, transform: model.Affine | None = None) -> model.CandidateRequest:
        solved = model.fit_calibration(
            synthetic_points(),
            target_crs="SYNTHETIC:1000",
            crs_kind=model.CrsKind.PROJECTED_LINEAR,
            unit=model.Unit.METRE,
            tolerance_m=0.01,
        )
        return model.CandidateRequest(
            asset_id="asset-a",
            asset_version="v1",
            calibration_id="cal-a",
            calibration_version="c1",
            target_crs="SYNTHETIC:1000",
            evidence_reference="synthetic-evidence",
            stored_transform=transform or solved.transform,
        )

    def test_candidate_recomputes_transform_and_residuals(self) -> None:
        result = model.validate_candidate(
            self._request(),
            expected_asset_id="asset-a",
            expected_asset_version="v1",
            expected_calibration_id="cal-a",
            expected_calibration_version="c1",
            expected_target_crs="SYNTHETIC:1000",
            expected_evidence_reference="synthetic-evidence",
            points=synthetic_points(),
            unit=model.Unit.METRE,
            tolerance_m=0.01,
        )
        self.assertTrue(result.passes)

    def test_candidate_rejects_wrong_identity_or_evidence(self) -> None:
        request = self._request()
        for expected_asset, expected_evidence in (("asset-b", "synthetic-evidence"), ("asset-a", "other-evidence")):
            with self.subTest(expected_asset=expected_asset, expected_evidence=expected_evidence), self.assertRaises(model.ControlError):
                model.validate_candidate(
                    request,
                    expected_asset_id=expected_asset,
                    expected_asset_version="v1",
                    expected_calibration_id="cal-a",
                    expected_calibration_version="c1",
                    expected_target_crs="SYNTHETIC:1000",
                    expected_evidence_reference=expected_evidence,
                    points=synthetic_points(),
                    unit=model.Unit.METRE,
                    tolerance_m=0.01,
                )

    def test_candidate_rejects_persisted_transform_mismatch(self) -> None:
        with self.assertRaises(model.ControlError):
            model.validate_candidate(
                self._request(model.Affine(1, 0, 0, 0, 1, 0)),
                expected_asset_id="asset-a",
                expected_asset_version="v1",
                expected_calibration_id="cal-a",
                expected_calibration_version="c1",
                expected_target_crs="SYNTHETIC:1000",
                expected_evidence_reference="synthetic-evidence",
                points=synthetic_points(),
                unit=model.Unit.METRE,
                tolerance_m=0.01,
            )

    def test_production_acceptance_remains_blocked_even_with_authority_text(self) -> None:
        with self.assertRaises(model.ControlError):
            model.accept_production(authority_text="synthetic approval text")


if __name__ == "__main__":
    unittest.main()
