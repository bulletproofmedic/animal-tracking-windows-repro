from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

from launcher_model import (
    Activation,
    COMPLETE_LOGGER_TRANSITION_FAILED,
    RECOVERY_ACTIVATION_FAILED,
    RESTORE_ACTIVATION_FAILED,
    STARTUP_FAILED,
    run,
)


class FakeDependencies:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.events: list[tuple[str, str]] = []
        self.fail_at: str | None = None
        self.initial_activation: Activation | None = Activation(
            "ACTIVATED_PENDING_PREFLIGHT"
        )
        self.recovered_activation: Activation | None = None

    @contextmanager
    def security_event_correlation(self) -> Iterator[str]:
        self.calls.append("correlation-enter")
        try:
            yield "a" * 32
        finally:
            self.calls.append("correlation-exit")

    def default_data_root(self) -> str:
        self.calls.append("default-root")
        return "C:/synthetic/data"

    def initialize_minimum_security_logging(self, data_root: str) -> None:
        self.calls.append(f"minimum:{data_root}")

    def validate_runtime_python(self) -> None:
        self.calls.append("runtime")

    def load_runtime_settings(self) -> Any:
        self.calls.append("settings")
        return SimpleNamespace(root_exists=True)

    def prepare_environment(self, settings: Any) -> str:
        del settings
        self.calls.append("environment")
        return "C:/synthetic/chrome.exe"

    @contextmanager
    def recovery_lock(self, settings: Any) -> Iterator[object]:
        del settings
        self.calls.append("recovery-lock-enter")
        try:
            yield object()
        finally:
            self.calls.append("recovery-lock-exit")

    def probe_instance_lock(self, settings: Any) -> None:
        del settings
        self.calls.append("instance-lock-probe")

    def reconcile_failed_roots(self, settings: Any) -> None:
        del settings
        self.calls.append("failed-roots")

    def reconcile_interrupted_staging(self, settings: Any) -> None:
        del settings
        self.calls.append("staging")

    def apply_pending_restore(self, settings: Any) -> Activation | None:
        del settings
        self.calls.append("apply-restore")
        if self.fail_at == "apply-restore":
            raise RuntimeError("synthetic restore failure")
        return self.initial_activation

    def prepare_runtime(self, settings: Any) -> Any:
        del settings
        self.calls.append("prepare-runtime")
        return SimpleNamespace(data_root="C:/synthetic/data")

    def configure_logging(self, log_directory: str) -> None:
        self.calls.append(f"configure:{log_directory}")

    def transition_to_complete_security_logging(self, log_directory: str) -> None:
        self.calls.append(f"complete:{log_directory}")
        if self.fail_at == "complete":
            raise RuntimeError("synthetic complete logger failure")

    def run_django_preflight(self) -> None:
        self.calls.append("preflight")

    def reconcile_backup_publications(self, settings: Any) -> None:
        del settings
        self.calls.append("backup-publications")

    def run_post_restore_finalizers(
        self, activation: Activation, settings: Any
    ) -> Activation:
        del settings
        self.calls.append("post-restore-finalizers")
        return activation

    def mark_preflight_passed(self, activation: Activation) -> Activation:
        del activation
        self.calls.append("mark-preflight")
        return Activation("PREFLIGHT_PASSED")

    def persist_terminal_journal(self, activation: Activation) -> None:
        self.calls.append(f"persist-terminal:{activation.phase}")

    def start_waitress(self, settings: Any) -> object:
        del settings
        self.calls.append("server-start")
        return object()

    def wait_until_ready(self, settings: Any) -> None:
        del settings
        self.calls.append("ready")

    def verify_post_start_routes(self, settings: Any) -> None:
        del settings
        self.calls.append("routes")

    def open_chrome(self, chrome: Any, settings: Any) -> None:
        del chrome, settings
        self.calls.append("browser")

    def mark_ready(self, activation: Activation) -> Activation:
        del activation
        self.calls.append("mark-ready")
        return Activation("READY")

    def finalize_activation(self, activation: Activation) -> Activation:
        del activation
        self.calls.append("finalize")
        return Activation("FINALIZED")

    def recover_startup_failure(
        self,
        settings: Any,
        activation: Activation | None,
        *,
        failure_code: str,
        failure_detail: str,
    ) -> Activation | None:
        del settings, activation
        self.calls.append(f"recover:{failure_code}:{failure_detail}")
        return self.recovered_activation

    def stop_server(self, server: Any) -> None:
        del server
        self.calls.append("server-stop")

    def emit_security_event(self, code: str, reason: str) -> None:
        self.calls.append(f"event:{code}:{reason}")
        self.events.append((code, reason))


class LauncherIntegrationTests(unittest.TestCase):
    def test_successful_restore_preserves_combined_order(self) -> None:
        deps = FakeDependencies()

        run(deps)

        calls = deps.calls
        self.assertEqual(calls[0], "correlation-enter")
        self.assertLess(calls.index("minimum:C:/synthetic/data"), calls.index("settings"))
        self.assertLess(calls.index("minimum:C:/synthetic/data"), calls.index("apply-restore"))
        self.assertLess(calls.index("recovery-lock-enter"), calls.index("failed-roots"))
        self.assertLess(calls.index("staging"), calls.index("apply-restore"))
        self.assertLess(calls.index("apply-restore"), calls.index("prepare-runtime"))
        self.assertLess(calls.index("prepare-runtime"), calls.index("complete:C:/synthetic/data/logs"))
        self.assertLess(calls.index("complete:C:/synthetic/data/logs"), calls.index("preflight"))
        self.assertLess(calls.index("post-restore-finalizers"), calls.index("mark-preflight"))
        self.assertLess(calls.index("mark-preflight"), calls.index("server-start"))
        self.assertLess(calls.index("routes"), calls.index("browser"))
        self.assertLess(calls.index("browser"), calls.index("mark-ready"))
        self.assertLess(calls.index("mark-ready"), calls.index("finalize"))
        self.assertIn("persist-terminal:FINALIZED", calls)
        self.assertEqual(calls[-2:], ["recovery-lock-exit", "correlation-exit"])
        self.assertEqual(deps.events, [])

    def test_restore_activation_failure_emits_exactly_two_deduplicated_events(self) -> None:
        deps = FakeDependencies()
        deps.fail_at = "apply-restore"

        with self.assertRaisesRegex(RuntimeError, "synthetic restore failure"):
            run(deps)

        self.assertEqual(
            deps.events,
            [
                (RECOVERY_ACTIVATION_FAILED, RESTORE_ACTIVATION_FAILED),
                (STARTUP_FAILED, RESTORE_ACTIVATION_FAILED),
            ],
        )
        self.assertEqual(
            sum(1 for code, _ in deps.events if code == STARTUP_FAILED),
            1,
        )
        self.assertTrue(any(call.startswith("recover:RUNTIMEERROR:") for call in deps.calls))
        self.assertEqual(deps.calls[-2:], ["recovery-lock-exit", "correlation-exit"])

    def test_complete_logger_failure_is_recovered_without_duplicate_startup_event(self) -> None:
        deps = FakeDependencies()
        deps.fail_at = "complete"

        with self.assertRaisesRegex(RuntimeError, "synthetic complete logger failure"):
            run(deps)

        self.assertEqual(deps.events, [(STARTUP_FAILED, COMPLETE_LOGGER_TRANSITION_FAILED)])
        self.assertNotIn("server-start", deps.calls)
        self.assertTrue(any(call.startswith("recover:RUNTIMEERROR:") for call in deps.calls))

    def test_terminal_activation_is_archived_before_server_start(self) -> None:
        deps = FakeDependencies()
        deps.initial_activation = Activation("FINALIZED")

        run(deps)

        self.assertLess(
            deps.calls.index("persist-terminal:FINALIZED"),
            deps.calls.index("server-start"),
        )
        self.assertNotIn("mark-ready", deps.calls)
        self.assertNotIn("finalize", deps.calls)

    def test_exact_private_identity_binding_is_declared(self) -> None:
        identity_path = Path(__file__).with_name("private_identity_binding.json")
        binding = json.loads(identity_path.read_text(encoding="utf-8"))

        self.assertEqual(
            binding["private_diagnostic_head"],
            "481fbdf0986e66e6cb85d2375f231ef2cf08d6ef",
        )
        self.assertEqual(
            binding["private_diagnostic_tree"],
            "5027c4696062006d0b48acc1e5c10d493fc8e28c",
        )
        self.assertEqual(
            binding["hybrid_launcher_blob"],
            "871c3ec362e362388b8ce6368f8dcec6e1a64a0a",
        )
        self.assertFalse(binding["replaces_private_validation"])


if __name__ == "__main__":
    unittest.main()
