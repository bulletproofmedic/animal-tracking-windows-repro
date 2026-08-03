from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any, Protocol


RECOVERY_ACTIVATION_FAILED = "RECOVERY_ACTIVATION_FAILED"
STARTUP_FAILED = "STARTUP_FAILED"
COMPLETE_LOGGER_TRANSITION_FAILED = "COMPLETE_LOGGER_TRANSITION_FAILED"
UNEXPECTED_FAILURE = "UNEXPECTED_FAILURE"
RESTORE_ACTIVATION_FAILED = "RESTORE_ACTIVATION_FAILED"


class Dependencies(Protocol):
    def security_event_correlation(self) -> AbstractContextManager[object]: ...

    def default_data_root(self) -> str: ...

    def initialize_minimum_security_logging(self, data_root: str) -> None: ...

    def validate_runtime_python(self) -> None: ...

    def load_runtime_settings(self) -> Any: ...

    def prepare_environment(self, settings: Any) -> Any: ...

    def recovery_lock(self, settings: Any) -> AbstractContextManager[object]: ...

    def probe_instance_lock(self, settings: Any) -> None: ...

    def reconcile_failed_roots(self, settings: Any) -> None: ...

    def reconcile_interrupted_staging(self, settings: Any) -> None: ...

    def apply_pending_restore(self, settings: Any) -> Any: ...

    def prepare_runtime(self, settings: Any) -> Any: ...

    def configure_logging(self, log_directory: str) -> None: ...

    def transition_to_complete_security_logging(self, log_directory: str) -> None: ...

    def run_django_preflight(self) -> None: ...

    def reconcile_backup_publications(self, settings: Any) -> None: ...

    def run_post_restore_finalizers(self, activation: Any, settings: Any) -> Any: ...

    def mark_preflight_passed(self, activation: Any) -> Any: ...

    def persist_terminal_journal(self, activation: Any) -> None: ...

    def start_waitress(self, settings: Any) -> Any: ...

    def wait_until_ready(self, settings: Any) -> None: ...

    def verify_post_start_routes(self, settings: Any) -> None: ...

    def open_chrome(self, chrome: Any, settings: Any) -> None: ...

    def mark_ready(self, activation: Any) -> Any: ...

    def finalize_activation(self, activation: Any) -> Any: ...

    def recover_startup_failure(
        self,
        settings: Any,
        activation: Any,
        *,
        failure_code: str,
        failure_detail: str,
    ) -> Any: ...

    def stop_server(self, server: Any) -> None: ...

    def emit_security_event(self, code: str, reason: str) -> None: ...


@dataclass(slots=True)
class Activation:
    phase: str


@dataclass(slots=True)
class RuntimeReport:
    data_root: str


TERMINAL_PHASES = {"FINALIZE_PENDING", "FINALIZED", "ROLLED_BACK"}
PREFLIGHT_PHASES = {"ACTIVATED_PENDING_PREFLIGHT", "PREFLIGHT_PASSED", "READY"}


def run(deps: Dependencies) -> None:
    """Sanitized model of the required hybrid launcher lifecycle.

    This reproducer deliberately models only the integration boundary under review:
    minimum logging, recovery lifecycle, complete-logger transition, startup probes,
    activation finalization, and deduplicated security failure events.
    """

    with deps.security_event_correlation():
        _run_correlated(deps)


def _run_correlated(deps: Dependencies) -> None:
    deps.initialize_minimum_security_logging(deps.default_data_root())

    startup_failure_recorded = False
    recorded_events: set[tuple[str, str]] = set()

    def record_once(code: str, reason: str) -> None:
        key = (code, reason)
        if key in recorded_events:
            return
        recorded_events.add(key)
        deps.emit_security_event(code, reason)

    def record_startup_failure(reason: str) -> None:
        nonlocal startup_failure_recorded
        if startup_failure_recorded:
            return
        startup_failure_recorded = True
        record_once(STARTUP_FAILED, reason)

    deps.validate_runtime_python()
    settings = deps.load_runtime_settings()
    chrome = deps.prepare_environment(settings)

    with deps.recovery_lock(settings):
        deps.probe_instance_lock(settings)
        activation: Any = None
        server: Any = None
        try:
            deps.reconcile_failed_roots(settings)
            deps.reconcile_interrupted_staging(settings)
            try:
                activation = deps.apply_pending_restore(settings)
            except Exception:
                record_once(RECOVERY_ACTIVATION_FAILED, RESTORE_ACTIVATION_FAILED)
                record_startup_failure(RESTORE_ACTIVATION_FAILED)
                raise

            report = deps.prepare_runtime(settings)
            log_directory = f"{report.data_root}/logs"
            deps.configure_logging(log_directory)
            try:
                deps.transition_to_complete_security_logging(log_directory)
            except Exception:
                record_startup_failure(COMPLETE_LOGGER_TRANSITION_FAILED)
                raise

            deps.run_django_preflight()
            deps.reconcile_backup_publications(settings)

            if activation is not None and activation.phase == "ACTIVATED_PENDING_PREFLIGHT":
                activation = deps.run_post_restore_finalizers(activation, settings)

            if activation is not None and activation.phase in PREFLIGHT_PHASES:
                activation = deps.mark_preflight_passed(activation)
            elif activation is not None and activation.phase in TERMINAL_PHASES:
                deps.persist_terminal_journal(activation)
                activation = None

            server = deps.start_waitress(settings)
            deps.wait_until_ready(settings)
            deps.verify_post_start_routes(settings)
            if chrome is not None:
                deps.open_chrome(chrome, settings)
            deps.wait_until_ready(settings)

            if activation is not None:
                activation = deps.mark_ready(activation)
                activation = deps.finalize_activation(activation)
                deps.persist_terminal_journal(activation)
                activation = None
        except BaseException as error:
            if not startup_failure_recorded and not isinstance(error, KeyboardInterrupt):
                record_startup_failure(UNEXPECTED_FAILURE)
            if server is not None:
                deps.stop_server(server)
            recovered = deps.recover_startup_failure(
                settings,
                activation,
                failure_code=type(error).__name__.upper()[:64],
                failure_detail=str(error)[:4000],
            )
            if recovered is not None and recovered.phase in TERMINAL_PHASES:
                deps.run_django_preflight()
                deps.persist_terminal_journal(recovered)
            raise
