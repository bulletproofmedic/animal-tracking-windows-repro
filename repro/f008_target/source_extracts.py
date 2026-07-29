"""Sanitized control-flow reproducer for target 42c72f37d3e17f2ad51ec16c867acdfdf1458dc9.

The strict parser is exact. These lifecycle extracts preserve the target read-before-mutation ordering
while minimizing unrelated dependencies and implementation detail for public Windows execution.
Exact source identity is recorded in SOURCE_SNAPSHOT.json and verified separately.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path


class StartupError(RuntimeError):
    pass


# Dependency names are supplied by the test harness.

def startup_read_journal(journal_path: Path) -> dict[str, object]:
    try:
        return read_strict_json_object(journal_path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StartupError("The restore activation journal is malformed.") from exc


def startup_load_current_journal(settings):
    journal_path = stable_restore_journal_path(settings.paths)
    legacy_path = legacy_pending_marker_path(settings.paths)
    if journal_path.exists() and legacy_path.exists():
        raise StartupError("Conflicting current and legacy restore markers exist.")
    if legacy_path.exists():
        raise StartupError(
            "A legacy restore marker cannot satisfy activation-time integrity checks; "
            "remove the staged legacy restore and stage the backup again."
        )
    if not journal_path.exists():
        return None
    return journal_path, startup_read_journal(journal_path)


def startup_apply_pending_restore(settings, *, recovery_lock):
    _require_lock(recovery_lock)
    loaded = startup_load_current_journal(settings)
    if loaded is None:
        return None
    journal_path, journal = loaded
    activation = _validated_activation(settings, journal_path, journal)
    phase = activation.phase

    if phase in _PREACTIVATION_PHASES:
        _verify_archive_identity(activation, journal)
        _verify_snapshot_identity(activation, journal)

    if phase in {"STAGED", "ACTIVE_RENAME_PENDING"}:
        if phase == "STAGED":
            _verify_staged_identity(activation, journal)
            journal = _write_transition(
                journal_path,
                journal,
                "ACTIVE_RENAME_PENDING",
                reason="STAGED_TREE_REVERIFIED",
            )
        if activation.active_root.exists() and not activation.rollback_root.exists():
            durable_replace(activation.active_root, activation.rollback_root)
        elif not activation.active_root.exists() and activation.rollback_root.exists():
            pass
        else:
            raise StartupError("The active-to-rollback rename state is inconsistent.")
        journal = _write_transition(
            journal_path,
            journal,
            "ACTIVE_MOVED",
            reason="ACTIVE_ROOT_MOVED_TO_ROLLBACK",
        )
        phase = "ACTIVE_MOVED"

    if phase in {"ACTIVE_MOVED", "STAGED_RENAME_PENDING"}:
        if phase == "ACTIVE_MOVED":
            journal = _write_transition(
                journal_path,
                journal,
                "STAGED_RENAME_PENDING",
                reason="STAGED_ACTIVATION_PREPARED",
            )
        if (
            not activation.active_root.exists()
            and activation.staged_root.exists()
            and activation.rollback_root.exists()
        ):
            _verify_archive_identity(activation, journal)
            _verify_staged_identity(activation, journal)
            durable_replace(activation.staged_root, activation.active_root)
        elif (
            activation.active_root.exists()
            and not activation.staged_root.exists()
            and activation.rollback_root.exists()
        ):
            pass
        else:
            raise StartupError("The staged-to-active rename state is inconsistent.")
        journal = _write_transition(
            journal_path,
            journal,
            "ACTIVATED_PENDING_PREFLIGHT",
            reason="STAGED_ROOT_ACTIVATED",
        )
        phase = "ACTIVATED_PENDING_PREFLIGHT"

    if phase in {"ROLLBACK_PENDING", "FAILED_ROOT_MOVED"}:
        return _resume_rollback(activation, journal, recovery_lock=recovery_lock)

    if phase == "FINALIZE_PENDING":
        journal = _complete_pending_finalization(activation, journal)
        phase = str(journal["phase"])

    if phase in {"ACTIVATED_PENDING_PREFLIGHT", "PREFLIGHT_PASSED", "READY"}:
        if not activation.active_root.is_dir() or not activation.rollback_root.is_dir():
            raise StartupError("The activated restore lacks its active or rollback root.")
        if activation.staged_root.exists():
            raise StartupError("The activated restore unexpectedly retains a staging root.")

    if phase == "ROLLED_BACK" and (
        not activation.active_root.is_dir() or activation.rollback_root.exists()
    ):
        raise StartupError("The durable rolled-back state is inconsistent.")

    if phase == "FINALIZED" and (
        not activation.active_root.is_dir() or activation.rollback_root.exists()
    ):
        raise StartupError("The durable finalized state is inconsistent.")

    return replace(activation, phase=phase)


def startup_mark_preflight_passed(activation, *, recovery_lock):
    _require_lock(recovery_lock)
    journal = startup_read_journal(activation.journal_path)
    updated = _write_transition(
        activation.journal_path,
        journal,
        "PREFLIGHT_PASSED",
        reason="DJANGO_CHECK_AND_MIGRATIONS_PASSED",
    )
    return replace(activation, phase=str(updated["phase"]))


def startup_mark_ready(activation, *, recovery_lock):
    _require_lock(recovery_lock)
    journal = startup_read_journal(activation.journal_path)
    updated = _write_transition(
        activation.journal_path,
        journal,
        "READY",
        reason="SERVER_HEALTH_ROUTE_AND_BROWSER_START_PASSED",
    )
    return replace(activation, phase=str(updated["phase"]))


def staging_read_journal(path: Path) -> dict[str, object]:
    try:
        return read_strict_json_object(path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StartupError("The restore staging journal is malformed.") from exc


def staging_reconcile_interrupted_staging(settings, *, recovery_lock):
    if not recovery_lock.acquired:
        raise StartupError("Interrupted restore staging requires the stable recovery lock.")

    journal_path = stable_restore_journal_path(settings.paths)
    if not journal_path.exists():
        return False
    journal = staging_read_journal(journal_path)
    if journal.get("phase") != _PREPARING_PHASE:
        return False

    operation_id, active_root, staged_root, rollback_root, _snapshot = _validated_preparing_paths(
        settings,
        journal,
    )
    if not active_root.is_dir():
        raise StartupError("Interrupted restore staging lacks the active authoritative root.")
    if rollback_root.exists():
        raise StartupError("Interrupted restore staging unexpectedly created a rollback root.")

    failed_root = stable_failed_root(settings.paths, operation_id).resolve()
    if staged_root.exists():
        if failed_root.exists():
            raise StartupError("Interrupted restore staging has conflicting candidate roots.")
        failed_root.parent.mkdir(parents=True, exist_ok=True)
        durable_replace(staged_root, failed_root)
    elif failed_root.exists():
        pass

    updated = _append_terminal_transition(
        journal,
        reason="INTERRUPTED_STAGING_RECONCILED",
        error_code="RESTORE_STAGING_INTERRUPTED",
    )
    atomic_write_json(journal_path, updated)
    return True


def staging_archive_failed_preparing_journal(paths, *, operation_id: str, error_code: str):
    journal_path = stable_restore_journal_path(paths)
    if not journal_path.exists():
        return None
    journal = staging_read_journal(journal_path)
    if journal.get("phase") != _PREPARING_PHASE or str(journal.get("operation_id")) != operation_id:
        return None
    updated = _append_terminal_transition(
        journal,
        reason="STAGING_FAILURE_CLEANED_BEFORE_ACTIVATION",
        error_code=error_code,
    )
    history_path = stable_journal_history_path(paths, operation_id)
    atomic_write_json(history_path, updated)
    journal_path.unlink()
    fsync_directory(journal_path.parent)
    return history_path


def post_restore_read_journal(path: Path) -> dict[str, object]:
    try:
        return read_strict_json_object(path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StartupError("The restore activation journal is malformed.") from exc


def post_restore_run(activation, *, settings, recovery_lock, finalizers=None):
    if not recovery_lock.acquired:
        raise StartupError("Post-restore finalization requires the stable recovery lock.")
    if activation.phase != "ACTIVATED_PENDING_PREFLIGHT":
        return activation

    journal = post_restore_read_journal(activation.journal_path)
    if str(journal.get("phase")) != "ACTIVATED_PENDING_PREFLIGHT":
        raise StartupError("Post-restore finalizers require the activated preflight phase.")
    records = _records(journal)
    selected = tuple(finalizers) if finalizers is not None else get_post_restore_finalizers()
    ordered = sorted(
        selected,
        key=lambda row: (str(row.finalizer_id), str(row.finalizer_version)),
    )
    seen: set[str] = set()

    for finalizer in ordered:
        finalizer_id = str(finalizer.finalizer_id)
        finalizer_version = str(finalizer.finalizer_version)
        if not finalizer_id or not finalizer_version:
            raise StartupError("A post-restore finalizer has an empty identity.")
        if finalizer_id in seen:
            raise StartupError(f"Duplicate post-restore finalizer identity: {finalizer_id}")
        seen.add(finalizer_id)
        finalizer.finalize_post_restore(None)
    return activation


def lineage_read_terminal_journal(instance, *, synthesize_missing_lineage: bool = True):
    validation_result = instance.validation_result
    if (
        not isinstance(validation_result, dict)
        or validation_result.get("journal_phase") not in TERMINAL_STATUSES
    ):
        return None
    path = _journal_path_for_operation(instance)
    if path is None or not path.is_file():
        raise StartupError("The terminal restore journal is unavailable for package lineage.")
    try:
        journal = read_strict_json_object(path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StartupError(
            "The terminal restore journal is malformed for package lineage."
        ) from exc
    if str(journal.get("operation_id")) != str(instance.id):
        raise StartupError("The terminal restore journal operation identity does not match.")
    if journal.get("phase") not in TERMINAL_STATUSES:
        raise StartupError("Package lineage requires a terminal restore journal.")
    if "backup_lineage" not in journal:
        if not synthesize_missing_lineage:
            return None
        journal["backup_lineage"] = build_lineage(journal)
        atomic_write_json(path, journal)
    return journal


def materialize_terminal_lineage(instance, *, synthesize_missing_lineage: bool = True):
    journal = lineage_read_terminal_journal(
        instance,
        synthesize_missing_lineage=synthesize_missing_lineage,
    )
    if journal is None:
        return
    lineage = journal.get("backup_lineage")
    if not isinstance(lineage, dict):
        raise StartupError("The terminal restore journal lacks package lineage.")
    _validate_terminal_lineage(lineage)
    mutation_boundary()
