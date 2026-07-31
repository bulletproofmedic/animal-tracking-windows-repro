from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections.abc import Callable, Iterable
from pathlib import Path

CHECK_INTERVAL = 256


class Cancelled(RuntimeError):
    pass


class CancellationToken:
    def __init__(self, cancel_after_checks: int | None = None) -> None:
        self.cancel_after_checks = cancel_after_checks
        self.checks = 0

    def check(self) -> None:
        self.checks += 1
        if self.cancel_after_checks is not None and self.checks >= self.cancel_after_checks:
            raise Cancelled("cancelled")


class SQLiteSnapshot:
    def __init__(
        self,
        database: Path,
        *,
        after_state_read: Callable[[], None] | None = None,
    ) -> None:
        self.database = database
        self.after_state_read = after_state_read
        self.connection: sqlite3.Connection | None = None
        self.source_revision: int | None = None
        self.rows: tuple[str, ...] = ()
        self.session_ids: list[int] = []
        self.close_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.closed = False
        self.entered = False

    def __enter__(self) -> "SQLiteSnapshot":
        if self.entered or self.closed:
            raise RuntimeError("snapshot cannot be reopened")
        connection = sqlite3.connect(self.database, isolation_level=None, timeout=5.0)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        self.connection = connection
        self.entered = True
        try:
            self.source_revision = int(
                self._execute("SELECT revision FROM source_state WHERE singleton = 1").fetchone()[0]
            )
            if self.after_state_read is not None:
                self.after_state_read()
            self.rows = tuple(
                str(row[0])
                for row in self._execute("SELECT stable_id FROM projected_row ORDER BY stable_id")
            )
            return self
        except BaseException:
            self._finish(success=False)
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._finish(success=exc_type is None)

    def close(self) -> None:
        self._finish(success=True)

    def stream_rows(self) -> Iterable[str]:
        self._require_open()
        self._record_session()
        return iter(self.rows)

    def current_source_revision(self) -> int:
        self._require_open()
        self._record_session()
        assert self.source_revision is not None
        return self.source_revision

    def _execute(self, sql: str) -> sqlite3.Cursor:
        self._require_connection()
        self._record_session()
        assert self.connection is not None
        return self.connection.execute(sql)

    def _record_session(self) -> None:
        self._require_connection()
        assert self.connection is not None
        self.session_ids.append(id(self.connection))

    def _require_connection(self) -> None:
        if self.connection is None or self.closed:
            raise RuntimeError("snapshot is not open")

    def _require_open(self) -> None:
        if not self.entered or self.closed:
            raise RuntimeError("snapshot is not open")

    def _finish(self, *, success: bool) -> None:
        if self.closed:
            return
        self.closed = True
        connection = self.connection
        self.connection = None
        if connection is None:
            return
        try:
            if success:
                connection.commit()
                self.commit_calls += 1
            else:
                connection.rollback()
                self.rollback_calls += 1
        finally:
            connection.close()
            self.close_calls += 1


def build_rows(
    snapshot: SQLiteSnapshot,
    token: CancellationToken,
    *,
    fail_post_read_validation: bool = False,
) -> tuple[int, tuple[str, ...]]:
    token.check()
    with snapshot:
        initial_revision = snapshot.current_source_revision()
        rows: list[str] = []
        token.check()
        for index, row in enumerate(snapshot.stream_rows(), start=1):
            rows.append(row)
            if index % CHECK_INTERVAL == 0:
                token.check()
        token.check()
        final_revision = snapshot.current_source_revision()
        if final_revision != initial_revision:
            raise RuntimeError("source state changed")
    if fail_post_read_validation:
        raise RuntimeError("post-read validation failed")
    token.check()
    return initial_revision, tuple(rows)


def initialize_database(path: Path, *, row_count: int = 1) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            "CREATE TABLE source_state (singleton INTEGER PRIMARY KEY, revision INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE projected_row (stable_id TEXT PRIMARY KEY, source_revision INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO source_state VALUES (1, 1)")
        connection.executemany(
            "INSERT INTO projected_row VALUES (?, 1)",
            [(f"row-{index:04d}",) for index in range(1, row_count + 1)],
        )
        connection.commit()
    finally:
        connection.close()


def mutate_database(path: Path) -> None:
    connection = sqlite3.connect(path, isolation_level=None, timeout=5.0)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE source_state SET revision = 2 WHERE singleton = 1")
        connection.execute("INSERT INTO projected_row VALUES ('row-later', 2)")
        connection.commit()
    finally:
        connection.close()


def read_current_database(path: Path) -> tuple[int, int]:
    connection = sqlite3.connect(path)
    try:
        revision = int(connection.execute("SELECT revision FROM source_state").fetchone()[0])
        row_count = int(connection.execute("SELECT COUNT(*) FROM projected_row").fetchone()[0])
        return revision, row_count
    finally:
        connection.close()


class SQLiteSnapshotTests(unittest.TestCase):
    def database(self, *, row_count: int = 1) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "snapshot.sqlite3"
        initialize_database(path, row_count=row_count)
        return temporary, path

    def test_one_transaction_retains_atomic_view_across_concurrent_commit(self) -> None:
        temporary, path = self.database()
        self.addCleanup(temporary.cleanup)
        snapshot = SQLiteSnapshot(path, after_state_read=lambda: mutate_database(path))

        revision, rows = build_rows(snapshot, CancellationToken())

        self.assertEqual(revision, 1)
        self.assertEqual(rows, ("row-0001",))
        self.assertEqual(len(set(snapshot.session_ids)), 1)
        self.assertEqual(snapshot.close_calls, 1)
        self.assertEqual(snapshot.commit_calls, 1)
        current_revision, current_row_count = read_current_database(path)
        self.assertEqual(current_revision, 2)
        self.assertEqual(current_row_count, 2)

    def test_exception_rolls_back_and_closes_once(self) -> None:
        temporary, path = self.database()
        self.addCleanup(temporary.cleanup)
        snapshot = SQLiteSnapshot(path)

        with self.assertRaisesRegex(RuntimeError, "forced"):
            with snapshot:
                raise RuntimeError("forced")

        self.assertEqual(snapshot.close_calls, 1)
        self.assertEqual(snapshot.rollback_calls, 1)
        snapshot.close()
        self.assertEqual(snapshot.close_calls, 1)

    def test_cancellation_at_256_rows_closes_once(self) -> None:
        temporary, path = self.database(row_count=256)
        self.addCleanup(temporary.cleanup)
        snapshot = SQLiteSnapshot(path)

        with self.assertRaises(Cancelled):
            build_rows(snapshot, CancellationToken(cancel_after_checks=3))

        self.assertEqual(snapshot.close_calls, 1)
        self.assertEqual(snapshot.rollback_calls, 1)

    def test_post_read_validation_failure_occurs_after_close(self) -> None:
        temporary, path = self.database()
        self.addCleanup(temporary.cleanup)
        snapshot = SQLiteSnapshot(path)

        with self.assertRaisesRegex(RuntimeError, "post-read validation failed"):
            build_rows(
                snapshot,
                CancellationToken(),
                fail_post_read_validation=True,
            )

        self.assertTrue(snapshot.closed)
        self.assertEqual(snapshot.close_calls, 1)
        self.assertEqual(snapshot.commit_calls, 1)

    def test_closed_snapshot_rejects_reads(self) -> None:
        temporary, path = self.database()
        self.addCleanup(temporary.cleanup)
        snapshot = SQLiteSnapshot(path)
        with snapshot:
            self.assertEqual(tuple(snapshot.stream_rows()), ("row-0001",))

        with self.assertRaisesRegex(RuntimeError, "not open"):
            tuple(snapshot.stream_rows())

    def test_snapshot_cannot_be_reopened(self) -> None:
        temporary, path = self.database()
        self.addCleanup(temporary.cleanup)
        snapshot = SQLiteSnapshot(path)
        with snapshot:
            pass

        with self.assertRaisesRegex(RuntimeError, "cannot be reopened"):
            snapshot.__enter__()


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SQLiteSnapshotTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "schema_version": "1.0",
        "control_class": "PR17_F007_SQLITE_TRANSACTION_SNAPSHOT",
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "total": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "result": "PASS" if result.wasSuccessful() else "FAIL",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
