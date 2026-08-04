from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIGRATION_PATH = HERE / "0008_interval_chronology_guards.py"
TABLES = (
    "persistence_bearinginterval",
    "persistence_operationalinterval",
    "persistence_cameraconfigurationinterval",
)


def load_migration_module():
    spec = importlib.util.spec_from_file_location("migration_0008", MIGRATION_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load migration 0008")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_schema(connection: sqlite3.Connection) -> None:
    for table in TABLES:
        connection.execute(
            f"""
            CREATE TABLE {table} (
                id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                valid_from_lower TEXT NOT NULL,
                valid_to_lower TEXT NULL,
                valid_to_upper TEXT NULL,
                status TEXT NOT NULL,
                supersedes_id TEXT NULL
            )
            """
        )


def apply_migration(connection: sqlite3.Connection) -> list[str]:
    module = load_migration_module()
    reverse_sql: list[str] = []
    for operation in module.Migration.operations:
        connection.executescript(operation.sql)
        reverse_sql.append(operation.reverse_sql)
    return reverse_sql


def insert_interval(
    connection: sqlite3.Connection,
    table: str,
    *,
    row_id: str,
    start: str,
    end_lower: str | None,
    end_upper: str | None = None,
    status: str = "FINAL",
    supersedes_id: str | None = None,
) -> None:
    connection.execute(
        f"""
        INSERT INTO {table} (
            id, deployment_id, valid_from_lower, valid_to_lower,
            valid_to_upper, status, supersedes_id
        ) VALUES (?, 'deployment-1', ?, ?, ?, ?, ?)
        """,
        (row_id, start, end_lower, end_upper, status, supersedes_id),
    )


class Migration0008Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        create_schema(self.connection)
        self.reverse_sql = apply_migration(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    def test_invalid_insert_rejected_for_every_governed_interval_table(self) -> None:
        for table in TABLES:
            with self.subTest(table=table):
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "interval end bounds are invalid"
                ):
                    insert_interval(
                        self.connection,
                        table,
                        row_id=f"bad-{table}",
                        start="2026-08-04T12:00:00Z",
                        end_lower="2026-08-04T11:59:59Z",
                    )

    def test_invalid_update_rejected(self) -> None:
        insert_interval(
            self.connection,
            "persistence_operationalinterval",
            row_id="row-1",
            start="2026-08-04T12:00:00Z",
            end_lower="2026-08-04T13:00:00Z",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "interval end bounds are invalid"
        ):
            self.connection.execute(
                """
                UPDATE persistence_operationalinterval
                SET valid_to_lower = '2026-08-04T11:59:59Z'
                WHERE id = 'row-1'
                """
            )

    def test_upper_only_insert_rejected_for_every_governed_interval_table(self) -> None:
        for table in TABLES:
            with self.subTest(table=table):
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "interval end bounds are invalid"
                ):
                    insert_interval(
                        self.connection,
                        table,
                        row_id=f"upper-only-{table}",
                        start="2026-08-04T12:00:00Z",
                        end_lower=None,
                        end_upper="2026-08-04T11:59:59Z",
                    )

    def test_upper_only_update_rejected_for_every_governed_interval_table(self) -> None:
        for table in TABLES:
            with self.subTest(table=table):
                row_id = f"upper-only-update-{table}"
                insert_interval(
                    self.connection,
                    table,
                    row_id=row_id,
                    start="2026-08-04T12:00:00Z",
                    end_lower="2026-08-04T13:00:00Z",
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "interval end bounds are invalid"
                ):
                    self.connection.execute(
                        f"""
                        UPDATE {table}
                        SET valid_to_lower = NULL,
                            valid_to_upper = '2026-08-04T11:59:59Z'
                        WHERE id = ?
                        """,
                        (row_id,),
                    )

    def test_upper_only_end_after_start_is_still_rejected(self) -> None:
        for table in TABLES:
            with self.subTest(table=table):
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "interval end bounds are invalid"
                ):
                    insert_interval(
                        self.connection,
                        table,
                        row_id=f"upper-only-after-start-{table}",
                        start="2026-08-04T12:00:00Z",
                        end_lower=None,
                        end_upper="2026-08-04T13:00:00Z",
                    )

    def test_latest_possible_bounded_end_is_enforced(self) -> None:
        insert_interval(
            self.connection,
            "persistence_operationalinterval",
            row_id="bounded-valid",
            start="2026-08-04T12:00:00Z",
            end_lower="2026-08-04T11:55:00Z",
            end_upper="2026-08-04T12:05:00Z",
        )
        count = self.connection.execute(
            "SELECT COUNT(*) FROM persistence_operationalinterval"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_failed_successor_insert_rolls_back_predecessor_retirement(self) -> None:
        insert_interval(
            self.connection,
            "persistence_operationalinterval",
            row_id="predecessor",
            start="2026-08-04T12:00:00Z",
            end_lower="2026-08-04T13:00:00Z",
        )
        self.connection.commit()

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "interval end bounds are invalid"
        ):
            with self.connection:
                self.connection.execute(
                    "UPDATE persistence_operationalinterval SET status = 'SUPERSEDED' WHERE id = 'predecessor'"
                )
                insert_interval(
                    self.connection,
                    "persistence_operationalinterval",
                    row_id="invalid-successor",
                    start="2026-08-04T12:00:00Z",
                    end_lower=None,
                    end_upper="2026-08-04T11:59:59Z",
                    supersedes_id="predecessor",
                )

        status = self.connection.execute(
            "SELECT status FROM persistence_operationalinterval WHERE id = 'predecessor'"
        ).fetchone()[0]
        self.assertEqual(status, "FINAL")

    def test_concurrent_replacement_commits_one_successor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "concurrency.sqlite3"
            setup = sqlite3.connect(database)
            create_schema(setup)
            apply_migration(setup)
            insert_interval(
                setup,
                "persistence_operationalinterval",
                row_id="predecessor",
                start="2026-08-04T12:00:00Z",
                end_lower="2026-08-04T13:00:00Z",
            )
            setup.commit()
            setup.close()

            barrier = threading.Barrier(2)
            results: list[str] = []
            results_lock = threading.Lock()

            def replace(suffix: str) -> None:
                connection = sqlite3.connect(database, timeout=30, isolation_level=None)
                try:
                    barrier.wait(timeout=10)
                    connection.execute("BEGIN IMMEDIATE")
                    status = connection.execute(
                        "SELECT status FROM persistence_operationalinterval WHERE id = 'predecessor'"
                    ).fetchone()[0]
                    if status != "FINAL":
                        connection.rollback()
                        result = "CONFLICT"
                    else:
                        connection.execute(
                            "UPDATE persistence_operationalinterval SET status = 'SUPERSEDED' WHERE id = 'predecessor'"
                        )
                        insert_interval(
                            connection,
                            "persistence_operationalinterval",
                            row_id=f"successor-{suffix}",
                            start="2026-08-04T12:00:00Z",
                            end_lower="2026-08-04T13:00:00Z",
                            supersedes_id="predecessor",
                        )
                        connection.commit()
                        result = "COMMITTED"
                finally:
                    connection.close()
                with results_lock:
                    results.append(result)

            threads = [
                threading.Thread(target=replace, args=("a",)),
                threading.Thread(target=replace, args=("b",)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=40)
                self.assertFalse(thread.is_alive())

            self.assertEqual(sorted(results), ["COMMITTED", "CONFLICT"])
            check = sqlite3.connect(database)
            final_count = check.execute(
                "SELECT COUNT(*) FROM persistence_operationalinterval WHERE status = 'FINAL'"
            ).fetchone()[0]
            predecessor_status = check.execute(
                "SELECT status FROM persistence_operationalinterval WHERE id = 'predecessor'"
            ).fetchone()[0]
            check.close()
            self.assertEqual(final_count, 1)
            self.assertEqual(predecessor_status, "SUPERSEDED")

    def test_reverse_sql_removes_all_guards(self) -> None:
        for sql in reversed(self.reverse_sql):
            self.connection.executescript(sql)
        insert_interval(
            self.connection,
            "persistence_operationalinterval",
            row_id="rollback-allows-pre-migration-shape",
            start="2026-08-04T12:00:00Z",
            end_lower=None,
            end_upper="2026-08-04T11:59:59Z",
        )
        count = self.connection.execute(
            "SELECT COUNT(*) FROM persistence_operationalinterval"
        ).fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
