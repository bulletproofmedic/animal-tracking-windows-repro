from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from repro.sqlite_canonical import (
    DATABASE_PATH,
    is_transient_archive_path,
    validate_members,
    validate_staged_database,
)


class SqliteCanonicalizationTests(unittest.TestCase):
    def test_sidecar_namespace_is_rejected_case_insensitively(self) -> None:
        for member in (
            f"{DATABASE_PATH}-wal",
            f"{DATABASE_PATH}-shm",
            f"{DATABASE_PATH}-journal",
            f"{DATABASE_PATH}-mj0123456789abcdef",
            f"{DATABASE_PATH}.super-journal",
            f"{DATABASE_PATH}.tmp",
            "DATA/ANIMAL_TRACKING.SQLITE3-WAL",
        ):
            with self.subTest(member=member):
                self.assertTrue(is_transient_archive_path(member))
                with self.assertRaisesRegex(ValueError, "transient SQLite sidecar"):
                    validate_members([DATABASE_PATH, member])

    def test_real_wal_only_schema_and_shm_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "animal_tracking.sqlite3"
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
                connection.execute("CREATE TABLE base_state (id INTEGER PRIMARY KEY)")
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
                connection.execute(
                    "CREATE TABLE wal_only_schema (id INTEGER PRIMARY KEY, value TEXT)"
                )
                connection.execute("INSERT INTO wal_only_schema(value) VALUES ('wal-only')")
                connection.commit()
                wal = database.with_name(f"{database.name}-wal")
                shm = database.with_name(f"{database.name}-shm")
                self.assertTrue(wal.is_file())
                members = [DATABASE_PATH, f"{DATABASE_PATH}-wal"]
                if shm.is_file():
                    members.append(f"{DATABASE_PATH}-shm")
                with self.assertRaisesRegex(ValueError, "transient SQLite sidecar"):
                    validate_members(members)
                with self.assertRaisesRegex(ValueError, "transient SQLite sidecar"):
                    validate_staged_database(database)
            finally:
                connection.close()

    def test_real_rollback_journal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "animal_tracking.sqlite3"
            with closing(sqlite3.connect(database)) as setup:
                setup.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)")
                setup.execute("INSERT INTO sample(value) VALUES ('base')")
                setup.commit()
            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE sample SET value = 'journal-only' WHERE id = 1")
                journal = database.with_name(f"{database.name}-journal")
                self.assertTrue(journal.is_file())
                with self.assertRaisesRegex(ValueError, "transient SQLite sidecar"):
                    validate_members([DATABASE_PATH, f"{DATABASE_PATH}-journal"])
                with self.assertRaisesRegex(ValueError, "transient SQLite sidecar"):
                    validate_staged_database(database)
            finally:
                connection.rollback()
                connection.close()

    def test_checkpointed_main_database_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "animal_tracking.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)")
                connection.execute("INSERT INTO sample(value) VALUES ('canonical')")
                connection.commit()
            validate_members([DATABASE_PATH])
            validate_staged_database(database)
            with closing(
                sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
            ) as connection:
                self.assertEqual(
                    connection.execute("SELECT value FROM sample").fetchone(),
                    ("canonical",),
                )

    def test_mixed_and_truncated_sidecars_never_reach_semantic_validation(self) -> None:
        variants = [
            f"{DATABASE_PATH}-wal",
            f"{DATABASE_PATH}-shm",
            f"{DATABASE_PATH}-journal",
        ]
        with self.assertRaisesRegex(ValueError, "transient SQLite sidecar"):
            validate_members([DATABASE_PATH, *variants])


if __name__ == "__main__":
    unittest.main()
