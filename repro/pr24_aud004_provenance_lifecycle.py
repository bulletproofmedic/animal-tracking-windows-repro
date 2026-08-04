from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

PRIVATE_PR24_HEAD = "9aa4c6906cd04f7483d9bed4aa125f66e5a2d690"
PRIVATE_MERGE_TARGET = "b2a97af503bf8d054bc2dbd3370ec577697208dd"
PRIVATE_MIGRATION_BLOB = "8c2483d6a9351001d2f0b8d2310fc7d63ebd9bdc"

PROOF_TABLE = "synthetic_acceptance_proof"
PROOF_TRIGGERS = {
    "synthetic_proof_insert_guard",
    "synthetic_proof_update_guard",
    "synthetic_proof_delete_guard",
    "synthetic_acceptance_requires_proof",
}


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_schema_0006(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE synthetic_property (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE' UNIQUE
        );

        CREATE TABLE synthetic_calibration (
            id TEXT PRIMARY KEY,
            property_id INTEGER NOT NULL REFERENCES synthetic_property(id),
            version TEXT NOT NULL,
            evidence_reference TEXT NOT NULL,
            assessor TEXT NOT NULL,
            tolerance REAL NOT NULL,
            residual REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'DRAFT'
        );

        CREATE TRIGGER synthetic_0006_evidence_guard
        BEFORE UPDATE OF status ON synthetic_calibration
        FOR EACH ROW
        WHEN NEW.status = 'ACCEPTED'
          AND (
              trim(NEW.version) = ''
              OR trim(NEW.evidence_reference) = ''
              OR trim(NEW.assessor) = ''
              OR NEW.tolerance <= 0
              OR NEW.residual < 0
              OR NEW.residual > NEW.tolerance
          )
        BEGIN
            SELECT RAISE(ABORT, 'accepted state lacks evidence');
        END;
        """
    )


def apply_schema_0007(connection: sqlite3.Connection) -> None:
    connection.executescript(
        f"""
        CREATE TABLE {PROOF_TABLE} (
            calibration_id TEXT PRIMARY KEY
                REFERENCES synthetic_calibration(id) DEFERRABLE INITIALLY DEFERRED,
            actor TEXT NOT NULL,
            authority_reference TEXT NOT NULL,
            accepted_at TEXT NOT NULL
        );

        CREATE TRIGGER synthetic_proof_insert_guard
        BEFORE INSERT ON {PROOF_TABLE}
        FOR EACH ROW
        WHEN trim(NEW.actor) = ''
          OR trim(NEW.authority_reference) = ''
          OR trim(NEW.accepted_at) = ''
          OR NOT EXISTS (
              SELECT 1
              FROM synthetic_calibration calibration
              WHERE calibration.id = NEW.calibration_id
                AND calibration.status = 'DRAFT'
          )
        BEGIN
            SELECT RAISE(ABORT, 'acceptance proof is invalid');
        END;

        CREATE TRIGGER synthetic_proof_update_guard
        BEFORE UPDATE ON {PROOF_TABLE}
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'acceptance proof is immutable');
        END;

        CREATE TRIGGER synthetic_proof_delete_guard
        BEFORE DELETE ON {PROOF_TABLE}
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'acceptance proof is immutable');
        END;

        CREATE TRIGGER synthetic_acceptance_requires_proof
        BEFORE UPDATE OF status ON synthetic_calibration
        FOR EACH ROW
        WHEN NEW.status = 'ACCEPTED'
          AND NOT EXISTS (
              SELECT 1
              FROM {PROOF_TABLE} proof
              WHERE proof.calibration_id = NEW.id
                AND trim(proof.actor) <> ''
                AND trim(proof.authority_reference) <> ''
                AND trim(proof.accepted_at) <> ''
          )
        BEGIN
            SELECT RAISE(ABORT, 'accepted state lacks governed proof');
        END;
        """
    )


def rollback_schema_0007(connection: sqlite3.Connection) -> None:
    connection.executescript(
        f"""
        DROP TRIGGER IF EXISTS synthetic_acceptance_requires_proof;
        DROP TRIGGER IF EXISTS synthetic_proof_delete_guard;
        DROP TRIGGER IF EXISTS synthetic_proof_update_guard;
        DROP TRIGGER IF EXISTS synthetic_proof_insert_guard;
        DROP TABLE IF EXISTS {PROOF_TABLE};
        """
    )


def schema_objects(connection: sqlite3.Connection) -> tuple[set[str], set[str]]:
    triggers = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        )
    }
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    return triggers, tables


def verify_0007_present(connection: sqlite3.Connection) -> None:
    triggers, tables = schema_objects(connection)
    missing = PROOF_TRIGGERS - triggers
    assert not missing, f"missing proof triggers: {sorted(missing)}"
    assert PROOF_TABLE in tables, "proof table is missing"


def verify_0007_absent(connection: sqlite3.Connection) -> None:
    triggers, tables = schema_objects(connection)
    assert not (PROOF_TRIGGERS & triggers), "proof triggers survived rollback"
    assert PROOF_TABLE not in tables, "proof table survived rollback"


def seed(connection: sqlite3.Connection, label: str) -> str:
    property_row = connection.execute(
        "SELECT id FROM synthetic_property ORDER BY id LIMIT 1"
    ).fetchone()
    if property_row is None:
        property_id = connection.execute(
            "INSERT INTO synthetic_property(name) VALUES (?) RETURNING id",
            (f"Synthetic {label} property",),
        ).fetchone()[0]
    else:
        property_id = property_row[0]

    calibration_id = f"calibration-{label}"
    connection.execute(
        """
        INSERT INTO synthetic_calibration(
            id,
            property_id,
            version,
            evidence_reference,
            assessor,
            tolerance,
            residual,
            status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'DRAFT')
        """,
        (
            calibration_id,
            property_id,
            f"version-{label}",
            f"evidence-{label}",
            "synthetic-actor",
            0.1,
            0.0,
        ),
    )
    connection.commit()
    return calibration_id


def direct_acceptance_rejected(
    connection: sqlite3.Connection,
    calibration_id: str,
) -> None:
    try:
        connection.execute(
            "UPDATE synthetic_calibration SET status = 'ACCEPTED' WHERE id = ?",
            (calibration_id,),
        )
    except sqlite3.IntegrityError as exc:
        assert "lacks governed proof" in str(exc)
        connection.rollback()
    else:
        raise AssertionError("direct acceptance bypassed the proof boundary")


def governed_acceptance(
    connection: sqlite3.Connection,
    calibration_id: str,
) -> None:
    with connection:
        connection.execute(
            f"""
            INSERT INTO {PROOF_TABLE}(
                calibration_id,
                actor,
                authority_reference,
                accepted_at
            ) VALUES (?, 'synthetic-actor', 'synthetic-authority', '2026-08-04T00:00:00Z')
            """,
            (calibration_id,),
        )
        connection.execute(
            "UPDATE synthetic_calibration SET status = 'ACCEPTED' WHERE id = ?",
            (calibration_id,),
        )


def projection_is_usable(
    connection: sqlite3.Connection,
    calibration_id: str,
) -> bool:
    row = connection.execute(
        f"""
        SELECT calibration.status, proof.calibration_id
        FROM synthetic_calibration calibration
        LEFT JOIN {PROOF_TABLE} proof
          ON proof.calibration_id = calibration.id
        WHERE calibration.id = ?
        """,
        (calibration_id,),
    ).fetchone()
    return row == ("ACCEPTED", calibration_id)


def verify_proof_immutable(connection: sqlite3.Connection) -> None:
    for statement in (
        f"UPDATE {PROOF_TABLE} SET actor = 'tampered'",
        f"DELETE FROM {PROOF_TABLE}",
    ):
        try:
            connection.execute(statement)
        except sqlite3.IntegrityError as exc:
            assert "immutable" in str(exc)
            connection.rollback()
        else:
            raise AssertionError(f"proof mutation unexpectedly succeeded: {statement}")


def run_clean_install(root: Path) -> None:
    path = root / "clean.sqlite3"
    with connect(path) as connection:
        create_schema_0006(connection)
        apply_schema_0007(connection)
        verify_0007_present(connection)
        calibration_id = seed(connection, "clean")
        direct_acceptance_rejected(connection, calibration_id)
        governed_acceptance(connection, calibration_id)
        assert projection_is_usable(connection, calibration_id)
        verify_proof_immutable(connection)
    print("PUBLIC_CLEAN_INSTALL_0007=PASS")
    print("PUBLIC_DIRECT_ACCEPTANCE_REJECTION=PASS")
    print("PUBLIC_GOVERNED_PROOF_AND_PROJECTION=PASS")


def run_upgrade_rollback_reapply(root: Path) -> None:
    path = root / "upgrade.sqlite3"
    with connect(path) as connection:
        create_schema_0006(connection)
        legacy_id = seed(connection, "legacy")
        connection.execute(
            "UPDATE synthetic_calibration SET status = 'ACCEPTED' WHERE id = ?",
            (legacy_id,),
        )
        connection.commit()

        apply_schema_0007(connection)
        verify_0007_present(connection)
        assert not projection_is_usable(connection, legacy_id)
        print("PUBLIC_UPGRADE_0006_TO_0007=PASS")
        print("PUBLIC_LEGACY_ACCEPTED_WITHOUT_PROOF_UNUSABLE=PASS")

        rollback_schema_0007(connection)
        verify_0007_absent(connection)
        print("PUBLIC_ROLLBACK_0007_TO_0006=PASS")

        apply_schema_0007(connection)
        verify_0007_present(connection)
        reapply_id = seed(connection, "reapply")
        property_count = connection.execute(
            "SELECT COUNT(*) FROM synthetic_property"
        ).fetchone()[0]
        assert property_count == 1, "fixture failed to reuse the unique property row"
        direct_acceptance_rejected(connection, reapply_id)
        governed_acceptance(connection, reapply_id)
        assert projection_is_usable(connection, reapply_id)
        verify_proof_immutable(connection)
    print("PUBLIC_REAPPLY_0007=PASS")
    print("PUBLIC_REAPPLY_FIXTURE_PROPERTY_REUSE=PASS")
    print("PUBLIC_REAPPLY_PROVENANCE_BOUNDARY=PASS")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="pr24-aud004-") as temporary_directory:
        root = Path(temporary_directory)
        run_clean_install(root)
        run_upgrade_rollback_reapply(root)

    print(f"PRIVATE_PR24_HEAD={PRIVATE_PR24_HEAD}")
    print(f"PRIVATE_MERGE_TARGET={PRIVATE_MERGE_TARGET}")
    print(f"PRIVATE_MIGRATION_BLOB={PRIVATE_MIGRATION_BLOB}")
    print("PUBLIC_SANITIZED_PR24_AUD004_LIFECYCLE=PASS")


if __name__ == "__main__":
    main()
