from django.db import migrations


_INTERVAL_TABLES = (
    (
        "persistence_bearinginterval",
        "bearing_interval_chronology",
    ),
    (
        "persistence_operationalinterval",
        "operational_interval_chronology",
    ),
    (
        "persistence_cameraconfigurationinterval",
        "configuration_interval_chronology",
    ),
)


def _invalid_end_condition() -> str:
    return """
(
    NEW.valid_to_upper IS NOT NULL
    AND NEW.valid_to_lower IS NULL
)
OR
(
    COALESCE(NEW.valid_to_upper, NEW.valid_to_lower) IS NOT NULL
    AND COALESCE(NEW.valid_to_upper, NEW.valid_to_lower) < NEW.valid_from_lower
)
""".strip()


def _insert_guard(table: str, prefix: str) -> str:
    return f"""
CREATE TRIGGER {prefix}_insert_guard
BEFORE INSERT ON {table}
FOR EACH ROW
WHEN {_invalid_end_condition()}
BEGIN
    SELECT RAISE(ABORT, 'interval end bounds are invalid');
END;
""".strip()


def _update_guard(table: str, prefix: str) -> str:
    return f"""
CREATE TRIGGER {prefix}_update_guard
BEFORE UPDATE OF valid_from_lower, valid_to_lower, valid_to_upper ON {table}
FOR EACH ROW
WHEN {_invalid_end_condition()}
BEGIN
    SELECT RAISE(ABORT, 'interval end bounds are invalid');
END;
""".strip()


def _drop_guard(prefix: str, suffix: str) -> str:
    return f"DROP TRIGGER IF EXISTS {prefix}_{suffix}_guard;"


class Migration(migrations.Migration):
    dependencies = [
        ("persistence", "0007_map_calibration_acceptance_provenance"),
    ]

    operations = [
        *(
            migrations.RunSQL(
                sql=_insert_guard(table, prefix),
                reverse_sql=_drop_guard(prefix, "insert"),
            )
            for table, prefix in _INTERVAL_TABLES
        ),
        *(
            migrations.RunSQL(
                sql=_update_guard(table, prefix),
                reverse_sql=_drop_guard(prefix, "update"),
            )
            for table, prefix in _INTERVAL_TABLES
        ),
    ]
