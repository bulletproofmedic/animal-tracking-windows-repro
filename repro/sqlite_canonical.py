from __future__ import annotations

from pathlib import Path, PurePosixPath

DATABASE_PATH = "data/animal_tracking.sqlite3"


def normalize(value: str) -> str:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts:
        raise ValueError("invalid archive path")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("invalid archive path")
    if "\\" in value:
        raise ValueError("invalid archive path")
    return candidate.as_posix()


def is_transient_archive_path(value: str) -> bool:
    candidate = PurePosixPath(normalize(value))
    database = PurePosixPath(DATABASE_PATH)
    if candidate.parent.as_posix().casefold() != database.parent.as_posix().casefold():
        return False
    candidate_name = candidate.name.casefold()
    database_name = database.name.casefold()
    return candidate_name != database_name and (
        candidate_name.startswith(f"{database_name}-")
        or candidate_name.startswith(f"{database_name}.")
    )


def validate_members(members: list[str]) -> None:
    if DATABASE_PATH not in members:
        raise ValueError("main database missing")
    for member in members:
        if is_transient_archive_path(member):
            raise ValueError("transient SQLite sidecar rejected")


def validate_staged_database(database: Path) -> None:
    if not database.is_file():
        raise ValueError("main database missing")
    database_name = database.name.casefold()
    for sibling in database.parent.iterdir():
        name = sibling.name.casefold()
        if name == database_name:
            continue
        if name.startswith(f"{database_name}-") or name.startswith(f"{database_name}."):
            raise ValueError("transient SQLite sidecar rejected")
