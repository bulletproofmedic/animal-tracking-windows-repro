from __future__ import annotations

import json
from pathlib import Path


def reject_duplicate_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build one JSON object while rejecting alternate duplicate-key representations."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def read_strict_json_object(path: Path) -> dict[str, object]:
    """Read a UTF-8 JSON object and reject duplicate keys at every nesting level."""
    raw: object = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_object_pairs,
    )
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError("JSON document must contain one object with string keys.")
    return dict(raw)
