from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import Any

from repro import core_hardening_reproducer as _core

_original_normalize = _core._normalize


def _normalize_dataclasses(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _normalize_dataclasses(getattr(value, field.name))
            for field in fields(value)
        }
    return _original_normalize(value)


_core._normalize = _normalize_dataclasses
