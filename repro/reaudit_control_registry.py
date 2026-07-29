from __future__ import annotations

CONTROL_IDS = {
    *(f"AT-WAL-008-F-{index:03d}" for index in range(1, 10)),
    "AT-WAL-008-R2-F-010",
}

PRIVATE_SUCCESSOR = "ffe1e2b426d40ad7bd212684b326d6758004adaf"
