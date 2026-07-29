from __future__ import annotations

CONTROL_IDS = {
    *(f"AT-WAL-008-F-{index:03d}" for index in range(1, 10)),
    "AT-WAL-008-R2-F-010",
}

PRIVATE_SUCCESSOR = "264cc30b30520960d107dbaa4c50219a7c80bda5"
