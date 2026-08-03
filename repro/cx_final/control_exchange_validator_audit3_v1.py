"""Audit Report 3 semantic rule overrides for Control Exchange evaluator 1.3.0."""

from __future__ import annotations

from typing import Any

import control_exchange_validator_audit3_recovery_v1 as recovery
import control_exchange_validator_audit3_time_transaction_v1 as time_transaction

VERSION = "1.3.0"


def rule_overrides() -> dict[str, Any]:
    return {
        "CX-SV-005": time_transaction.rule_005,
        "CX-SV-021": time_transaction.rule_021,
        "CX-SV-022": time_transaction.rule_022,
        "CX-SV-024": recovery.rule_024,
    }
