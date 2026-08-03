"""Audit Report 3 recovery semantic overrides for Control Exchange evaluator 1.3.0."""

from __future__ import annotations

import hashlib
import json
from typing import Any

VERSION = "1.3.0"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def error(rule: str, code: str) -> str:
    return f"{rule}:{code}"


def _recovery_error(b: Any) -> str | None:
    checkpoint = b.record("recovery_checkpoint")
    head = b.record("recovery_head")
    sequence = checkpoint.get("checkpoint_sequence")
    work_receipt_id = checkpoint.get("work_receipt_id")
    transaction_id = checkpoint.get("transaction_id")
    universe = checkpoint.get("transaction_item_ids", [])
    successful = checkpoint.get("successful_items", [])
    remaining = checkpoint.get("remaining_items", [])
    uncertain = checkpoint.get("uncertain_items", [])
    if not isinstance(sequence, int) or sequence < 0:
        return "RECOVERY_SEQUENCE"
    expected_id = f"AT-RCP-{work_receipt_id}-C{sequence}"
    expected_path = (
        f"docs/coordination/control_exchange/recovery/{work_receipt_id}/C{sequence}.json"
    )
    if checkpoint.get("checkpoint_id") != expected_id:
        return "RECOVERY_CHECKPOINT_ID"
    if checkpoint.get("recovery_head_path") != (
        f"docs/coordination/control_exchange/recovery_heads/{work_receipt_id}.json"
    ):
        return "RECOVERY_HEAD_PATH"
    if any(
        items != sorted(items) or len(items) != len(set(items))
        for items in (universe, successful, remaining, uncertain)
    ):
        return "RECOVERY_SET_ORDER_OR_DUPLICATE"
    sets = [set(successful), set(remaining), set(uncertain)]
    if any(sets[left] & sets[right] for left in range(3) for right in range(left + 1, 3)):
        return "RECOVERY_SET_OVERLAP"
    if set(universe) != set().union(*sets):
        return "RECOVERY_SET_INCOMPLETE"
    expected_item_hash = sha256_bytes(canonical_json(universe).encode("utf-8"))
    if checkpoint.get("transaction_item_set_sha256") != expected_item_hash:
        return "RECOVERY_ITEM_SET_HASH"

    predecessor_reference = checkpoint.get("predecessor_checkpoint")
    predecessor = b.record("predecessor_recovery_checkpoint", None)
    if sequence == 0:
        if predecessor_reference is not None or predecessor is not None:
            return "RECOVERY_PREDECESSOR"
    else:
        if not isinstance(predecessor_reference, dict) or not isinstance(predecessor, dict):
            return "RECOVERY_PREDECESSOR"
        if sequence != predecessor.get("checkpoint_sequence", -2) + 1:
            return "RECOVERY_PREDECESSOR"
        if predecessor_reference.get("checkpoint_id") != predecessor.get("checkpoint_id"):
            return "RECOVERY_PREDECESSOR"
        if predecessor_reference.get("checkpoint_sequence") != predecessor.get(
            "checkpoint_sequence"
        ):
            return "RECOVERY_PREDECESSOR"
        if predecessor_reference.get("sha256") != b.raw_sha("predecessor_recovery_checkpoint"):
            return "RECOVERY_PREDECESSOR"
        if predecessor.get("work_receipt_id") != work_receipt_id:
            return "RECOVERY_PREDECESSOR"
        if predecessor.get("transaction_id") != transaction_id:
            return "RECOVERY_PREDECESSOR"
        if predecessor.get("transaction_item_set_sha256") != expected_item_hash:
            return "RECOVERY_PREDECESSOR"
        prior_successful = set(predecessor.get("successful_items", []))
        if not prior_successful <= set(successful):
            return "RECOVERY_SUCCESS_REGRESSION"
        prior_uncertain = set(predecessor.get("uncertain_items", []))
        evidence = checkpoint.get("uncertain_resolution_evidence", [])
        evidence_by_item = {item.get("item_id"): item for item in evidence}
        if len(evidence_by_item) != len(evidence):
            return "RECOVERY_UNCERTAIN_EVIDENCE"
        for item_id in prior_uncertain:
            item = evidence_by_item.get(item_id)
            if not isinstance(item, dict) or item.get("matched") is not True:
                return "RECOVERY_UNCERTAIN_EVIDENCE"
            if item.get("expected_state_sha256") != item.get("observed_state_sha256"):
                return "RECOVERY_UNCERTAIN_EVIDENCE"
            destination = successful if item.get("resolved_state") == "SUCCESSFUL" else remaining
            if item_id not in destination:
                return "RECOVERY_UNCERTAIN_EVIDENCE"

    state = checkpoint.get("transaction_state")
    terminal = checkpoint.get("terminal_result")
    next_action = checkpoint.get("next_action", {})
    action = next_action.get("action")
    action_items = next_action.get("item_ids", [])
    if state == "NOT_STARTED":
        ok = not successful and not uncertain and remaining == universe and terminal is None
        ok = (
            ok
            and action == "EXECUTE_REMAINING"
            and bool(action_items)
            and set(action_items) <= set(remaining)
        )
    elif state == "IN_PROGRESS":
        ok = bool(uncertain) and terminal is None and action == "RESOLVE_UNCERTAIN"
        ok = ok and action_items == uncertain
    elif state == "PARTIALLY_COMMITTED":
        ok = bool(successful) and bool(remaining) and not uncertain and terminal is None
        ok = (
            ok
            and action == "EXECUTE_REMAINING"
            and bool(action_items)
            and set(action_items) <= set(remaining)
        )
    elif state == "RESULT_PENDING":
        ok = successful == universe and not remaining and not uncertain and terminal is None
        ok = ok and action == "PUBLISH_RESULT" and not action_items
    elif state == "COMMITTED":
        ok = successful == universe and not remaining and not uncertain
        ok = (
            ok
            and isinstance(terminal, dict)
            and terminal.get("outcome") in {"COMPLETED", "NO_ACTION_REQUIRED"}
        )
        ok = ok and action == "NONE" and not action_items
    elif state in {"BLOCKED", "REJECTED"}:
        ok = isinstance(terminal, dict) and terminal.get("outcome") == state
        ok = ok and action == "NONE" and not action_items
    else:
        ok = False
    if not ok:
        return "RECOVERY_STATE_MATRIX"

    current = head.get("current_checkpoint")
    if not isinstance(current, dict):
        return "RECOVERY_HEAD_PROJECTION"
    if current.get("checkpoint_id") != checkpoint.get("checkpoint_id"):
        return "RECOVERY_HEAD_PROJECTION"
    if current.get("checkpoint_sequence") != sequence:
        return "RECOVERY_HEAD_PROJECTION"
    if current.get("sha256") != b.raw_sha("recovery_checkpoint"):
        return "RECOVERY_HEAD_PROJECTION"
    if current.get("path") != expected_path:
        return "RECOVERY_HEAD_PROJECTION"
    if head.get("work_receipt_id") != work_receipt_id:
        return "RECOVERY_HEAD_PROJECTION"
    if head.get("transaction_id") != transaction_id:
        return "RECOVERY_HEAD_PROJECTION"
    if head.get("transaction_item_set_sha256") != expected_item_hash:
        return "RECOVERY_HEAD_PROJECTION"
    if head.get("current_transaction_state") != state:
        return "RECOVERY_HEAD_PROJECTION"

    revision = head.get("head_revision")
    prior_head = b.record("predecessor_recovery_head", None)
    if revision == 0:
        if head.get("previous_head_sha256") is not None or prior_head is not None:
            return "RECOVERY_HEAD_CAS"
    elif isinstance(revision, int) and revision > 0:
        if not isinstance(prior_head, dict):
            return "RECOVERY_HEAD_CAS"
        if revision != prior_head.get("head_revision", -2) + 1:
            return "RECOVERY_HEAD_CAS"
        if head.get("previous_head_sha256") != b.raw_sha("predecessor_recovery_head"):
            return "RECOVERY_HEAD_CAS"
    else:
        return "RECOVERY_HEAD_CAS"
    return None


def rule_024(b: Any) -> list[str]:
    failures = b.context.get("pre_mutation_failures", [])
    if failures:
        return [error("CX-SV-024", str(failures[0]))]
    path_state = b.context.get("deterministic_path_state", "NEW")
    if path_state == "SAME_PATH_DIFFERENT_SHA256":
        return [error("CX-SV-024", "CONFLICT_NO_MUTATION")]
    if path_state not in {"NEW", "SAME_PATH_SAME_SHA256"}:
        return [error("CX-SV-024", "UNKNOWN_PATH_STATE")]
    if b.record("recovery_checkpoint", None) is not None:
        recovery_error = _recovery_error(b)
        if recovery_error is not None:
            return [error("CX-SV-024", recovery_error)]
    return []
