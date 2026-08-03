#!/usr/bin/env python3
"""Animal Tracking Control Exchange normative semantic evaluator v1.0.0.

Dependency-free reference implementation selected by the Control Exchange
semantic-validation contract. JSON Schema validation precedes this evaluator.
This program evaluates only marker-bound semantic relationships and emits one
canonical JSON result.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
RULE_IDS = tuple(f"CX-SV-{i:03d}" for i in range(1, 25))
_MISSING = object()


class ValidationFailure(Exception):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValidationFailure("timestamp is not a string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationFailure("invalid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationFailure("timestamp lacks explicit offset")
    if parsed.microsecond != 0:
        raise ValidationFailure("timestamp must use whole seconds")
    return parsed.astimezone(UTC)


def split_path(path: str) -> list[str]:
    if not isinstance(path, str) or not path:
        raise ValidationFailure("path is empty")
    return path.split(".")


def get_path(root: Any, path: str, default: Any = _MISSING) -> Any:
    current = root
    for token in split_path(path):
        if isinstance(current, dict) and token in current:
            current = current[token]
        else:
            if default is not _MISSING:
                return default
            raise ValidationFailure(f"missing path {path}")
    return current


def set_pointer(root: Any, pointer: str, value: Any) -> None:
    if pointer == "":
        raise ValidationFailure("root replacement is not supported")
    if not pointer.startswith("/"):
        raise ValidationFailure("patch path must be a JSON Pointer")
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]
    current = root
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    last = tokens[-1]
    if isinstance(current, list):
        current[int(last)] = value
    else:
        current[last] = value


def delete_pointer(root: Any, pointer: str) -> None:
    if not pointer.startswith("/"):
        raise ValidationFailure("patch path must be a JSON Pointer")
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]
    current = root
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    last = tokens[-1]
    if isinstance(current, list):
        del current[int(last)]
    else:
        current.pop(last, None)


class Bundle:
    def __init__(self, value: dict[str, Any]):
        if not isinstance(value, dict):
            raise ValidationFailure("bundle root must be an object")
        self.case_id = str(value.get("case_id", "UNNAMED"))
        self.context = value.get("context", {})
        if not isinstance(self.context, dict):
            raise ValidationFailure("context must be an object")
        raw_records = value.get("raw_records", {})
        if not isinstance(raw_records, dict):
            raise ValidationFailure("raw_records must be an object")
        self.raw: dict[str, bytes] = {}
        self.records: dict[str, Any] = {}
        for alias, raw in raw_records.items():
            if not isinstance(alias, str) or not isinstance(raw, str):
                raise ValidationFailure("raw record aliases and values must be strings")
            encoded = raw.encode("utf-8")
            self.raw[alias] = encoded
            try:
                self.records[alias] = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValidationFailure(f"record {alias} is not valid JSON") from exc

    def record(self, alias: str, default: Any = _MISSING) -> Any:
        if alias in self.records:
            return self.records[alias]
        if default is not _MISSING:
            return default
        raise ValidationFailure(f"missing record alias {alias}")

    def raw_sha(self, alias: str) -> str:
        if alias not in self.raw:
            raise ValidationFailure(f"missing raw record alias {alias}")
        return sha256_bytes(self.raw[alias])

    def value(self, expression: str, default: Any = _MISSING) -> Any:
        alias, sep, path = expression.partition(".")
        if not sep:
            return self.record(alias, default)
        record = self.record(alias, default)
        if record is default and default is not _MISSING:
            return default
        return get_path(record, path, default)


def error(rule: str, code: str) -> str:
    return f"{rule}:{code}"


def rule_001(b: Bundle) -> list[str]:
    r = b.record("work_receipt")
    i = b.record("work_index_entry")
    expected = f"{r['work_id']}--{r['route_id']}--G{r['work_receipt_generation']}"
    pairs = [
        r.get("work_receipt_id") == expected,
        i.get("work_id") == r.get("work_id"),
        i.get("route_id") == r.get("route_id"),
        i.get("work_receipt_generation") == r.get("work_receipt_generation"),
        i.get("work_receipt_id") == expected,
    ]
    return [] if all(pairs) else [error("CX-SV-001", "WORK_RECEIPT_ID_MISMATCH")]


def rule_002(b: Bundle) -> list[str]:
    index = b.record("work_index_entry")
    expected = b.raw_sha("work_receipt")
    if index.get("work_receipt_content_sha256") != expected:
        return [error("CX-SV-002", "WORK_RECEIPT_RAW_HASH_MISMATCH")]
    for alias in ("claim", "claim_renewal", "control_result", "recovery_checkpoint"):
        record = b.record(alias, None)
        if record is not None and record.get("work_receipt_content_sha256") != expected:
            return [error("CX-SV-002", f"{alias.upper()}_HASH_MISMATCH")]
    return []


def rule_003(b: Bundle) -> list[str]:
    c = b.record("claim")
    expected = f"AT-CLAIM-{c['work_receipt_id']}--C{c['claim_generation']}"
    return [] if c.get("claim_id") == expected else [error("CX-SV-003", "CLAIM_ID_MISMATCH")]


def rule_004(b: Bundle) -> list[str]:
    c = b.record("claim")
    generation = c.get("claim_generation")
    pred = b.record("predecessor_claim", None)
    if generation == 0:
        ok = pred is None and c.get("predecessor_claim_id") is None and c.get("claim_basis") == "INITIAL_CLAIM"
    else:
        ok = (
            isinstance(pred, dict)
            and generation == pred.get("claim_generation", -2) + 1
            and c.get("predecessor_claim_id") == pred.get("claim_id")
        )
    return [] if ok else [error("CX-SV-004", "SKIPPED_OR_BAD_PREDECESSOR")]


def _validate_time_ref(b: Bundle, binding: dict[str, Any]) -> bool:
    obs_alias = binding["observation_alias"]
    obs = b.record(obs_alias)
    ref = b.value(binding["reference_path"])
    action = parse_time(b.value(binding["action_path"]))
    observed = parse_time(obs["effective_decision_time"])
    if action != observed:
        return False
    if ref.get("time_observation_id") != obs.get("time_observation_id"):
        return False
    if ref.get("sha256") != b.raw_sha(obs_alias):
        return False
    if ref.get("payload_sha256") != obs.get("payload_sha256"):
        return False
    measured = obs.get("measured_skew_seconds")
    maximum = obs.get("maximum_clock_skew_seconds")
    if not isinstance(measured, int) or not isinstance(maximum, int):
        return False
    return abs(measured) <= maximum <= 120


def rule_005(b: Bundle) -> list[str]:
    try:
        for binding in b.context.get("time_bindings", []):
            if not _validate_time_ref(b, binding):
                return [error("CX-SV-005", "TIME_BINDING_OR_SKEW")]
        for earlier, later in b.context.get("strict_time_pairs", []):
            if not parse_time(b.value(earlier)) < parse_time(b.value(later)):
                return [error("CX-SV-005", "TIME_ORDER")]
    except (ValidationFailure, KeyError, TypeError):
        return [error("CX-SV-005", "TIME_BINDING_OR_SKEW")]
    return []


def rule_006(b: Bundle) -> list[str]:
    renewal = b.record("claim_renewal")
    claim = b.record("claim")
    expected_id = f"AT-CRENEW-{renewal['claim_id']}-R{renewal['renewal_sequence']}"
    fields = (
        ("work_receipt_id", "work_receipt_id"),
        ("work_receipt_content_sha256", "work_receipt_content_sha256"),
        ("claim_id", "claim_id"),
        ("claim_generation", "claim_generation"),
        ("renewed_by_router_id", "owner_router_id"),
        ("renewed_by_chat_id", "owner_chat_id"),
        ("renewed_by_conversation_name", "owner_conversation_name"),
    )
    ok = renewal.get("renewal_id") == expected_id and all(renewal.get(a) == claim.get(c) for a, c in fields)
    return [] if ok else [error("CX-SV-006", "OWNER_OR_IDENTITY_MISMATCH")]


def rule_007(b: Bundle) -> list[str]:
    r = b.record("claim_renewal")
    prior = b.record("prior_claim_renewal", None)
    claim = b.record("claim")
    expected_sequence = 1 if prior is None else prior.get("renewal_sequence", -1) + 1
    expected_previous = claim.get("lease_expires_at") if prior is None else prior.get("new_lease_expires_at")
    try:
        ok = (
            r.get("renewal_sequence") == expected_sequence
            and r.get("previous_lease_expires_at") == expected_previous
            and parse_time(r["renewed_at"]) < parse_time(r["previous_lease_expires_at"])
            and parse_time(r["new_lease_expires_at"]) > parse_time(r["previous_lease_expires_at"])
        )
    except (ValidationFailure, KeyError):
        ok = False
    return [] if ok else [error("CX-SV-007", "LEASE_SEQUENCE_OR_TIME")]


def rule_008(b: Bundle) -> list[str]:
    r = b.record("claim_renewal")
    claim = b.record("claim")
    terminal = b.record("terminal_control_result", None)
    valid_claims = b.context.get("valid_claims", [])
    try:
        effective_expiry = parse_time(b.context.get("claim_effective_lease_expires_at", claim["lease_expires_at"]))
        renewed = parse_time(r["renewed_at"])
    except (ValidationFailure, KeyError):
        return [error("CX-SV-008", "CLAIM_EXPIRED_OR_FENCED")]
    higher = any(
        isinstance(x, dict)
        and x.get("claim_generation", -1) > claim.get("claim_generation", -1)
        and x.get("valid", True)
        for x in valid_claims
    )
    ok = terminal is None and renewed < effective_expiry and not higher
    return [] if ok else [error("CX-SV-008", "CLAIM_EXPIRED_OR_FENCED")]


def rule_009(b: Bundle) -> list[str]:
    claim = b.record("claim")
    pred = b.record("predecessor_claim")
    terminal = b.record("terminal_control_result", None)
    try:
        decision = parse_time(b.context["decision_time"])
        expiry = parse_time(b.context["predecessor_effective_lease_expires_at"])
        grace = int(b.context.get("takeover_grace_seconds", 120))
    except (ValidationFailure, KeyError, TypeError, ValueError):
        return [error("CX-SV-009", "BEFORE_GRACE_OR_BAD_GENERATION")]
    ok = (
        terminal is None
        and claim.get("claim_generation") == pred.get("claim_generation", -2) + 1
        and claim.get("predecessor_claim_id") == pred.get("claim_id")
        and decision >= expiry + timedelta(seconds=grace)
    )
    return [] if ok else [error("CX-SV-009", "BEFORE_GRACE_OR_BAD_GENERATION")]


def rule_010(b: Bundle) -> list[str]:
    for alias in b.context.get("authorization_aliases", ["claim", "resource_lock"]):
        record = b.record(alias, None)
        if record is None:
            continue
        auth = record.get("takeover_authorization")
        if record.get("takeover_basis") == "OWNER_DIRECTED":
            if not isinstance(auth, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(auth.get("sha256", ""))):
                return [error("CX-SV-010", "AUTHORIZATION_REQUIRED")]
        elif auth is not None:
            return [error("CX-SV-010", "UNEXPECTED_AUTHORIZATION")]
    return []


def _resource_ok(record: dict[str, Any]) -> bool:
    key = record.get("resource_key")
    generation = record.get("lock_generation")
    if not isinstance(key, str) or not isinstance(generation, int):
        return False
    digest = sha256_bytes(key.encode("utf-8"))
    return (
        record.get("resource_key_sha256") == digest
        and record.get("lock_id") == f"AT-LOCK-{digest[:16]}-G{generation}"
        and record.get("lock_head_path") == f"docs/coordination/control_exchange/resource_lock_heads/{digest}.json"
    )


def rule_011(b: Bundle) -> list[str]:
    aliases = b.context.get("resource_record_aliases", ["resource_lock"])
    for alias in aliases:
        record = b.record(alias, None)
        if record is not None and not _resource_ok(record):
            return [error("CX-SV-011", "RESOURCE_DERIVATION_MISMATCH")]
    return []


def rule_012(b: Bundle) -> list[str]:
    head = b.record("resource_lock_head")
    state = head.get("effective_state")
    if state == "HELD":
        ok = head.get("effective_lease_expires_at") is not None and head.get("release") is None
    elif state == "RELEASED":
        ok = head.get("effective_lease_expires_at") is None and isinstance(head.get("release"), dict)
    else:
        ok = False
    return [] if ok else [error("CX-SV-012", "LOCK_HEAD_STATE_MATRIX")]


def rule_013(b: Bundle) -> list[str]:
    lock = b.record("resource_lock")
    renewal = b.record("resource_lock_renewal")
    prior = b.record("prior_resource_lock_renewal", None)
    head = b.record("resource_lock_head")
    acq = lock.get("acquisition", {})
    expected_sequence = 1 if prior is None else prior.get("renewal_sequence", -1) + 1
    expected_previous = acq.get("initial_lease_expires_at") if prior is None else prior.get("new_lease_expires_at")
    same = all(
        renewal.get(field) == expected
        for field, expected in (
            ("resource_key_sha256", lock.get("resource_key_sha256")),
            ("lock_id", lock.get("lock_id")),
            ("lock_generation", lock.get("lock_generation")),
            ("claim_id", acq.get("claim_id")),
            ("transaction_id", acq.get("transaction_id")),
            ("renewed_by_router_id", acq.get("owner_router_id")),
            ("renewed_by_chat_id", acq.get("owner_chat_id")),
            ("renewed_by_conversation_name", acq.get("owner_conversation_name")),
        )
    )
    try:
        time_ok = (
            renewal.get("renewal_sequence") == expected_sequence
            and renewal.get("previous_lease_expires_at") == expected_previous
            and parse_time(renewal["renewed_at"]) < parse_time(renewal["previous_lease_expires_at"])
            and parse_time(renewal["new_lease_expires_at"]) > parse_time(renewal["previous_lease_expires_at"])
        )
    except (ValidationFailure, KeyError):
        time_ok = False
    head_ref = head.get("latest_renewal")
    head_ok = (
        isinstance(head_ref, dict)
        and head_ref.get("lock_renewal_id") == renewal.get("lock_renewal_id")
        and head_ref.get("sha256") == b.raw_sha("resource_lock_renewal")
        and head.get("effective_lease_expires_at") == renewal.get("new_lease_expires_at")
    )
    return [] if same and time_ok and head_ok else [error("CX-SV-013", "LOCK_RENEWAL_BINDING")]


def rule_014(b: Bundle) -> list[str]:
    lock = b.record("resource_lock")
    pred = b.record("predecessor_resource_lock", None)
    pred_head = b.record("predecessor_resource_lock_head", None)
    generation = lock.get("lock_generation")
    if generation == 0:
        ok = pred is None and lock.get("predecessor_lock") is None and lock.get("takeover_basis") == "INITIAL_ACQUISITION"
    else:
        ref = lock.get("predecessor_lock")
        ok = (
            isinstance(pred, dict)
            and isinstance(pred_head, dict)
            and generation == pred.get("lock_generation", -2) + 1
            and isinstance(ref, dict)
            and ref.get("lock_id") == pred.get("lock_id")
            and ref.get("sha256") == b.raw_sha("predecessor_resource_lock")
        )
        basis = lock.get("takeover_basis")
        if basis == "RELEASED_REACQUISITION":
            ok = ok and pred_head.get("effective_state") == "RELEASED"
        elif basis == "EXPIRED_AFTER_GRACE":
            try:
                decision = parse_time(lock["acquisition"]["acquired_at"])
                expiry = parse_time(pred_head["effective_lease_expires_at"])
                ok = ok and pred_head.get("effective_state") == "HELD" and decision >= expiry + timedelta(seconds=120)
            except (ValidationFailure, KeyError):
                ok = False
        elif basis == "OWNER_DIRECTED":
            ok = ok and isinstance(lock.get("takeover_authorization"), dict)
        else:
            ok = False
    return [] if ok else [error("CX-SV-014", "LOCK_TAKEOVER_INVALID")]


def rule_015(b: Bundle) -> list[str]:
    result = b.record("control_result")
    claim = b.record("highest_valid_claim")
    fields = (
        ("work_receipt_id", "work_receipt_id"),
        ("work_receipt_content_sha256", "work_receipt_content_sha256"),
        ("claim_id", "claim_id"),
        ("claim_generation", "claim_generation"),
        ("router_id", "owner_router_id"),
        ("chat_id", "owner_chat_id"),
    )
    return [] if all(result.get(a) == claim.get(c) for a, c in fields) else [error("CX-SV-015", "STALE_OR_MISMATCHED_CLAIM")]


def rule_016(b: Bundle) -> list[str]:
    result = b.record("control_result")
    claim = b.record("highest_valid_claim")
    locks = b.context.get("valid_resource_locks", [])
    expected = {
        (x.get("resource_key_sha256"), x.get("lock_id"), x.get("lock_generation"))
        for x in locks
        if isinstance(x, dict)
    }
    actual = {
        (x.get("resource_key_sha256"), x.get("lock_id"), x.get("lock_generation"))
        for x in result.get("resource_locks", [])
        if isinstance(x, dict)
    }
    claim_ok = result.get("claim_id") == claim.get("claim_id")
    return [] if expected == actual and claim_ok else [error("CX-SV-016", "RESULT_LOCK_BINDING")]


def rule_017(b: Bundle) -> list[str]:
    mapping = b.record("legacy_compatibility_mapping")
    carrier_alias = b.context.get("legacy_carrier_alias", "legacy_carrier")
    expected = b.raw_sha(carrier_alias)
    ok = mapping.get("legacy_content_sha256") == expected and mapping.get("carrier_sha256") == expected
    return [] if ok else [error("CX-SV-017", "LEGACY_HASH_MISMATCH")]


def rule_018(b: Bundle) -> list[str]:
    candidate = b.record("candidate_cutover_marker", None)
    if candidate is not None and candidate.get("state") != "NOT_EFFECTIVE":
        return [error("CX-SV-018", "CANDIDATE_MARKER_NOT_INACTIVE")]
    marker = b.record("effective_cutover_marker")
    aliases = b.context.get("source_aliases", [])
    for alias in aliases:
        ref = marker.get(alias)
        source = b.record(alias, None)
        if not isinstance(ref, dict) or source is None:
            return [error("CX-SV-018", "SOURCE_REFERENCE_MISSING")]
        if ref.get("sha256") != b.raw_sha(alias):
            return [error("CX-SV-018", "SOURCE_HASH_MISMATCH")]
        if not re.fullmatch(r"[0-9a-f]{40}", str(ref.get("commit", ""))):
            return [error("CX-SV-018", "SOURCE_COMMIT_MISSING")]
    groups = b.context.get("same_commit_groups", [])
    for group in groups:
        commits = {marker.get(alias, {}).get("commit") for alias in group}
        if len(commits) != 1:
            return [error("CX-SV-018", "MIXED_SOURCE_COMMITS")]
    return []


def rule_019(b: Bundle) -> list[str]:
    marker = b.record("effective_cutover_marker")
    aliases = b.context.get("cutover_ack_aliases", [])
    required = {"AT-ROUTER-001", "AT-ROUTER-002", "AT-ROUTER-003"}
    seen: set[str] = set()
    bindings = b.context.get("ack_binding_pairs", [])
    for alias in aliases:
        ack = b.record(alias)
        ref = next((x for x in marker.get("cutover_acknowledgements", []) if x.get("alias") == alias), None)
        if not isinstance(ref, dict) or ref.get("sha256") != b.raw_sha(alias):
            return [error("CX-SV-019", "ACK_RAW_HASH_MISMATCH")]
        router = ack.get("router_id")
        if ack.get("status") != "ACKNOWLEDGED" or router in seen:
            return [error("CX-SV-019", "DUPLICATE_OR_NONACKNOWLEDGED_ROUTER")]
        seen.add(router)
        for ack_path, marker_path in bindings:
            if get_path(ack, ack_path, None) != get_path(marker, marker_path, None):
                return [error("CX-SV-019", "ACK_BINDING_MISMATCH")]
    return [] if seen == required else [error("CX-SV-019", "MISSING_ROUTER_ACKNOWLEDGEMENT")]


def rule_020(b: Bundle) -> list[str]:
    g = b.record("global_lock_disposition")
    state = g.get("observed_state")
    disposition = g.get("disposition")
    blocks = g.get("blocks_cutover")
    owner = g.get("owner")
    recovery = g.get("recovery_evidence")
    post = g.get("post_recovery_state")
    if state in {"ABSENT", "FREE"}:
        ok = disposition == "FREE_VERIFIED" and blocks is False and owner is None and recovery is None and post is None
    elif state == "HELD_ACTIVE":
        ok = disposition == "HELD_BLOCKS_CUTOVER" and blocks is True and isinstance(owner, dict)
    elif state == "HELD_EXPIRED":
        ok = (
            (disposition == "HELD_BLOCKS_CUTOVER" and blocks is True)
            or (
                disposition == "STALE_RECOVERED"
                and blocks is False
                and isinstance(recovery, dict)
                and post in {"ABSENT", "FREE"}
            )
        )
    elif state == "CONFLICT":
        ok = disposition == "CONFLICT_BLOCKS_CUTOVER" and blocks is True
    else:
        ok = False
    inventory = b.record("legacy_inventory", None)
    if inventory is not None:
        ok = ok and inventory.get("item_count") == len(inventory.get("items", []))
    if b.context.get("require_cutover_permitted") is True and blocks is True:
        ok = False
    return [] if ok else [error("CX-SV-020", "GLOBAL_LOCK_BINDING_OR_STATE")]


def _barrier_common(b: Bundle, marker_alias: str, transaction_type: str) -> bool:
    marker = b.record(marker_alias)
    evidence = b.record("barrier_transaction_evidence")
    if evidence.get("transaction_type") != transaction_type:
        return False
    if marker.get("barrier_evidence_sha256") != b.raw_sha("barrier_transaction_evidence"):
        return False
    if evidence.get("barrier_resource_key") != "GLOBAL::CONTROL_PLANE::CUTOVER":
        return False
    if evidence.get("publisher_router_id") != marker.get("publisher_router_id"):
        return False
    if evidence.get("publisher_chat_id") != marker.get("publisher_chat_id"):
        return False
    locks = evidence.get("component_locks", [])
    reads = evidence.get("readbacks", [])
    if evidence.get("component_lock_count") != len(locks) or evidence.get("readback_count") != len(reads):
        return False
    lock_keys = {x.get("resource_key") for x in locks}
    read_keys = {x.get("resource_key") for x in reads}
    if lock_keys != read_keys:
        return False
    for lock in locks:
        if lock.get("owner_router_id") != evidence.get("publisher_router_id"):
            return False
        if lock.get("owner_chat_id") != evidence.get("publisher_chat_id"):
            return False
        if lock.get("claim_id") != evidence.get("claim_id"):
            return False
        if lock.get("transaction_id") != evidence.get("transaction_id"):
            return False
        if lock.get("state") != "HELD":
            return False
    for read in reads:
        if read.get("matched") is not True or read.get("expected_sha256") != read.get("observed_sha256"):
            return False
    if marker.get("claim_id") != evidence.get("claim_id"):
        return False
    if marker.get("transaction_id") != evidence.get("transaction_id"):
        return False
    try:
        effective = parse_time(marker["effective_at"])
        if parse_time(evidence["published_at"]) > effective:
            return False
        if parse_time(evidence["barrier_lease_expires_at"]) < effective:
            return False
        for lock in locks:
            if parse_time(lock["lease_expires_at"]) < effective:
                return False
    except (ValidationFailure, KeyError):
        return False
    return True


def rule_021(b: Bundle) -> list[str]:
    return [] if _barrier_common(b, "effective_cutover_marker", "CUTOVER") else [error("CX-SV-021", "CUTOVER_BARRIER_INVALID")]


def rule_022(b: Bundle) -> list[str]:
    marker = b.record("rollback_marker")
    if not _barrier_common(b, "rollback_marker", "ROLLBACK"):
        return [error("CX-SV-022", "ROLLBACK_BARRIER_INVALID")]
    aliases = b.context.get("rollback_ack_aliases", [])
    required = {"AT-ROUTER-001", "AT-ROUTER-002", "AT-ROUTER-003"}
    seen = set()
    for alias in aliases:
        ack = b.record(alias)
        ref = next((x for x in marker.get("rollback_acknowledgements", []) if x.get("alias") == alias), None)
        if not isinstance(ref, dict) or ref.get("sha256") != b.raw_sha(alias):
            return [error("CX-SV-022", "ROLLBACK_ACK_HASH")]
        if ack.get("record_type") != "ANIMAL_TRACKING_CONTROL_EXCHANGE_ROLLBACK_ROUTER_ACKNOWLEDGEMENT":
            return [error("CX-SV-022", "WRONG_ACKNOWLEDGEMENT_TYPE")]
        if ack.get("rollback_id") != marker.get("rollback_id"):
            return [error("CX-SV-022", "ROLLBACK_ID_MISMATCH")]
        if ack.get("future_operational_commit") != marker.get("future_operational_commit"):
            return [error("CX-SV-022", "FUTURE_SOURCE_MISMATCH")]
        seen.add(ack.get("router_id"))
    return [] if seen == required else [error("CX-SV-022", "ROLLBACK_ACK_SET")]


def rule_023(b: Bundle) -> list[str]:
    inventory = b.record("rollback_scope_inventory")
    claims = inventory.get("native_claims", [])
    if inventory.get("native_claim_count") != len(claims):
        return [error("CX-SV-023", "SCOPE_COUNT_MISMATCH")]
    ids = [x.get("claim_id") for x in claims]
    if len(ids) != len(set(ids)):
        return [error("CX-SV-023", "DUPLICATE_CLAIM")]
    allowed = {"COMPLETE_UNDER_RECORDED_PROCEDURE", "RECOVER_UNDER_RECORDED_PROCEDURE", "QUARANTINE_CONFLICT"}
    for item in claims:
        if item.get("disposition") not in allowed:
            return [error("CX-SV-023", "INVALID_DISPOSITION")]
        if item.get("disposition") == "COMPLETE_UNDER_RECORDED_PROCEDURE" and not item.get("terminal_result_sha256"):
            return [error("CX-SV-023", "MISSING_TERMINAL_RESULT")]
        if item.get("disposition") == "RECOVER_UNDER_RECORDED_PROCEDURE" and not item.get("recovery_checkpoint_sha256"):
            return [error("CX-SV-023", "MISSING_RECOVERY_CHECKPOINT")]
    if inventory.get("unresolved_legacy_conflict_count", 0) != 0:
        return [error("CX-SV-023", "UNRESOLVED_LEGACY_CONFLICT")]
    return []


def rule_024(b: Bundle) -> list[str]:
    failures = b.context.get("pre_mutation_failures", [])
    if failures:
        return [error("CX-SV-024", str(failures[0]))]
    path_state = b.context.get("deterministic_path_state", "NEW")
    if path_state == "SAME_PATH_DIFFERENT_SHA256":
        return [error("CX-SV-024", "CONFLICT_NO_MUTATION")]
    if path_state not in {"NEW", "SAME_PATH_SAME_SHA256"}:
        return [error("CX-SV-024", "UNKNOWN_PATH_STATE")]
    return []


RULES: dict[str, Callable[[Bundle], list[str]]] = {
    f"CX-SV-{i:03d}": globals()[f"rule_{i:03d}"] for i in range(1, 25)
}


def evaluate_bundle(value: dict[str, Any]) -> dict[str, Any]:
    case_id = str(value.get("case_id", "UNNAMED"))
    requested = value.get("requested_rules", list(RULE_IDS))
    if not isinstance(requested, list) or any(rule not in RULES for rule in requested):
        return {
            "validator_version": VERSION,
            "case_id": case_id,
            "accepted": False,
            "mutation_permitted": False,
            "errors": ["VALIDATOR:UNKNOWN_RULE"],
        }
    try:
        bundle = Bundle(value)
    except ValidationFailure as exc:
        return {
            "validator_version": VERSION,
            "case_id": case_id,
            "accepted": False,
            "mutation_permitted": False,
            "errors": [f"VALIDATOR:BUNDLE:{exc}"],
        }
    errors: list[str] = []
    for rule_id in requested:
        try:
            errors.extend(RULES[rule_id](bundle))
        except (ValidationFailure, KeyError, TypeError, ValueError) as exc:
            errors.append(error(rule_id, f"MISSING_OR_INVALID_INPUT:{exc}"))
    accepted = not errors
    return {
        "validator_version": VERSION,
        "case_id": case_id,
        "accepted": accepted,
        "mutation_permitted": accepted,
        "errors": errors,
    }


def materialize_case(corpus: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    base_id = case["base_bundle"]
    base = copy.deepcopy(corpus["base_bundles"][base_id])
    for patch in case.get("patches", []):
        op = patch["op"]
        if op == "set":
            set_pointer(base, patch["path"], patch["value"])
        elif op == "delete":
            delete_pointer(base, patch["path"])
        else:
            raise ValidationFailure(f"unsupported patch operation {op}")
    raw_records = {
        alias: canonical_json(record)
        for alias, record in base.get("records", {}).items()
    }
    return {
        "bundle_version": "1.0",
        "case_id": case["id"],
        "requested_rules": case["requested_rules"],
        "raw_records": raw_records,
        "context": base.get("context", {}),
    }


def run_corpus(corpus: dict[str, Any]) -> dict[str, Any]:
    case_results = []
    passed = 0
    for case in corpus.get("cases", []):
        bundle = materialize_case(corpus, case)
        observed = evaluate_bundle(bundle)
        expected = case["expected"]
        ok = (
            observed["accepted"] == expected["accepted"]
            and observed["mutation_permitted"] == expected["mutation_permitted"]
            and observed["errors"] == expected["errors"]
        )
        case_results.append({"id": case["id"], "pass": ok, "observed": observed, "expected": expected})
        passed += int(ok)
    return {
        "validator_version": VERSION,
        "corpus_id": corpus.get("corpus_id"),
        "case_count": len(case_results),
        "passed": passed,
        "failed": len(case_results) - passed,
        "cases": case_results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--corpus", action="store_true")
    args = parser.parse_args(argv)
    value = json.loads(args.input.read_text(encoding="utf-8"))
    result = run_corpus(value) if args.corpus else evaluate_bundle(value)
    sys.stdout.write(canonical_json(result) + "\n")
    return 0 if (result.get("failed", 0) == 0 and result.get("accepted", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
