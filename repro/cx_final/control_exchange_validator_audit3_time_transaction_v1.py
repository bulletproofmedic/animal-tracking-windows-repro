"""Audit Report 3 semantic rule overrides for Control Exchange evaluator 1.3.0."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

VERSION = "1.3.0"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError("invalid timestamp")
    return parsed.astimezone(UTC)


def get_path(root: Any, path: str, default: Any = None) -> Any:
    current = root
    for token in path.split("."):
        if isinstance(current, dict) and token in current:
            current = current[token]
        else:
            return default
    return current


def resolve_pointer(root: Any, pointer: str) -> Any:
    if pointer == "":
        return root
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("invalid JSON Pointer")
    current = root
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise ValueError("JSON Pointer target missing")
    return current


def error(rule: str, code: str) -> str:
    return f"{rule}:{code}"


def _validate_time_ref(b: Any, binding: dict[str, Any]) -> bool:
    observation_alias = binding["observation_alias"]
    source_alias = binding["source_alias"]
    observation = b.record(observation_alias)
    source = b.record(source_alias)
    payload = observation.get("payload")
    if not isinstance(payload, dict):
        return False
    reference = b.value(binding["reference_path"])
    if not isinstance(reference, dict):
        return False

    source_reference = payload.get("source_response")
    if not isinstance(source_reference, dict):
        return False
    if source_reference.get("record_type") != source.get("record_type"):
        return False
    if source_reference.get("time_source_id") != source.get("time_source_id"):
        return False
    if source_reference.get("sha256") != b.raw_sha(source_alias):
        return False
    if source_reference.get("raw_response_sha256") != source.get("raw_response_sha256"):
        return False

    try:
        response_bytes = base64.b64decode(source["raw_response_base64"], validate=True)
    except (KeyError, ValueError, binascii.Error):
        return False
    response_sha = sha256_bytes(response_bytes)
    if source.get("raw_response_size_bytes") != len(response_bytes):
        return False
    if source.get("raw_response_sha256") != response_sha:
        return False
    if source.get("time_source_id") != f"AT-TSRC-{response_sha[:16]}":
        return False
    expected_path = f"docs/coordination/control_exchange/time_sources/{response_sha}.json"
    if source_reference.get("path") != expected_path:
        return False
    try:
        response = json.loads(response_bytes.decode("utf-8"))
        extracted = resolve_pointer(response, source["source_time_json_pointer"])
        extracted_time = parse_time(extracted)
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    if extracted != source.get("extracted_server_timestamp"):
        return False
    if extracted != payload.get("server_timestamp"):
        return False
    if parse_time(b.value(binding["action_path"])) != extracted_time:
        return False

    payload_hash = sha256_bytes(canonical_json(payload).encode("utf-8"))
    if observation.get("payload_sha256") != payload_hash:
        return False
    if observation.get("time_observation_id") != f"AT-TIME-{payload_hash[:16]}":
        return False
    if reference.get("time_observation_id") != observation.get("time_observation_id"):
        return False
    if reference.get("sha256") != b.raw_sha(observation_alias):
        return False
    if reference.get("payload_sha256") != payload_hash:
        return False

    local_used = payload.get("local_clock_used")
    local_time = payload.get("local_timestamp")
    measured = payload.get("measured_skew_seconds")
    maximum = payload.get("maximum_allowed_skew_seconds")
    if maximum != 120:
        return False
    if local_used is True:
        try:
            expected_skew = int(abs((parse_time(local_time) - extracted_time).total_seconds()))
        except ValueError:
            return False
        if measured != expected_skew or measured > maximum:
            return False
    elif local_used is False:
        if local_time is not None or measured is not None:
            return False
    else:
        return False
    return True


def rule_005(b: Any) -> list[str]:
    try:
        for binding in b.context.get("time_bindings", []):
            if not _validate_time_ref(b, binding):
                return [error("CX-SV-005", "TIME_SOURCE_OR_BINDING_INVALID")]
        for earlier, later in b.context.get("strict_time_pairs", []):
            if not parse_time(b.value(earlier)) < parse_time(b.value(later)):
                return [error("CX-SV-005", "TIME_ORDER")]
    except (ValueError, KeyError, TypeError):
        return [error("CX-SV-005", "TIME_SOURCE_OR_BINDING_INVALID")]
    return []


def _record_id(record: dict[str, Any], path: str) -> Any:
    return get_path(record, path, None)


def _transaction_binding_ok(
    b: Any, marker_alias: str, operation_type: str, acknowledgement_aliases: list[str]
) -> bool:
    marker = b.record(marker_alias)
    binding = b.record("control_transaction_binding")
    reference = marker.get("control_transaction_binding")
    transaction_id = marker.get("control_transaction_id")
    operation_id = (
        marker.get("marker_id") if operation_type == "CUTOVER" else marker.get("rollback_id")
    )
    if not isinstance(reference, dict):
        return False
    if reference.get("record_type") != binding.get("record_type"):
        return False
    if reference.get("sha256") != b.raw_sha("control_transaction_binding"):
        return False
    if reference.get("control_transaction_id") != transaction_id:
        return False
    if binding.get("binding_id") != f"AT-CTXB-{transaction_id}":
        return False
    if binding.get("operation_type") != operation_type:
        return False
    if binding.get("operation_id") != operation_id:
        return False
    if binding.get("control_transaction_id") != transaction_id:
        return False
    members = binding.get("evidence_members", [])
    locks = binding.get("lock_members", [])
    if binding.get("evidence_member_count") != len(members):
        return False
    if binding.get("lock_member_count") != len(locks):
        return False
    member_keys = {(item.get("role"), item.get("path"), item.get("sha256")) for item in members}
    if len(member_keys) != len(members):
        return False
    lock_keys = {
        (item.get("resource_key"), item.get("lock_id"), item.get("head_sha256")) for item in locks
    }
    if len(lock_keys) != len(locks):
        return False
    for item in locks:
        if item.get("transaction_id") != transaction_id:
            return False
        if item.get("claim_id") != binding.get("claim_id"):
            return False
        if item.get("owner_router_id") != binding.get("publisher_router_id"):
            return False
        if item.get("owner_chat_id") != binding.get("publisher_chat_id"):
            return False
        try:
            if parse_time(item["lease_expires_at"]) < parse_time(marker["effective_at"]):
                return False
        except (KeyError, ValueError):
            return False
    for descriptor in b.context.get("transaction_evidence_aliases", []):
        alias = descriptor["alias"]
        record = b.record(alias)
        expected = (
            descriptor["role"],
            descriptor["path"],
            b.raw_sha(alias),
        )
        if expected not in member_keys:
            return False
        matching = [
            item
            for item in members
            if (item.get("role"), item.get("path"), item.get("sha256")) == expected
        ]
        if len(matching) != 1:
            return False
        if matching[0].get("record_type") != record.get("record_type"):
            return False
        if matching[0].get("record_id") != _record_id(record, descriptor["id_path"]):
            return False
    for alias in acknowledgement_aliases:
        if b.record(alias).get("control_transaction_id") != transaction_id:
            return False
    return True


def _barrier_common(
    b: Any, marker_alias: str, operation_type: str, acknowledgement_aliases: list[str]
) -> bool:
    marker = b.record(marker_alias)
    evidence = b.record("barrier_transaction_evidence")
    transaction_id = marker.get("control_transaction_id")
    operation_id = (
        marker.get("marker_id") if operation_type == "CUTOVER" else marker.get("rollback_id")
    )
    reference = marker.get("barrier_transaction_evidence")
    if not isinstance(reference, dict):
        return False
    if reference.get("sha256") != b.raw_sha("barrier_transaction_evidence"):
        return False
    if reference.get("control_transaction_id") != transaction_id:
        return False
    if reference.get("operation_id") != operation_id:
        return False
    if evidence.get("transaction_type") != operation_type:
        return False
    if evidence.get("operation_id") != operation_id:
        return False
    if evidence.get("control_transaction_id") != transaction_id:
        return False
    if evidence.get("claim_id") != b.record("control_transaction_binding").get("claim_id"):
        return False
    if evidence.get("published_by_router_id") != marker.get("published_by_router_id"):
        return False
    if evidence.get("published_by_chat_id") != marker.get("published_by_chat_id"):
        return False
    barrier = evidence.get("barrier_lock")
    if (
        not isinstance(barrier, dict)
        or barrier.get("resource_key") != "GLOBAL::CONTROL_PLANE::CUTOVER"
    ):
        return False
    locks = evidence.get("component_locks", [])
    readbacks = evidence.get("readbacks", [])
    if evidence.get("component_lock_count") != len(locks):
        return False
    if evidence.get("readback_count") != len(readbacks):
        return False
    if evidence.get("all_component_locks_held") is not True:
        return False
    if evidence.get("all_target_readbacks_match") is not True:
        return False
    all_locks = [barrier, *locks]
    for lock in all_locks:
        if lock.get("transaction_id") != transaction_id:
            return False
        if lock.get("claim_id") != evidence.get("claim_id"):
            return False
        if lock.get("owner_router_id") != evidence.get("published_by_router_id"):
            return False
        if lock.get("owner_chat_id") != evidence.get("published_by_chat_id"):
            return False
        try:
            if parse_time(lock["lease_expires_at"]) < parse_time(marker["effective_at"]):
                return False
        except (KeyError, ValueError):
            return False
    lock_keys = {item.get("resource_key") for item in locks}
    readback_keys = {item.get("resource_key") for item in readbacks}
    if lock_keys != readback_keys:
        return False
    for readback in readbacks:
        if readback.get("matched") is not True:
            return False
        if readback.get("expected_post_state_sha256") != readback.get("observed_post_state_sha256"):
            return False
    try:
        if parse_time(evidence["published_at"]) > parse_time(marker["effective_at"]):
            return False
    except (KeyError, ValueError):
        return False
    return _transaction_binding_ok(b, marker_alias, operation_type, acknowledgement_aliases)


def rule_021(b: Any) -> list[str]:
    aliases = b.context.get("cutover_ack_aliases", [])
    return (
        []
        if _barrier_common(b, "effective_cutover_marker", "CUTOVER", aliases)
        else [error("CX-SV-021", "CUTOVER_TRANSACTION_INVALID")]
    )


def rule_022(b: Any) -> list[str]:
    marker = b.record("rollback_marker")
    aliases = b.context.get("rollback_ack_aliases", [])
    required = {"AT-ROUTER-001", "AT-ROUTER-002", "AT-ROUTER-003"}
    seen = set()
    for alias in aliases:
        acknowledgement = b.record(alias)
        if acknowledgement.get("record_type") != (
            "ANIMAL_TRACKING_CONTROL_EXCHANGE_ROLLBACK_ROUTER_ACKNOWLEDGEMENT"
        ):
            return [error("CX-SV-022", "WRONG_ACKNOWLEDGEMENT_TYPE")]
        if acknowledgement.get("rollback_id") != marker.get("rollback_id"):
            return [error("CX-SV-022", "ROLLBACK_ID_MISMATCH")]
        if acknowledgement.get("future_operational_source") != marker.get(
            "future_operational_source"
        ):
            return [error("CX-SV-022", "FUTURE_SOURCE_MISMATCH")]
        seen.add(acknowledgement.get("router_id"))
    if seen != required:
        return [error("CX-SV-022", "ROLLBACK_ACK_SET")]
    if not _barrier_common(b, "rollback_marker", "ROLLBACK", aliases):
        return [error("CX-SV-022", "ROLLBACK_TRANSACTION_INVALID")]
    return []
