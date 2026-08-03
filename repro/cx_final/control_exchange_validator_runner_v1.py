#!/usr/bin/env python3
"""Sharded corpus entry point for Control Exchange semantic evaluator v1.3.0."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import control_exchange_validator_audit3_v1 as audit3
import control_exchange_validator_v1 as core

VERSION = "1.3.0"
core.VERSION = VERSION
core.RULES.update(audit3.rule_overrides())


def load_corpus(path: Path) -> dict[str, Any]:
    index = json.loads(path.read_text(encoding="utf-8"))
    if index.get("record_type") != "ANIMAL_TRACKING_CONTROL_EXCHANGE_SEMANTIC_CONFORMANCE_INDEX":
        raise core.ValidationFailure("wrong conformance index record_type")
    if index.get("validator_version") != VERSION:
        raise core.ValidationFailure("conformance index version mismatch")
    shards = index.get("shards")
    if not isinstance(shards, list) or not shards:
        raise core.ValidationFailure("conformance index has no shards")

    merged: dict[str, Any] = {"corpus_id": index.get("corpus_id"), "base_bundles": {}, "cases": []}
    seen_cases: set[str] = set()
    for entry in shards:
        if not isinstance(entry, dict):
            raise core.ValidationFailure("invalid shard entry")
        relative = entry.get("path")
        if not isinstance(relative, str):
            raise core.ValidationFailure("invalid shard path")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise core.ValidationFailure("unsafe shard path")
        raw = (path.parent / relative_path).read_bytes()
        if len(raw) != entry.get("size_bytes"):
            raise core.ValidationFailure(f"shard size mismatch: {relative}")
        if core.sha256_bytes(raw) != entry.get("sha256"):
            raise core.ValidationFailure(f"shard SHA-256 mismatch: {relative}")
        shard = json.loads(raw.decode("utf-8"))
        if shard.get("record_type") != "ANIMAL_TRACKING_CONTROL_EXCHANGE_SEMANTIC_CONFORMANCE_SHARD":
            raise core.ValidationFailure(f"wrong shard record_type: {relative}")
        if shard.get("validator_version") != entry.get("validator_version"):
            raise core.ValidationFailure(f"shard version mismatch: {relative}")
        for bundle_id, bundle in shard.get("base_bundles", {}).items():
            prior = merged["base_bundles"].get(bundle_id)
            if prior is not None and prior != bundle:
                raise core.ValidationFailure(f"conflicting base bundle: {bundle_id}")
            merged["base_bundles"][bundle_id] = bundle
        for case in shard.get("cases", []):
            case_id = case.get("id")
            if not isinstance(case_id, str) or case_id in seen_cases:
                raise core.ValidationFailure(f"duplicate or invalid case: {case_id}")
            seen_cases.add(case_id)
            merged["cases"].append(case)

    if index.get("coverage", {}).get("total") != len(merged["cases"]):
        raise core.ValidationFailure("conformance case-count mismatch")
    return merged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus_index", type=Path)
    arguments = parser.parse_args(argv)
    try:
        result = core.run_corpus(load_corpus(arguments.corpus_index))
    except Exception as exc:
        result = {
            "validator_version": VERSION,
            "corpus_id": None,
            "case_count": 0,
            "passed": 0,
            "failed": 1,
            "errors": [f"VALIDATOR_RUNNER:{type(exc).__name__}:{exc}"],
            "cases": [],
        }
    sys.stdout.write(core.canonical_json(result) + "\n")
    return 0 if result.get("failed") == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
