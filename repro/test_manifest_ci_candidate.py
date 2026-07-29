from __future__ import annotations

import copy
import json
from dataclasses import replace

from manifest_ci_candidate import CONTROLLED_PATHS, Facts, validate

STATE = "R1_SECURITY_COMBINED_FINAL_TARGET_MANIFEST_CONTROL"


def main() -> None:
    paths = (
        ".github/workflows/ci.yml",
        "README.md",
        "docs/remediation/evidence.md",
        "requirements/runtime.lock",
        "scripts/generate_source_manifest.py",
        "src/pkg/app.py",
        "tests/test_app.py",
    )
    payload = {
        "schema_version": 6,
        "state": STATE,
        "source_commit": "1" * 40,
        "source_git_tree": "2" * 40,
        "source_base_commit": "0" * 40,
        "control_commit": "3" * 40,
        "control_git_tree": "4" * 40,
        "controlled_paths": list(sorted(CONTROLLED_PATHS)),
        "path_inventory": [
            {"directory": "", "entries": ["README.md"]},
            {"directory": ".github/workflows", "entries": ["ci.yml"]},
            {"directory": "docs/remediation", "entries": ["evidence.md"]},
            {"directory": "requirements", "entries": ["runtime.lock"]},
            {"directory": "scripts", "entries": ["generate_source_manifest.py"]},
            {"directory": "src/pkg", "entries": ["app.py"]},
            {"directory": "tests", "entries": ["test_app.py"]},
        ],
        "summary": {
            "total_file_count": 7,
            "count_by_category": {
                "APPLICATION_SOURCE": 1,
                "CI_WORKFLOW": 1,
                "CONFIGURATION": 1,
                "DEPENDENCY_LOCK": 1,
                "EVIDENCE": 1,
                "TEST": 1,
                "VALIDATION_SCRIPT": 1,
            },
            "excluded_entry_count": 1,
        },
    }
    facts = Facts(
        base_commit="0" * 40,
        source_commit="1" * 40,
        source_tree="2" * 40,
        source_paths=paths,
        base_is_ancestor=True,
        control_commit="3" * 40,
        control_tree="4" * 40,
        control_parent="1" * 40,
        control_changed_paths=tuple(sorted(CONTROLLED_PATHS)),
        head_commit="5" * 40,
        head_tree="6" * 40,
        head_parent="3" * 40,
        head_changed_paths=("IMPLEMENTATION_SOURCE_MANIFEST.json",),
        manifest_bytes_match=True,
        checkout_commit="5" * 40,
        checkout_parents=("3" * 40,),
    )

    results: list[dict[str, object]] = []

    def record(name: str, expected: str, manifest=payload, observed=facts, context="exact-head") -> None:
        errors = validate(manifest, observed, context)
        actual = "PASS" if not errors else "FAIL"
        results.append({"name": name, "expected": expected, "actual": actual, "ok": actual == expected, "errors": errors})

    record("positive_exact_head", "PASS")
    changed = copy.deepcopy(payload); changed["path_inventory"][0]["entries"] = []; record("missing_path", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["path_inventory"][0]["entries"].append("extra.txt"); record("extra_path", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["path_inventory"][0]["entries"].append("README.md"); record("duplicate_path", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["path_inventory"].reverse(); record("ordering", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["summary"]["count_by_category"]["CONFIGURATION"] = 99; record("category", "FAIL", changed)
    record("mode_mutation", "FAIL", observed=replace(facts, source_tree="7" * 40))
    record("blob_mutation", "FAIL", observed=replace(facts, source_tree="8" * 40))
    record("hash_mutation", "FAIL", observed=replace(facts, source_tree="9" * 40))
    record("size_mutation", "FAIL", observed=replace(facts, source_tree="a" * 40))
    changed = copy.deepcopy(payload); changed["source_commit"] = "b" * 40; record("stale_source", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["source_git_tree"] = "c" * 40; record("stale_tree", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["state"] = "STALE"; record("stale_state", "FAIL", changed)
    changed = copy.deepcopy(payload); changed["summary"]["total_file_count"] = 99; record("summary", "FAIL", changed)
    record("unexpected_control_path", "FAIL", observed=replace(facts, control_changed_paths=tuple(sorted(CONTROLLED_PATHS)) + ("UNAUTHORIZED.txt",)))
    record("unexpected_manifest_path", "FAIL", observed=replace(facts, head_changed_paths=("IMPLEMENTATION_SOURCE_MANIFEST.json", "EXTRA.txt")))
    merge_facts = replace(facts, checkout_commit="d" * 40, checkout_parents=(facts.head_commit, "e" * 40))
    record("positive_merge_ref", "PASS", observed=merge_facts, context="merge-ref")
    record("merge_ref_on_exact_head", "FAIL", context="merge-ref")

    summary = {"schema": "CF004_FINAL_TARGET_PUBLIC_WINDOWS_MATRIX_V1", "test_count": len(results), "pass_count": sum(bool(item["ok"]) for item in results), "all_expected": all(bool(item["ok"]) for item in results), "results": results}
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["all_expected"] else 1)


if __name__ == "__main__":
    main()
