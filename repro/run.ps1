$ErrorActionPreference = "Stop"

$stage = Join-Path $PSScriptRoot "cx_final"
$output = Join-Path $stage "output"
Remove-Item -Recurse -Force $output -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $output | Out-Null

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location $stage
try {
    python -m ruff check --fix . && python -m ruff format .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -m ruff check . && python -m ruff format --check .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    python control_exchange_validator_runner_v1.py control_exchange_validator_conformance_v1.json > output/conformance_result.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $record = @'
from __future__ import annotations

import hashlib
import json
from pathlib import Path

root = Path(".")
result = json.loads((root / "output/conformance_result.json").read_text(encoding="utf-8"))
if result.get("case_count") != 80 or result.get("passed") != 80 or result.get("failed") != 0:
    raise SystemExit(f"Unexpected conformance result: {result.get('passed')}/{result.get('case_count')}, failed={result.get('failed')}")

paths = [
    Path("control_exchange_validator_v1.py"),
    Path("control_exchange_validator_audit3_v1.py"),
    Path("control_exchange_validator_audit3_time_transaction_v1.py"),
    Path("control_exchange_validator_audit3_recovery_v1.py"),
    Path("control_exchange_validator_runner_v1.py"),
    Path("control_exchange_validator_conformance_v1.json"),
    *sorted(Path("conformance").glob("*.json")),
]
files = {}
for path in paths:
    raw = path.read_bytes()
    files[path.as_posix()] = {
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
manifest = {
    "record_type": "ANIMAL_TRACKING_CONTROL_EXCHANGE_PUBLIC_SEMANTIC_VALIDATION_RESULT",
    "validator_version": "1.3.0",
    "ruff_version": "0.15.22",
    "case_count": 80,
    "passed": 80,
    "failed": 0,
    "files": files,
}
(root / "output/identity_manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps(manifest, indent=2, sort_keys=True))
'@
    $record | python -
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
