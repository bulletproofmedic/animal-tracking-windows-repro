$ErrorActionPreference = "Stop"

$stage = Join-Path $PSScriptRoot "ruff_pr83"
$inputDir = Join-Path $stage "input"
$outputDir = Join-Path $stage "output"

Remove-Item -Recurse -Force $inputDir, $outputDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $inputDir, $outputDir | Out-Null

$assemble = @'
from __future__ import annotations

import hashlib
from pathlib import Path

stage = Path("repro/ruff_pr83")
input_dir = stage / "input"


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def normalize_to_expected(data: bytes, expected: str, label: str) -> bytes:
    candidates = [data]
    if data.endswith(b"\n"):
        candidates.append(data[:-1])
    else:
        candidates.append(data + b"\n")
    for candidate in candidates:
        if git_blob_sha(candidate) == expected:
            return candidate
    raise SystemExit(
        f"{label} assembly mismatch: observed {git_blob_sha(data)}, expected {expected}"
    )

parts = sorted(stage.glob("control_exchange_validator_v1.py.part*"))
if len(parts) != 4:
    raise SystemExit(f"Expected four evaluator fragments, found {len(parts)}")

evaluator = normalize_to_expected(
    b"".join(path.read_bytes() for path in parts),
    "21eb882e34454699e13bd16593d324be0b6201bb",
    "evaluator",
)
runner = normalize_to_expected(
    (stage / "control_exchange_validator_runner_v1.py").read_bytes(),
    "602999346fca212042ab7cf45d5db0f1c51badc5",
    "runner",
)

(input_dir / "control_exchange_validator_v1.py").write_bytes(evaluator)
(input_dir / "control_exchange_validator_runner_v1.py").write_bytes(runner)
(input_dir / "pyproject.toml").write_bytes((stage / "pyproject.toml").read_bytes())

print(f"Evaluator input SHA-256: {hashlib.sha256(evaluator).hexdigest()}")
print(f"Runner input SHA-256: {hashlib.sha256(runner).hexdigest()}")
'@

$assemble | python -

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22

Push-Location $inputDir
try {
    python -m ruff check --fix . && python -m ruff format .
    python -m ruff check . && python -m ruff format --check .
} finally {
    Pop-Location
}

Copy-Item (Join-Path $inputDir "control_exchange_validator_v1.py") $outputDir
Copy-Item (Join-Path $inputDir "control_exchange_validator_runner_v1.py") $outputDir

$record = @'
from __future__ import annotations

import hashlib
import json
from pathlib import Path

output = Path("repro/ruff_pr83/output")
records = {}
for path in sorted(output.glob("*.py")):
    raw = path.read_bytes()
    records[path.name] = {
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
(output / "ruff_result.json").write_text(
    json.dumps(
        {
            "ruff_version": "0.15.22",
            "command": "python -m ruff check --fix . && python -m ruff format .",
            "verification": "python -m ruff check . && python -m ruff format --check .",
            "files": records,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
print(json.dumps(records, indent=2, sort_keys=True))
'@

$record | python -
