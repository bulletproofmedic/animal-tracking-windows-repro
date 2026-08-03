$ErrorActionPreference = "Stop"

$stage = Join-Path $PSScriptRoot "ruff_pr83"
$inputDir = Join-Path $stage "input"
$outputDir = Join-Path $stage "output"

Remove-Item -Recurse -Force $inputDir, $outputDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $inputDir, $outputDir | Out-Null

$prepare = @'
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

stage = Path("repro/ruff_pr83")
input_dir = stage / "input"


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def read_exact_git_blob(name: str) -> bytes:
    git_path = f"repro/ruff_pr83/exact/{name}"
    return subprocess.check_output(["git", "show", f"HEAD:{git_path}"])


def copy_verified(name: str, expected_blob: str) -> None:
    raw = read_exact_git_blob(name)
    observed = git_blob_sha(raw)
    if observed != expected_blob:
        raise SystemExit(f"{name} blob mismatch: observed {observed}, expected {expected_blob}")
    (input_dir / name).write_bytes(raw)
    print(f"{name} input SHA-256: {hashlib.sha256(raw).hexdigest()}")


copy_verified(
    "control_exchange_validator_v1.py",
    "21eb882e34454699e13bd16593d324be0b6201bb",
)
copy_verified(
    "control_exchange_validator_runner_v1.py",
    "602999346fca212042ab7cf45d5db0f1c51badc5",
)
(input_dir / "pyproject.toml").write_bytes((stage / "pyproject.toml").read_bytes())
'@

$prepare | python -
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location $inputDir
try {
    python -m ruff check --fix . && python -m ruff format .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -m ruff check . && python -m ruff format --check .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
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
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
