$ErrorActionPreference = "Stop"

Write-Host "Compiling sanitized AT-WAL-008 round-three control model"
python -m compileall -q repro
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running sanitized AT-WAL-008 round-three control tests"
python -m unittest discover -s repro/tests -p "test_round3_control.py" -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Emitting measured per-mutant producer evidence"
python repro/round3_control.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
