$ErrorActionPreference = "Stop"

Write-Host "Compiling sanitized AT-WAL-008 round-five result-validation model"
python -m compileall -q repro
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running bounded result-validation cancellation controls"
python repro/round5_result_validation.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "AT-WAL-008 ROUND-FIVE PUBLIC WINDOWS VALIDATION: PASS"
