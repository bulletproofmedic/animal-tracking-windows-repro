$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "AT-WAL-008 ROUND-FOUR PUBLIC WINDOWS VALIDATION"
Write-Host "scope=synthetic typed identity, payload cancellation, and shallow history controls"
Write-Host "private_history=not_present"
Write-Host "sensitive_data=not_present"

python -m compileall -q repro/round3_control.py repro/tests/test_round3_control.py
python -m unittest discover -s repro/tests -p "test_round3_control.py" -v
python repro/round3_control.py
python scripts/check_public_payload.py
git diff --check

Write-Host "AT-WAL-008 ROUND-FOUR PUBLIC WINDOWS VALIDATION: PASS"
