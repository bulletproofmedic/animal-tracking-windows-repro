$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "GENERATION-8 WINDOWS HANDLE CONTROL DIAGNOSTIC"
Write-Host "scope=synthetic exact-object acknowledgement and cleanup"
Write-Host "private_history=not_present"
Write-Host "sensitive_data=not_present"

python -m compileall -q repro/g8_handle_controls.py repro/tests/test_g8_handle_controls.py
python -m unittest -v repro.tests.test_g8_handle_controls
python scripts/check_public_payload.py
git diff --check

Write-Host "GENERATION-8 WINDOWS HANDLE CONTROL DIAGNOSTIC: PASS"
