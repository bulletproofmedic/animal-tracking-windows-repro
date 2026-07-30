$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "GENERATION-8 WINDOWS HANDLE CONTROL DIAGNOSTIC"
Write-Host "scope=synthetic exact-object acknowledgement and cleanup"
Write-Host "private_history=not_present"
Write-Host "sensitive_data=not_present"

python -m compileall -q repro/g8_handle_controls.py repro/g8_rename_layout_fix.py repro/run_g8_tests.py repro/tests/test_g8_handle_controls.py
python -m repro.run_g8_tests
python scripts/check_public_payload.py
git diff --check

Write-Host "GENERATION-8 WINDOWS HANDLE CONTROL DIAGNOSTIC: PASS"
