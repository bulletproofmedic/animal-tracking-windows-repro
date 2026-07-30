$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "GENERATION-6 MANIFEST/CI PUBLIC VALIDATION"
Write-Host "scope=synthetic control-chain semantics"
Write-Host "private_history=not_present"
Write-Host "sensitive_data=not_present"

python -m compileall -q repro/g6_manifest_control.py repro/tests/test_g6_manifest_control.py
python -m unittest discover -s repro/tests -p "test_g6_manifest_control.py" -v
git diff --check

Write-Host "GENERATION-6 MANIFEST/CI PUBLIC VALIDATION: PASS"
