$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "GENERATION-7 RETAINED MANIFEST CONTROL PUBLIC VALIDATION"
Write-Host "scope=synthetic retained-head topology"
Write-Host "private_history=not_present"
Write-Host "sensitive_data=not_present"

python -m compileall -q repro/g7_manifest_control.py repro/tests/test_g7_manifest_control.py
python -m unittest discover -s repro/tests -p "test_g7_manifest_control.py" -v
git diff --check

Write-Host "GENERATION-7 RETAINED MANIFEST CONTROL PUBLIC VALIDATION: PASS"
