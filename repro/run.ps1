$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

python -m unittest repro/test_pr27_aud001_hook_composition.py -v
Write-Host "PR27_AUD001_HOOK_COMPOSITION: PASS"
