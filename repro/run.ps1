$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

python -m unittest repro/test_pr27_aud005_retry_bounds.py -v
Write-Host "PR27_AUD005_RETRY_BOUNDS: PASS"
