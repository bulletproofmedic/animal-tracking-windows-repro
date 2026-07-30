$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

python -m unittest repro/test_pr27_aud004_authority.py -v
Write-Host "PR27_AUD004_AUTHORITY: PASS"
