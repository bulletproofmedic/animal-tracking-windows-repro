$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

python --version
git --version
python -m compileall -q repro

$candidateHash = (Get-FileHash "repro/manifest_ci_candidate.py" -Algorithm SHA256).Hash.ToLowerInvariant()
$testHash = (Get-FileHash "repro/test_manifest_ci_candidate.py" -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "MANIFEST_CANDIDATE_SHA256=$candidateHash"
Write-Host "MANIFEST_TEST_SHA256=$testHash"

python repro/test_manifest_ci_candidate.py
