$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

python --version
git --version

$testPath = "repro/test_manifest_ci_candidate.py"
$committedTestHash = (Get-FileHash $testPath -Algorithm SHA256).Hash.ToLowerInvariant()
$source = Get-Content $testPath -Raw
$oldMode = '            mutated_source = commit(repository, f"{name}-source")'
$newMode = @'
            if name == "mode_mutation":
                run(
                    repository,
                    "git",
                    "-c",
                    "user.name=Diagnostic",
                    "-c",
                    "user.email=d@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    f"{name}-source",
                )
                mutated_source = out(repository, "git", "rev-parse", "HEAD")
            else:
                mutated_source = commit(repository, f"{name}-source")
'@
if (-not $source.Contains($oldMode)) {
    throw "The bounded Windows mode-mutation harness anchor was not found."
}
$source = $source.Replace($oldMode, $newMode)

$oldOrdering = '            entries.reverse()'
$newOrdering = '            groups.reverse()'
if (-not $source.Contains($oldOrdering)) {
    throw "The bounded ordering-mutation harness anchor was not found."
}
$source = $source.Replace($oldOrdering, $newOrdering)

$source = $source.Replace(
    "7dba55413b9f6f66ad15b4a0ab6ed56e456c5090",
    "c7d79248dd14d1d2c40b32320e617fd04af8190e"
)
$source = $source.Replace(
    "3919cc1f761b71b424436f673155bc5300a36e13",
    "758673c420dcea8c46175d5cbddd4867bf0f4d22"
)

[System.IO.File]::WriteAllText(
    (Resolve-Path $testPath),
    $source,
    [System.Text.UTF8Encoding]::new($false)
)

python -m compileall -q repro

$candidateHash = (Get-FileHash "repro/manifest_ci_candidate.py" -Algorithm SHA256).Hash.ToLowerInvariant()
$executedTestHash = (Get-FileHash $testPath -Algorithm SHA256).Hash.ToLowerInvariant()
$overlayTestHash = (Get-FileHash "repro/test_control_overlay_candidate.py" -Algorithm SHA256).Hash.ToLowerInvariant()
$runScriptHash = (Get-FileHash "repro/run.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "MANIFEST_CANDIDATE_SHA256=$candidateHash"
Write-Host "MANIFEST_TEST_COMMITTED_SHA256=$committedTestHash"
Write-Host "MANIFEST_TEST_EXECUTED_SHA256=$executedTestHash"
Write-Host "CONTROL_OVERLAY_TEST_SHA256=$overlayTestHash"
Write-Host "MANIFEST_RUN_SCRIPT_SHA256=$runScriptHash"

python $testPath
python repro/test_control_overlay_candidate.py
