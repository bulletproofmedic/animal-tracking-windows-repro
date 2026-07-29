$ErrorActionPreference = "Stop"

Write-Host "Running bounded Generation-6 security-logging reproducer"
python repro/generation6_validation.py
if ($LASTEXITCODE -ne 0) {
    throw "Generation-6 public reproducer failed."
}

Write-Host "Generation-6 public reproducer passed."
