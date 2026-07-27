$ErrorActionPreference = "Stop"

$out = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
python -m pip download `
  --only-binary=:all: `
  --no-deps `
  --dest $out `
  "ruff==0.15.22"

$wheel = Get-ChildItem -Path $out -Filter "ruff-0.15.22-*.whl" | Select-Object -First 1
if (-not $wheel) {
  throw "The Ruff 0.15.22 wheel was not downloaded."
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $wheel.FullName).Hash.ToLowerInvariant()
Write-Host "Ruff wheel: $($wheel.Name)"
Write-Host "SHA-256: $hash"
