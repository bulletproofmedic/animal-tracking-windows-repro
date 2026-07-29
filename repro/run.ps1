$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22

$reproRoot = (Resolve-Path "repro").Path
$env:PYTHONPATH = (Resolve-Path ".").Path

python -m compileall -q `
  repro/at_wal_006_controls.py `
  repro/g4_security_controls.py `
  repro/g4_secret_scan.py `
  repro/tests/test_at_wal_006_controls.py `
  repro/tests/test_g4_security_controls.py `
  repro/tests/test_g4_secret_scan.py

python -m ruff check `
  repro/at_wal_006_controls.py `
  repro/g4_security_controls.py `
  repro/g4_secret_scan.py `
  repro/tests/test_at_wal_006_controls.py `
  repro/tests/test_g4_security_controls.py `
  repro/tests/test_g4_secret_scan.py

python -m ruff format --check `
  repro/at_wal_006_controls.py `
  repro/g4_security_controls.py `
  repro/g4_secret_scan.py `
  repro/tests/test_at_wal_006_controls.py `
  repro/tests/test_g4_security_controls.py `
  repro/tests/test_g4_secret_scan.py

python -m unittest discover -s repro/tests -v

if ($LASTEXITCODE -ne 0) {
  throw "Generation-4 security remediation diagnostic failed."
}

Write-Host "Generation-4 security remediation diagnostic PASS"
