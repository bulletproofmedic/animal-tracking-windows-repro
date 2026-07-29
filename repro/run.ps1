$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
Set-StrictMode -Version Latest

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22

$repoRoot = (Resolve-Path ".").Path
$reproRoot = (Resolve-Path "repro").Path
$env:PYTHONPATH = "$reproRoot;$repoRoot"

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

python -m ruff format `
  repro/g4_security_controls.py `
  repro/g4_secret_scan.py `
  repro/tests/test_g4_security_controls.py `
  repro/tests/test_g4_secret_scan.py

python -m ruff format --check `
  repro/g4_security_controls.py `
  repro/g4_secret_scan.py `
  repro/tests/test_g4_security_controls.py `
  repro/tests/test_g4_secret_scan.py

python -m unittest discover -s repro/tests -v

Write-Host "Generation-4 security remediation diagnostic PASS"
