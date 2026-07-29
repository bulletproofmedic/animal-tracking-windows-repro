$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
Set-StrictMode -Version Latest

python -m pip install --disable-pip-version-check --no-input ruff==0.15.22

$reproRoot = (Resolve-Path "repro").Path
$env:PYTHONPATH = $reproRoot

python -m compileall -q `
  repro/at_wal_006_controls.py `
  repro/at_wal_006_reaudit_controls.py `
  repro/tests/test_at_wal_006_controls.py `
  repro/tests/test_at_wal_006_reaudit_controls.py

python -m ruff check `
  repro/at_wal_006_controls.py `
  repro/at_wal_006_reaudit_controls.py `
  repro/tests/test_at_wal_006_controls.py `
  repro/tests/test_at_wal_006_reaudit_controls.py

python -m ruff format --diff `
  repro/at_wal_006_controls.py `
  repro/at_wal_006_reaudit_controls.py `
  repro/tests/test_at_wal_006_controls.py `
  repro/tests/test_at_wal_006_reaudit_controls.py
