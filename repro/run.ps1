$ErrorActionPreference = "Stop"

python -m py_compile repro/map_calibration_model.py repro/test_map_calibration_controls.py
if ($LASTEXITCODE -ne 0) { throw "Synthetic map/calibration compile failed." }

Push-Location repro
try {
  python -m unittest -v test_map_calibration_controls
  if ($LASTEXITCODE -ne 0) { throw "Synthetic map/calibration controls failed." }
} finally {
  Pop-Location
}

Write-Host "PR24_MAP_CALIBRATION_PUBLIC_WINDOWS_VALIDATION=PASS"
