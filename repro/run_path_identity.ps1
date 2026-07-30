$ErrorActionPreference = "Stop"

python -m py_compile repro/path_identity_model.py repro/test_path_identity_controls.py
python -m unittest -v repro.test_path_identity_controls
python scripts/check_public_payload.py

if ($LASTEXITCODE -ne 0) {
    throw "Sanitized path-identity controls failed."
}

Write-Host "PR27_PATH_IDENTITY_PUBLIC_WINDOWS_VALIDATION=PASS"
