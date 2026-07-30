$ErrorActionPreference = "Stop"

python -m py_compile repro/path_identity_model.py repro/test_path_identity_controls.py
if ($LASTEXITCODE -ne 0) {
    throw "Sanitized path-identity compilation failed."
}

python -m unittest -v repro.test_path_identity_controls
if ($LASTEXITCODE -ne 0) {
    throw "Sanitized path-identity tests failed."
}

python scripts/check_public_payload.py
if ($LASTEXITCODE -ne 0) {
    throw "Public payload boundary check failed."
}

Write-Host "PR27_PATH_IDENTITY_PUBLIC_WINDOWS_VALIDATION=PASS"
