$ErrorActionPreference = "Stop"

python -m py_compile repro/windows_identity.py repro/test_windows_identity.py
if ($LASTEXITCODE -ne 0) {
    throw "Windows identity reproducer compilation failed."
}

python -m unittest -v repro.test_windows_identity
if ($LASTEXITCODE -ne 0) {
    throw "Windows identity reproducer tests failed."
}

python scripts/check_public_payload.py
if ($LASTEXITCODE -ne 0) {
    throw "Public payload boundary check failed."
}

Write-Host "WINDOWS_IDENTITY_PUBLIC_REPRODUCTION=PASS"
