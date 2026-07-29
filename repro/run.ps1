$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
    throw "This reproducer requires Windows."
}

$reproRoot = (Resolve-Path "repro").Path
$env:PYTHONPATH = $reproRoot

python -m py_compile `
    "repro/security_logging_windows.py" `
    "repro/tests/test_security_logging_windows.py"
if ($LASTEXITCODE -ne 0) {
    throw "Sanitized reproducer compilation failed with exit code $LASTEXITCODE."
}

python -m unittest discover -s "repro/tests" -v
if ($LASTEXITCODE -ne 0) {
    throw "Sanitized Windows diagnostic failed with exit code $LASTEXITCODE."
}
