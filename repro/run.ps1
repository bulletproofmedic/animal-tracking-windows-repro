$ErrorActionPreference = "Stop"

Write-Host "Compiling sanitized AT-WAL-008 reproducer"
python -m compileall -q repro

Write-Host "Running bounded rate-permission and cancellation controls"
python -m unittest discover -s repro/tests -v
