$ErrorActionPreference = "Stop"

Write-Host "Compiling sanitized AT-WAL-008 core hardening model"
python -m compileall -q repro sitecustomize.py

Write-Host "Running contract, graph, temporal, result, protocol, calculation, and cancellation controls"
python repro/run_tests.py
