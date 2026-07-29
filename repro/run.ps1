$ErrorActionPreference = "Stop"

Write-Host "Compiling sanitized AT-WAL-008 core hardening model"
python -m compileall -q repro

Write-Host "Running contract, graph, temporal, result, protocol, calculation, and cancellation controls"
python -m unittest discover -s repro/tests -p "test_core_hardening_reproducer.py" -v
