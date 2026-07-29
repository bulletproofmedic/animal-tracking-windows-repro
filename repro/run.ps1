$ErrorActionPreference = "Stop"

Write-Host "Compiling sanitized AT-WAL-008 independent re-audit remediation model"
python -m compileall -q repro

Write-Host "Running AT-WAL-008 F-001 through F-009 and NF-001 controls"
python -m unittest discover -s repro/tests -p "test_reaudit_remediation_reproducer.py" -v
