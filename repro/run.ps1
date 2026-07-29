$ErrorActionPreference = "Stop"

python -m unittest tests.test_finalizer_roster_repro -v
python -m compileall -q repro tests

Write-Host "Finalizer roster reproducer passed on hosted Windows."
