$ErrorActionPreference = "Stop"
$env:PYTHONPATH = (Resolve-Path "repro").Path
python -m unittest discover -s repro -p "test_*.py" -v
