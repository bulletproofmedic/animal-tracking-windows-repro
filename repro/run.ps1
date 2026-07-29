$ErrorActionPreference = "Stop"
Write-Host "AT-WAL-007-COMB-F008 independent Windows hostile-input/no-mutation reproducer"
python -m unittest discover -s tests -v
