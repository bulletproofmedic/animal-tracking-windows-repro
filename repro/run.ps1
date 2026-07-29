$ErrorActionPreference = "Stop"

python -m pip install --disable-pip-version-check --no-input --requirement repro/requirements.txt
$env:PYTHONPATH = (Resolve-Path "repro/src").Path
python -m compileall -q repro/src repro/tests
python -m ruff check repro/src repro/tests
python -m ruff format --check repro/src repro/tests
python -m pytest -q repro/tests
