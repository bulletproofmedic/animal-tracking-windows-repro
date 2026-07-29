$ErrorActionPreference = "Stop"

python -m pip install --disable-pip-version-check --requirement repro/requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m compileall -q repro
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m ruff check --config repro/pyproject.toml repro
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m ruff format --config repro/pyproject.toml --check --diff repro
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m pytest -q repro/tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
