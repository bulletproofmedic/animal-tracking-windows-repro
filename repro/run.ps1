$ErrorActionPreference = "Stop"

python -m pip install --disable-pip-version-check --requirement repro/requirements.txt
python -m compileall -q repro
python -m ruff check --config repro/pyproject.toml repro
python -m ruff format --config repro/pyproject.toml --check repro
python -m pytest -q repro/tests
