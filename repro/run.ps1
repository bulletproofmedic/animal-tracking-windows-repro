$ErrorActionPreference = "Stop"

python -m py_compile repro/pr17_sync_contract.py
python repro/pr17_sync_contract.py
