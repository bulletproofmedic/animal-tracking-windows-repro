$ErrorActionPreference = "Stop"

python -m unittest tests.test_terminal_commit_order -v
python repro/terminal_commit_order.py
