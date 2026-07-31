$ErrorActionPreference = "Stop"

python -m py_compile repro/pr17_f007_sqlite_snapshot.py
python repro/pr17_f007_sqlite_snapshot.py
