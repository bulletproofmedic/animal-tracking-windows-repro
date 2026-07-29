$ErrorActionPreference = "Stop"
python -m unittest discover -s repro -p "test_at_wal_007_reaud4_*.py" -v
