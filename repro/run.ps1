$ErrorActionPreference = 'Stop'
python -m compileall -q repro
python -m unittest discover -s repro/tests -p 'test_security_event_lifecycle.py' -v
