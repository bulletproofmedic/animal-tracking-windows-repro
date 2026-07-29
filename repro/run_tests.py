from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import sitecustomize  # noqa: F401,E402

suite = unittest.defaultTestLoader.discover(
    str(ROOT / "repro" / "tests"),
    pattern="test_core_hardening_reproducer.py",
)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
