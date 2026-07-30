from __future__ import annotations

import unittest

from repro import g8_handle_controls as controls
from repro.g8_rename_layout_fix import rename_file_descriptor_noreplace

controls.rename_file_descriptor_noreplace = rename_file_descriptor_noreplace

suite = unittest.defaultTestLoader.loadTestsFromName(
    "repro.tests.test_g8_handle_controls"
)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
