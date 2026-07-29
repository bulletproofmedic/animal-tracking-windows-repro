$ErrorActionPreference = 'Stop'

python --version
python -m compileall -q repro tests scripts

$testPatterns = @(
    'test_terminal_commit_order.py',
    'test_publication_protocol.py',
    'test_sqlite_canonical.py',
    'test_tile_integrity.py',
    'test_staged_namespace.py',
    'test_package_identity.py',
    'test_failed_root_lifecycle.py'
)

foreach ($pattern in $testPatterns) {
    python -m unittest discover -s tests -p $pattern -v
}

python scripts/check_public_payload.py
python repro/terminal_commit_order.py

Write-Output 'PR27_COMBINED_PUBLIC_WINDOWS_VALIDATION=PASS'
