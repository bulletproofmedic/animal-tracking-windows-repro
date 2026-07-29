$ErrorActionPreference = "Stop"

python -m unittest -v repro.test_post_restore_history_controls

if ($LASTEXITCODE -ne 0) {
    throw "Sanitized post-restore control tests failed."
}
