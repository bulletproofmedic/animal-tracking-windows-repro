$ErrorActionPreference = "Stop"

python repro/terminal_lineage_repro.py
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
