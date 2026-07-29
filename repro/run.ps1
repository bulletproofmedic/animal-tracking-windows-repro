[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SourceRoot = Join-Path $PSScriptRoot "at_r1_sec_cf_009"
$AssemblyRoot = Join-Path $env:RUNNER_TEMP "at-r1-sec-cf-009-assembly"
Remove-Item $AssemblyRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $AssemblyRoot -Force | Out-Null

$ProbeSource = Join-Path $AssemblyRoot "probe.py"
$RunImplementation = Join-Path $AssemblyRoot "run_impl.ps1"

Get-ChildItem $SourceRoot -Filter "probe.py.part*" -File |
    Sort-Object Name |
    ForEach-Object { Get-Content $_.FullName -Raw -Encoding utf8 } |
    Set-Content $ProbeSource -Encoding utf8 -NoNewline

Get-ChildItem $SourceRoot -Filter "run_impl.ps1.part*" -File |
    Sort-Object Name |
    ForEach-Object { Get-Content $_.FullName -Raw -Encoding utf8 } |
    Set-Content $RunImplementation -Encoding utf8 -NoNewline

$env:AT_CF009_ASSEMBLED_PROBE = $ProbeSource
& $RunImplementation
exit $LASTEXITCODE
