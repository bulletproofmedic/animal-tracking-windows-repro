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

$ProbeText = Get-Content $ProbeSource -Raw -Encoding utf8
$VerifiedOwnerResolver = @'
$ownerText = [string]$verified.Owner
if ($ownerText -match '^S-\d+(?:-\d+)+$') {
    $owner = $ownerText
} else {
    $owner = (New-Object System.Security.Principal.NTAccount($ownerText)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
}
'@
$CapturedOwnerResolver = @'
$ownerText = [string]$acl.Owner
if ($ownerText -match '^S-\d+(?:-\d+)+$') {
    $owner = $ownerText
} else {
    $owner = (New-Object System.Security.Principal.NTAccount($ownerText)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
}
'@
$ProbeText = $ProbeText.Replace(
    '$owner = $verified.Owner.Translate([System.Security.Principal.SecurityIdentifier]).Value',
    $VerifiedOwnerResolver.TrimEnd()
)
$ProbeText = $ProbeText.Replace(
    '$owner = $acl.Owner.Translate([System.Security.Principal.SecurityIdentifier]).Value',
    $CapturedOwnerResolver.TrimEnd()
)
if ($ProbeText.Contains('.Owner.Translate(')) {
    throw "ACL owner normalization patch was incomplete."
}
$ProbeText | Set-Content $ProbeSource -Encoding utf8 -NoNewline

Get-ChildItem $SourceRoot -Filter "run_impl.ps1.part*" -File |
    Sort-Object Name |
    ForEach-Object { Get-Content $_.FullName -Raw -Encoding utf8 } |
    Set-Content $RunImplementation -Encoding utf8 -NoNewline

$RunText = Get-Content $RunImplementation -Raw -Encoding utf8
$RunText = $RunText.Replace(
    'if ($Result.command) { $Case.commands += [string]$Result.command }',
    'if ($Result.Contains("command") -and $Result["command"]) { $Case.commands += [string]$Result["command"] }'
)
$RunText = $RunText.Replace(
    'if ($Result.artifacts) { $Case.artifacts = $Result.artifacts }',
    'if ($Result.Contains("artifacts") -and $Result["artifacts"]) { $Case.artifacts = $Result["artifacts"] }'
)
$RunText = $RunText.Replace(
    'if ($Result.observation) { $Case.observation = $Result.observation }',
    'if ($Result.Contains("observation") -and $Result["observation"]) { $Case.observation = $Result["observation"] }'
)
$RunText = $RunText.Replace(
    'public_commit = "$env:GITHUB_SHA"',
    'public_commit = "$env:AT_PUBLIC_COMMIT"'
)
if ($RunText.Contains('$Result.observation') -or $RunText.Contains('$Result.command') -or $RunText.Contains('$Result.artifacts')) {
    throw "StrictMode-safe result collector patch was incomplete."
}
$RunText | Set-Content $RunImplementation -Encoding utf8 -NoNewline

$env:AT_CF009_ASSEMBLED_PROBE = $ProbeSource
& $RunImplementation
exit $LASTEXITCODE
