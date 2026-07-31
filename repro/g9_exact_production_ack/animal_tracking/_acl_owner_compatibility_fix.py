from __future__ import annotations

import os
import subprocess
from pathlib import Path

from animal_tracking import logging_config


def _apply_windows_acl(path: Path, *, directory: bool) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:AT_PROTECTED_PATH
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
if ($env:AT_PROTECTED_DIRECTORY -eq '1') {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
} else {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
}
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true, $false)
$currentRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $current, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($currentRule)
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $system, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($systemRule)
if ($env:AT_PROTECTED_DIRECTORY -eq '1') {
    [System.IO.Directory]::SetAccessControl($path, $acl)
    $verified = [System.IO.Directory]::GetAccessControl($path)
} else {
    [System.IO.File]::SetAccessControl($path, $acl)
    $verified = [System.IO.File]::GetAccessControl($path)
}
if (-not $verified.AreAccessRulesProtected) { throw 'ACL inheritance remains enabled.' }
$owner = $verified.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $current.Value) { throw "Unexpected ACL owner: $owner" }
$rules = @(
    $verified.GetAccessRules(
        $true, $false, [System.Security.Principal.SecurityIdentifier]
    )
)
if ($rules.Count -ne 2) { throw "Unexpected explicit ACL entry count: $($rules.Count)" }
$expected = @($current.Value, $system.Value)
foreach ($sid in $expected) {
    $matches = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
    if ($matches.Count -ne 1) { throw "Expected exactly one ACL entry for $sid" }
    $entry = $matches[0]
    if ($entry.IsInherited) { throw "Inherited ACL entry for $sid" }
    if ($entry.AccessControlType -ne $allow) { throw "Non-allow ACL entry for $sid" }
    if ($entry.FileSystemRights -ne $rights) { throw "Non-FullControl ACL entry for $sid" }
    if ($entry.InheritanceFlags -ne $inheritance) {
        throw "Unexpected inheritance flags for $sid"
    }
    if ($entry.PropagationFlags -ne $propagation) {
        throw "Unexpected propagation flags for $sid"
    }
}
foreach ($entry in $rules) {
    if ($expected -notcontains $entry.IdentityReference.Value) {
        throw "Unexpected ACL entry: $($entry.IdentityReference.Value)"
    }
}
"""
    environment = os.environ.copy()
    environment["AT_PROTECTED_PATH"] = str(path)
    environment["AT_PROTECTED_DIRECTORY"] = "1" if directory else "0"
    try:
        completed = subprocess.run(
            [
                logging_config._powershell_executable(),  # noqa: SLF001
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PermissionError(f"Could not protect {path} with a Windows ACL.") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise PermissionError(f"Could not protect {path} with a Windows ACL: {detail}")


def install_acl_owner_compatibility_fix() -> None:
    """Install the minimal candidate correction before ACL guard initialization."""

    logging_config._apply_windows_acl = _apply_windows_acl  # noqa: SLF001
