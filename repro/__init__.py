"""Sanitized Animal Tracking Windows diagnostics."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from repro import g9_source_remediation as _g9


class _StableSyntheticJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "component": "synthetic.security",
            "correlation_id": record.correlation_id,
            "event_code": record.event_code,
            "message": "Synthetic rejection event",
            "record_id": record.record_id,
            "severity": record.levelname,
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _drift_windows_acl(path: Path) -> None:
    _g9._require_windows()
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:G9_SYNTHETIC_PATH
$acl = [System.IO.File]::GetAccessControl($path)
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = [System.Security.AccessControl.FileSystemRights]::Read
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $everyone, $rights, $inheritance, $propagation, $allow
)
$acl.AddAccessRule($rule)
[System.IO.File]::SetAccessControl($path, $acl)
"""
    environment = os.environ.copy()
    environment["G9_SYNTHETIC_PATH"] = str(path)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Synthetic ACL drift setup failed "
            f"(stderr={completed.stderr.strip()!r})."
        )


_g9.SyntheticJsonFormatter = _StableSyntheticJsonFormatter
_g9.drift_windows_acl = _drift_windows_acl
