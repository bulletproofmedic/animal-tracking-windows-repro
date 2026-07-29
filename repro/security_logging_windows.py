from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import BinaryIO, Callable


class ReproducerValidationError(ValueError):
    """Raised when the sanitized Windows reproducer fails closed."""


FileIdentity = tuple[int, int]


@dataclass(slots=True)
class OpenSource:
    stream: BinaryIO
    path: Path
    identity: FileIdentity
    size_bytes: int
    modified_ns: int
    initial_sha256: str


@lru_cache(maxsize=1)
def powershell_executable() -> str:
    for candidate in ("powershell.exe", "powershell"):
        executable = shutil.which(candidate)
        if executable is None:
            continue
        try:
            completed = subprocess.run(
                [
                    executable,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$PSVersionTable.PSVersion.Major",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed is not None and completed.returncode == 0:
            return executable
    raise PermissionError("PowerShell is required for the Windows ACL reproducer.")


def apply_windows_acl(path: Path, *, directory: bool) -> None:
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
$owner = $verified.Owner.Translate([System.Security.Principal.SecurityIdentifier]).Value
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
            [powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", script],
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


def protect_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise PermissionError(f"Private directory is not a regular directory: {path}.")
    if os.name == "nt":
        apply_windows_acl(path, directory=True)
        return
    os.chmod(path, 0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise PermissionError(f"Private directory mode was not established for {path}.")


def protect_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise PermissionError(f"Private file is not a regular file: {path}.")
    if os.name == "nt":
        apply_windows_acl(path, directory=False)
        return
    os.chmod(path, 0o600)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise PermissionError(f"Private file mode was not established for {path}.")


class ProtectedRotatingFileHandler(RotatingFileHandler):
    def _open(self) -> TextIOWrapper:
        stream = super()._open()
        try:
            protect_private_file(Path(self.baseFilename))
        except Exception:
            stream.close()
            raise
        return stream

    def doRollover(self) -> None:
        super().doRollover()
        protect_private_file(Path(self.baseFilename))
        for index in range(1, self.backupCount + 1):
            backup = Path(f"{self.baseFilename}.{index}")
            if backup.exists():
                protect_private_file(backup)


def read_windows_acl(path: Path) -> dict[str, object]:
    script = r"""
$ErrorActionPreference = 'Stop'
$path = $env:AT_PROTECTED_PATH
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ([System.IO.Directory]::Exists($path)) {
    $acl = [System.IO.Directory]::GetAccessControl($path)
} else {
    $acl = [System.IO.File]::GetAccessControl($path)
}
$owner = $acl.Owner.Translate([System.Security.Principal.SecurityIdentifier]).Value
$rules = @(
    $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        ForEach-Object {
            [PSCustomObject]@{
                sid = $_.IdentityReference.Value
                inherited = $_.IsInherited
                access = $_.AccessControlType.ToString()
                rights = $_.FileSystemRights.ToString()
                inheritance = $_.InheritanceFlags.ToString()
                propagation = $_.PropagationFlags.ToString()
            }
        }
)
[PSCustomObject]@{
    current = $current
    owner = $owner
    protected = $acl.AreAccessRulesProtected
    rules = $rules
} | ConvertTo-Json -Depth 5 -Compress
"""
    environment = os.environ.copy()
    environment["AT_PROTECTED_PATH"] = str(path)
    completed = subprocess.run(
        [powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ReproducerValidationError("ACL query did not return an object.")
    return value


def file_identity(metadata: os.stat_result, path: Path) -> FileIdentity:
    if metadata.st_ino:
        return metadata.st_dev, metadata.st_ino
    raise ReproducerValidationError(f"Could not establish filesystem identity for {path}.")


def sha256_binary_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        if not isinstance(chunk, bytes):
            raise ReproducerValidationError("Source did not provide raw bytes.")
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_source(path: Path) -> OpenSource:
    link_metadata = path.lstat()
    if stat.S_ISLNK(link_metadata.st_mode) or not stat.S_ISREG(link_metadata.st_mode):
        raise ReproducerValidationError("Source must be a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened_metadata = os.fstat(descriptor)
        identity = file_identity(opened_metadata, path)
        if identity != file_identity(link_metadata, path):
            raise ReproducerValidationError("Source changed during validation.")
        stream = os.fdopen(descriptor, "rb", buffering=0)
        descriptor = -1
        return OpenSource(
            stream=stream,
            path=path,
            identity=identity,
            size_bytes=opened_metadata.st_size,
            modified_ns=opened_metadata.st_mtime_ns,
            initial_sha256=sha256_binary_stream(stream),
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_open_source(source: OpenSource) -> None:
    link_metadata = source.path.lstat()
    if stat.S_ISLNK(link_metadata.st_mode) or not stat.S_ISREG(link_metadata.st_mode):
        raise ReproducerValidationError("Source changed during validation.")
    if file_identity(link_metadata, source.path) != source.identity:
        raise ReproducerValidationError("Source path identity changed.")
    final_metadata = os.fstat(source.stream.fileno())
    if (
        file_identity(final_metadata, source.path) != source.identity
        or final_metadata.st_size != source.size_bytes
        or final_metadata.st_mtime_ns != source.modified_ns
    ):
        raise ReproducerValidationError("Source metadata changed.")
    if sha256_binary_stream(source.stream) != source.initial_sha256:
        raise ReproducerValidationError("Source raw bytes changed.")


def copy_strict_utf8(source: OpenSource, destination: Path) -> None:
    source.stream.seek(0)
    with destination.open("x", encoding="utf-8", newline="\n") as output:
        for raw_line in source.stream:
            if not isinstance(raw_line, bytes):
                raise ReproducerValidationError("Source did not provide raw bytes.")
            try:
                line = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ReproducerValidationError("Source is not strict UTF-8.") from error
            output.write(line.rstrip("\r\n") + "\n")
        output.flush()
        os.fsync(output.fileno())
    protect_private_file(destination)
    verify_open_source(source)


def activate_no_clobber(
    temporary: Path,
    destination: Path,
    *,
    validator: Callable[[Path], None] | None = None,
) -> tuple[str, int]:
    try:
        os.link(temporary, destination)
    except FileExistsError as error:
        raise ReproducerValidationError("Destination already exists.") from error
    except OSError as error:
        raise ReproducerValidationError("Activation failed safely.") from error

    activated_identity = file_identity(destination.stat(), destination)
    if activated_identity != file_identity(temporary.stat(), temporary):
        raise ReproducerValidationError("Activation identity is inconsistent.")

    try:
        protect_private_file(destination)
        if destination.is_symlink() or not destination.is_file():
            raise ReproducerValidationError("Activated output is not a regular file.")
        if validator is not None:
            validator(destination)
        result_hash = sha256_file(destination)
        if result_hash != sha256_file(temporary):
            raise ReproducerValidationError("Activated output failed hash verification.")
        return result_hash, destination.stat().st_size
    except Exception:
        try:
            current_identity = file_identity(destination.stat(), destination)
        except (OSError, ReproducerValidationError):
            current_identity = None
        if current_identity == activated_identity and not destination.is_symlink():
            destination.unlink(missing_ok=True)
        raise
