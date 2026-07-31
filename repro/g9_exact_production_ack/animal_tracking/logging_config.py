from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import stat
import subprocess
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from functools import lru_cache
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType

_LOG_FILENAME = "animal-tracking.log"
_LOG_MAX_BYTES = 10 * 1024 * 1024
# RotatingFileHandler retains the active file in addition to backupCount files.
_LOG_BACKUP_COUNT = 9
_REDACTED = "<redacted>"
_BINARY_REDACTED = "<binary-redacted>"
_PATH_REDACTED = "<path-redacted>"
_COORDINATES_REDACTED = "<coordinates-redacted>"
_NON_FINITE_REDACTED = "<non-finite-number>"
_UNSUPPORTED_FIELD_REDACTED = "<unsupported-field-redacted>"
_TRUNCATION_MARKER = "<truncated>"
_MAX_SAFE_STRING_BYTES = 1024
_MAX_DECLARED_SENSITIVE_LITERALS = 32
_MAX_DECLARED_SENSITIVE_LITERAL_BYTES = 512

_SENSITIVE_KEY_PARTS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "coordinate",
    "credential",
    "csrf",
    "exception_detail",
    "filename",
    "gps",
    "latitude",
    "location",
    "longitude",
    "notes",
    "original_filename",
    "owner_note",
    "password",
    "passwd",
    "pin",
    "position",
    "private",
    "property_name",
    "secret",
    "session",
    "stack",
    "token",
    "traceback",
}

_SAFE_STRING_FIELDS = {
    "application_version",
    "error_code",
    "mode",
    "operation",
    "outcome",
    "reason_code",
    "record_type",
    "result",
    "schema_version",
    "source_commit",
    "status",
}
_SAFE_INTEGER_FIELDS = {
    "attempt",
    "byte_count",
    "count",
    "file_count",
    "item_count",
    "member_count",
}
_SAFE_NUMBER_FIELDS = {"duration_ms"}
_SAFE_BOOLEAN_FIELDS = {"enabled"}
_SAFE_FIELD_NAMES = (
    _SAFE_STRING_FIELDS | _SAFE_INTEGER_FIELDS | _SAFE_NUMBER_FIELDS | _SAFE_BOOLEAN_FIELDS
)
_LOG_RECORD_FIELDS = {
    "component",
    "correlation_id",
    "event_code",
    "exception_class",
    "fields",
    "message",
    "record_id",
    "severity",
    "timestamp",
}

_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    [\"']?
    \b(
        api[\s._-]*key
        |authorization
        |bearer
        |cookie
        |credential
        |csrf(?:[\s._-]*middleware)?[\s._-]*token
        |pass(?:[\s._-]*word|wd)?
        |pin
        |private[\s._-]*key
        |secret
        |session(?:[\s._-]*id)?
        |token
    )\b
    [\"']?
    \s*[:=]\s*
    (
        \"(?:[^\"\\]|\\.)*\"
        |'(?:[^'\\]|\\.)*'
        |[^\r\n,;}\]]+
    )
    """
)
_AUTHORIZATION_TOKEN = re.compile(
    r"(?i)\b(?:authorization\s*[:=]?\s*)?(?:basic|bearer)\s+[A-Za-z0-9._~+/=-]+"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_JWT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_CLOUD_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_LABELED_COORDINATE = re.compile(
    r"""(?ix)
    \b(latitude|longitude|lat|lon|lng|coordinate|coordinates|gps|location|position)\b
    [\"']?\s*[:=]\s*
    [-+]?(?:\d{1,3}(?:\.\d+)?|\.\d+)
    """
)
# Unlabelled pairs require precision evidence. Ordinary integer pairs remain observable.
_COORDINATE_PAIR = re.compile(
    r"""(?x)
    (?<![\w.])
    [-+]?(?:[0-8]?\d\.\d{3,}|90\.0{3,})
    (?:\s*[,/;]\s*|\s+)
    [-+]?(?:(?:1[0-7]\d|[0-9]?\d)\.\d{3,}|180\.0{3,})
    (?![\w.])
    """
)
_DMS_COORDINATE_PAIR = re.compile(
    r"(?ix)\b\d{1,2}\s*[°º]\s*\d{1,2}"
    r"(?:\s*['′]\s*\d{1,2}(?:\.\d+)?)?\s*[\"″]?\s*[NS]\b"
    r".{0,24}?"
    r"\b\d{1,3}\s*[°º]\s*\d{1,2}"
    r"(?:\s*['′]\s*\d{1,2}(?:\.\d+)?)?\s*[\"″]?\s*[EW]\b"
)
_PLUS_CODE = re.compile(r"(?i)\b[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3}\b")
_LABELED_UTM = re.compile(
    r"(?i)\bUTM\b\s*[:=]?\s*\d{1,2}[C-HJ-NP-X]?\s+\d{3,7}\s+\d{4,8}\b"
)
_WINDOWS_PATH = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9])
    (?:
        [A-Z]:[\\/]
        |(?:\\\\|//)[^\\/\s]+[\\/]
        |file:///[A-Z]:/
    )
    [^<>\"|?*\r\n,;)}\]]+
    """
)
_POSIX_PATH = re.compile(
    r"""(?x)
    (?<![:/A-Za-z0-9])
    (?:file://)?/(?!/)[^\s,;)}\]]+
    """
)
_RELATIVE_PRIVATE_PATH = re.compile(
    r"(?i)(?<![\w])(?:\.\.?[\\/])(?:[^\s,;)}\]]+[\\/])+[^\s,;)}\]]+"
)
_FILENAME = re.compile(
    r"""(?ix)
    (?<![\w.-])
    [\w][\w .()\[\]-]{0,120}\.
    [a-z0-9]{2,10}
    (?![\w.-])
    """
)
_PROPERTY_IDENTIFIER = re.compile(r"(?i)\b[\w][\w' -]{1,80}\s+property\b")
_CLASSIFIED_LOCATION_IDENTIFIER = re.compile(
    r"(?i)\b(?:north|south|east|west|upper|lower|back|front|old|new)\s+"
    r"(?:field|creek|trail|ridge|hill|pond|woods|forest|meadow|marsh|swamp|stand|site|camera)\b"
)
_COMPONENT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,256}")
_EVENT_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_EXCEPTION_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}")
_SEVERITY = re.compile(r"(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")

ExcInfo = (
    bool | BaseException | tuple[type[BaseException], BaseException, TracebackType | None] | None
)


class SensitiveValueValidationError(ValueError):
    """Raised when declared sensitive values cannot be applied completely."""


def _normalize_security_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return "".join(character for character in normalized if unicodedata.category(character) != "Cf")


def _normalize_key(key: str) -> str:
    normalized = _normalize_security_text(key).casefold().strip()
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")


def _contains_sensitive_key(key: str) -> bool:
    normalized = _normalize_key(key)
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _validated_sensitive_values(values: Sequence[str] = ()) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray, memoryview)) or not isinstance(values, Sequence):
        raise SensitiveValueValidationError("Sensitive values must be a sequence of strings.")
    if len(values) > _MAX_DECLARED_SENSITIVE_LITERALS:
        raise SensitiveValueValidationError(
            f"At most {_MAX_DECLARED_SENSITIVE_LITERALS} sensitive values may be declared."
        )

    normalized: dict[str, str] = {}
    for raw_value in values:
        if not isinstance(raw_value, str):
            raise SensitiveValueValidationError("Every sensitive value must be text.")
        candidate = _normalize_security_text(raw_value).strip()
        if not candidate:
            raise SensitiveValueValidationError("Sensitive values cannot be empty.")
        if len(candidate.encode("utf-8")) > _MAX_DECLARED_SENSITIVE_LITERAL_BYTES:
            raise SensitiveValueValidationError("A sensitive value exceeds the byte limit.")
        normalized.setdefault(candidate.casefold(), candidate)
    return tuple(sorted(normalized.values(), key=lambda item: (-len(item), item.casefold())))


def _redact_declared_sensitive_literals(value: str, sensitive_values: Sequence[str]) -> str:
    redacted = value
    for candidate in _validated_sensitive_values(sensitive_values):
        redacted = re.sub(re.escape(candidate), _REDACTED, redacted, flags=re.IGNORECASE)
    return redacted


def sanitize_log_text(value: str, sensitive_values: Sequence[str] = ()) -> str:
    """Normalize and remove credentials, locations, identifiers, and private paths."""

    redacted = _normalize_security_text(value)
    redacted = _redact_declared_sensitive_literals(redacted, sensitive_values)
    redacted = _PRIVATE_KEY_BLOCK.sub(_REDACTED, redacted)
    redacted = _AUTHORIZATION_TOKEN.sub(_REDACTED, redacted)
    redacted = _CREDENTIAL_ASSIGNMENT.sub(_REDACTED, redacted)
    redacted = _JWT_TOKEN.sub(_REDACTED, redacted)
    redacted = _CLOUD_ACCESS_KEY.sub(_REDACTED, redacted)
    redacted = _LABELED_COORDINATE.sub(_COORDINATES_REDACTED, redacted)
    redacted = _DMS_COORDINATE_PAIR.sub(_COORDINATES_REDACTED, redacted)
    redacted = _LABELED_UTM.sub(_COORDINATES_REDACTED, redacted)
    redacted = _PLUS_CODE.sub(_COORDINATES_REDACTED, redacted)
    redacted = _COORDINATE_PAIR.sub(_COORDINATES_REDACTED, redacted)
    redacted = _WINDOWS_PATH.sub(_PATH_REDACTED, redacted)
    redacted = _POSIX_PATH.sub(_PATH_REDACTED, redacted)
    redacted = _RELATIVE_PRIVATE_PATH.sub(_PATH_REDACTED, redacted)
    redacted = _FILENAME.sub(_REDACTED, redacted)
    redacted = _PROPERTY_IDENTIFIER.sub(_REDACTED, redacted)
    return _CLASSIFIED_LOCATION_IDENTIFIER.sub(_REDACTED, redacted)


def _truncate_utf8(value: str, *, limit: int, marker: str = _TRUNCATION_MARKER) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) > limit:
        return marker_bytes[:limit].decode("utf-8", errors="ignore")
    budget = limit - len(marker_bytes)
    prefix = encoded[:budget].decode("utf-8", errors="ignore")
    result = prefix + marker
    while len(result.encode("utf-8")) > limit and prefix:
        prefix = prefix[:-1]
        result = prefix + marker
    return result


def _bounded_safe_text(value: str, sensitive_values: Sequence[str] = ()) -> str:
    return _truncate_utf8(
        sanitize_log_text(value, sensitive_values),
        limit=_MAX_SAFE_STRING_BYTES,
    )


def _bounded_grammar_text(
    value: object,
    pattern: re.Pattern[str],
    fallback: str = _REDACTED,
) -> str:
    try:
        normalized = _normalize_security_text(str(value))
    except Exception:
        return fallback
    if pattern.fullmatch(normalized) is None:
        return fallback
    return normalized


def _bounded_component_text(value: object) -> str:
    return _bounded_grammar_text(value, _COMPONENT_NAME)


def _sanitize_registered_field(
    key: str, value: object, sensitive_values: Sequence[str] = ()
) -> object:
    if isinstance(value, str) and value in {
        _REDACTED,
        _BINARY_REDACTED,
        _PATH_REDACTED,
        _COORDINATES_REDACTED,
        _NON_FINITE_REDACTED,
        _UNSUPPORTED_FIELD_REDACTED,
    }:
        return value
    if key in _SAFE_STRING_FIELDS:
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return _UNSUPPORTED_FIELD_REDACTED
        return _bounded_safe_text(str(value), sensitive_values)
    if key in _SAFE_INTEGER_FIELDS:
        if not isinstance(value, int) or isinstance(value, bool):
            return _UNSUPPORTED_FIELD_REDACTED
        return value
    if key in _SAFE_NUMBER_FIELDS:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return _UNSUPPORTED_FIELD_REDACTED
        if isinstance(value, float) and not math.isfinite(value):
            return _NON_FINITE_REDACTED
        return value
    if key in _SAFE_BOOLEAN_FIELDS:
        return value if isinstance(value, bool) else _UNSUPPORTED_FIELD_REDACTED
    return _UNSUPPORTED_FIELD_REDACTED


def sanitize_log_value(key: str, value: object, sensitive_values: Sequence[str] = ()) -> object:
    """Sanitize one value under the closed structured-field registry."""

    validated_sensitive_values = _validated_sensitive_values(sensitive_values)
    normalized_key = _normalize_key(key)
    if _contains_sensitive_key(normalized_key):
        return _REDACTED
    if isinstance(value, Path):
        return _PATH_REDACTED
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _BINARY_REDACTED
    if normalized_key not in _SAFE_FIELD_NAMES:
        return _UNSUPPORTED_FIELD_REDACTED
    return _sanitize_registered_field(normalized_key, value, validated_sensitive_values)


def sanitize_log_fields(
    fields: Mapping[str, object], sensitive_values: Sequence[str] = ()
) -> dict[str, object]:
    """Return only registered structured fields using canonical field identifiers."""

    validated_sensitive_values = _validated_sensitive_values(sensitive_values)
    sanitized: dict[str, object] = {}
    for raw_key, value in fields.items():
        key = _normalize_key(str(raw_key))
        if not key or key not in _SAFE_FIELD_NAMES:
            continue
        sanitized[key] = sanitize_log_value(key, value, validated_sensitive_values)
    return sanitized


def sanitize_log_record(
    value: object, sensitive_values: Sequence[str] = ()
) -> dict[str, object]:
    """Apply the closed JSONL record schema to an existing record before export."""

    validated_sensitive_values = _validated_sensitive_values(sensitive_values)
    if not isinstance(value, Mapping):
        return {
            "event_code": "LEGACY_LOG_VALUE",
            "message": _bounded_safe_text(str(value), validated_sensitive_values),
        }

    sanitized: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        key = _normalize_key(str(raw_key))
        if key not in _LOG_RECORD_FIELDS:
            continue
        if key == "fields":
            if isinstance(raw_value, Mapping):
                safe_fields = sanitize_log_fields(
                    {str(field_key): field_value for field_key, field_value in raw_value.items()},
                    validated_sensitive_values,
                )
                if safe_fields:
                    sanitized[key] = safe_fields
            continue
        if key in {"correlation_id", "record_id", "message"}:
            sanitized[key] = _bounded_safe_text(str(raw_value), validated_sensitive_values)
            continue
        if key == "component":
            sanitized[key] = _bounded_component_text(raw_value)
            continue
        if key == "event_code":
            sanitized[key] = _bounded_grammar_text(raw_value, _EVENT_CODE, "LEGACY_LOG_RECORD")
            continue
        if key == "severity":
            sanitized[key] = _bounded_grammar_text(raw_value, _SEVERITY, "INFO")
            continue
        if key == "exception_class":
            sanitized[key] = _bounded_grammar_text(raw_value, _EXCEPTION_CLASS)
            continue
        if key == "timestamp":
            sanitized[key] = _bounded_grammar_text(
                raw_value,
                _TIMESTAMP,
                "1970-01-01T00:00:00Z",
            )

    sanitized.setdefault("event_code", "LEGACY_LOG_RECORD")
    sanitized.setdefault("message", "Legacy log record")
    return sanitized


def _default_event_code(record: logging.LogRecord) -> str:
    try:
        name = str(record.name)
        level = str(record.levelname)
    except Exception:
        return "LOG_ROOT_ERROR"
    component = re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
    candidate = f"LOG_{component or 'ROOT'}_{level}"
    return candidate if _EVENT_CODE.fullmatch(candidate) else "LOG_ROOT_ERROR"


def _safe_timestamp(value: object) -> str:
    try:
        created = float(value)
        if not math.isfinite(created):
            raise ValueError("non-finite timestamp")
        return datetime.fromtimestamp(created, tz=UTC).isoformat().replace("+00:00", "Z")
    except Exception:
        return "1970-01-01T00:00:00Z"


def _minimal_serialization_failure(_record: logging.LogRecord) -> str:
    # The fallback is intentionally independent of all untrusted record attributes.
    return (
        '{"component":"animal_tracking.logging","event_code":"LOG_SERIALIZATION_FAILURE",'
        '"message":"Log event could not be serialized safely","severity":"ERROR",'
        '"timestamp":"1970-01-01T00:00:00Z"}'
    )


class SafeJsonFormatter(logging.Formatter):
    """Emit one privacy-filtered, standards-conformant JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        try:
            raw_sensitive_values = getattr(record, "sensitive_values", ())
            declared_sensitive_values = _validated_sensitive_values(raw_sensitive_values)
            event_code = _bounded_grammar_text(
                getattr(record, "event_code", _default_event_code(record)),
                _EVENT_CODE,
                "LOG_INVALID_EVENT_CODE",
            )
            correlation_id = getattr(record, "correlation_id", None)
            record_id = getattr(record, "record_id", None)
            safe_fields = getattr(record, "safe_fields", None)

            payload: dict[str, object] = {
                "timestamp": _safe_timestamp(record.created),
                "severity": _bounded_grammar_text(record.levelname, _SEVERITY, "ERROR"),
                "event_code": event_code,
                "component": _bounded_component_text(record.name),
                "message": _bounded_safe_text(record.getMessage(), declared_sensitive_values),
            }
            if correlation_id is not None:
                payload["correlation_id"] = _bounded_safe_text(
                    str(correlation_id),
                    declared_sensitive_values,
                )
            if record_id is not None:
                payload["record_id"] = _bounded_safe_text(
                    str(record_id),
                    declared_sensitive_values,
                )
            if isinstance(safe_fields, Mapping):
                sanitized_fields = sanitize_log_fields(
                    {str(key): value for key, value in safe_fields.items()},
                    declared_sensitive_values,
                )
                if sanitized_fields:
                    payload["fields"] = sanitized_fields
            if record.exc_info and record.exc_info[0] is not None:
                payload["exception_class"] = _bounded_grammar_text(
                    record.exc_info[0].__name__,
                    _EXCEPTION_CLASS,
                )

            return json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except Exception:
            return _minimal_serialization_failure(record)


def log_event(
    logger: logging.Logger,
    level: int,
    event_code: str,
    message: str,
    *,
    correlation_id: str | None = None,
    record_id: str | None = None,
    fields: Mapping[str, object] | None = None,
    sensitive_values: Sequence[str] | None = None,
    exc_info: ExcInfo = None,
) -> None:
    """Write one structured event through the privacy-filtering formatter."""

    declared_sensitive_values = _validated_sensitive_values(tuple(sensitive_values or ()))
    if _EVENT_CODE.fullmatch(_normalize_security_text(event_code)) is None:
        raise ValueError("event_code is outside the closed event-code grammar.")

    extra: dict[str, object] = {
        "event_code": event_code,
        "sensitive_values": declared_sensitive_values,
    }
    if correlation_id is not None:
        extra["correlation_id"] = correlation_id
    if record_id is not None:
        extra["record_id"] = record_id
    if fields is not None:
        extra["safe_fields"] = sanitize_log_fields(fields, declared_sensitive_values)
    logger.log(level, message, extra=extra, exc_info=exc_info)


@lru_cache(maxsize=1)
def _powershell_executable() -> str:
    for candidate in ("powershell.exe", "powershell"):
        executable = shutil.which(candidate)
        if executable is None:
            continue
        try:
            completed = subprocess.run(  # noqa: S603 - fixed executable and argument vector
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
    raise PermissionError("PowerShell is required to establish private Windows file ACLs.")


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
        completed = subprocess.run(  # noqa: S603 - fixed PowerShell script and env-only path
            [_powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", script],
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
    """Establish and verify a private directory boundary or fail closed."""

    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise PermissionError(f"Private directory is not a regular directory: {path}.")
    if os.name == "nt":
        _apply_windows_acl(path, directory=True)
        return
    os.chmod(path, 0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise PermissionError(f"Private directory mode was not established for {path}.")


def protect_private_file(path: Path) -> None:
    """Establish and verify owner-private file access or fail closed."""

    if path.is_symlink() or not path.is_file():
        raise PermissionError(f"Private file is not a regular file: {path}.")
    if os.name == "nt":
        _apply_windows_acl(path, directory=False)
        return
    os.chmod(path, 0o600)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise PermissionError(f"Private file mode was not established for {path}.")


class ProtectedRotatingFileHandler(RotatingFileHandler):
    """Rotating handler that reapplies the private-file boundary after every rollover."""

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


def _build_handler(handler: logging.Handler) -> logging.Handler:
    handler.setFormatter(SafeJsonFormatter())
    return handler


def configure_logging(log_directory: Path | None = None) -> None:
    handlers: list[logging.Handler] = [_build_handler(logging.StreamHandler())]
    if log_directory is not None:
        protect_private_directory(log_directory)
        log_path = log_directory / _LOG_FILENAME
        if log_path.is_symlink():
            raise PermissionError(f"Log path cannot be a symbolic link: {log_path}.")
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(log_path, flags, 0o600)
        os.close(descriptor)
        protect_private_file(log_path)
        file_handler = ProtectedRotatingFileHandler(
            log_path,
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handlers.append(_build_handler(file_handler))
    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True)
