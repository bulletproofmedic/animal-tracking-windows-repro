from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SECURITY_BUNDLE_MAX_LOG_FILES = 12
SECURITY_BUNDLE_MAX_TOTAL_LOG_BYTES = 102 * 1024 * 1024


def is_loopback_origin(origin: str, *, expected_port: int) -> bool:
    if not isinstance(origin, str) or not origin or origin != origin.strip():
        return False
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.casefold() == "http"
        and parsed.hostname is not None
        and parsed.hostname.casefold() in LOOPBACK_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port == expected_port
    )


def mutation_allowed(
    method: str,
    *,
    origin: str | None,
    referer: str | None,
    expected_port: int,
) -> bool:
    if method.upper() not in MUTATING_METHODS:
        return True
    if origin is not None:
        return is_loopback_origin(origin, expected_port=expected_port)
    if referer is not None:
        return is_loopback_origin(referer, expected_port=expected_port)
    return False


class SinkStage(StrEnum):
    COMPLETE = "COMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


class SinkError(RuntimeError):
    pass


@dataclass(slots=True)
class DurableEventSink:
    path: Path
    stage: SinkStage = SinkStage.COMPLETE

    def emit(
        self,
        event_code: str,
        *,
        correlation_id: str,
        fail: str | None = None,
    ) -> str:
        if self.stage is SinkStage.UNAVAILABLE:
            raise SinkError("sink unavailable")
        record_id = uuid4().hex
        payload = {
            "event_code": event_code,
            "correlation_id": correlation_id,
            "record_id": record_id,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a+b") as stream:
                original = os.fstat(stream.fileno())
                if fail == "write":
                    raise OSError("forced write failure")
                stream.write((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
                if fail == "flush":
                    raise OSError("forced flush failure")
                stream.flush()
                if fail == "fsync":
                    raise OSError("forced fsync failure")
                os.fsync(stream.fileno())
                if fail == "path_replacement":
                    replacement = self.path.with_suffix(".replacement")
                    replacement.write_text("replacement\n", encoding="utf-8")
                    os.replace(replacement, self.path)
                current = self.path.stat()
                if (
                    original.st_dev != current.st_dev
                    or (original.st_ino and current.st_ino and original.st_ino != current.st_ino)
                ):
                    raise OSError("path identity changed")
                if fail == "acl":
                    raise PermissionError("forced ACL failure")
            if record_id.encode("ascii") not in self.path.read_bytes():
                raise OSError("record acknowledgement missing")
            return record_id
        except Exception as error:
            self.stage = SinkStage.UNAVAILABLE
            raise SinkError("mandatory event was not durably acknowledged") from error
