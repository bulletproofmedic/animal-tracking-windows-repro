from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(frozen=True)
class Policy:
    minimum: int
    max_count: int
    max_bytes: int
    max_age_days: int


@dataclass(frozen=True)
class Record:
    operation_id: str
    quarantined_at: datetime
    byte_count: int


class Lifecycle:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.failed = root / "failed"
        self.disposal = root / "disposal"
        self.metadata = root / "metadata"
        for directory in (self.failed, self.disposal, self.metadata):
            directory.mkdir(parents=True, exist_ok=True)

    def metadata_path(self, operation_id: str) -> Path:
        return self.metadata / f"{operation_id}.json"

    def create(self, operation_id: str, when: datetime, size: int, name: str) -> Path:
        target = self.failed / operation_id
        target.mkdir()
        (target / name).write_bytes(b"x" * size)
        self._write(operation_id, {"operation_id": operation_id, "state": "RETAINED", "quarantined_at": when.astimezone(UTC).isoformat(), "byte_count": size, "file_count": 1, "export_count": 0})
        return target

    def _read(self, operation_id: str) -> dict[str, object]:
        return json.loads(self.metadata_path(operation_id).read_text(encoding="utf-8"))

    def _write(self, operation_id: str, value: dict[str, object]) -> None:
        path = self.metadata_path(operation_id)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)

    def records(self) -> list[Record]:
        result: list[Record] = []
        for path in sorted(self.failed.iterdir()):
            metadata = self._read(path.name)
            size = sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
            result.append(Record(path.name, datetime.fromisoformat(str(metadata["quarantined_at"])).astimezone(UTC), size))
        return sorted(result, key=lambda item: (item.quarantined_at, item.operation_id))

    def resume(self, now: datetime) -> int:
        pending = {path.name for path in self.disposal.iterdir()}
        for path in self.metadata.glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("state") == "DISPOSING":
                pending.add(path.stem)
        count = 0
        for operation_id in sorted(pending):
            source = self.failed / operation_id
            target = self.disposal / operation_id
            if source.exists() and target.exists():
                raise RuntimeError("conflicting disposal state")
            if source.exists():
                os.replace(source, target)
            if target.exists():
                shutil.rmtree(target)
            metadata = self._read(operation_id)
            metadata.update({"state": "DISPOSED", "disposed_at": now.astimezone(UTC).isoformat()})
            self._write(operation_id, metadata)
            count += 1
        return count

    def reconcile(self, policy: Policy, now: datetime, *, protected: set[str] | None = None, authority_guarded: bool = False) -> tuple[set[str], set[str]]:
        self.resume(now)
        records = self.records()
        if authority_guarded:
            return {record.operation_id for record in records}, set()
        protected = set(protected or set())
        protected.update(record.operation_id for record in sorted(records, key=lambda item: item.quarantined_at, reverse=True)[: policy.minimum])
        retained = list(records)
        disposed: list[Record] = []

        def eligible() -> list[Record]:
            return [record for record in retained if record.operation_id not in protected and len(retained) > policy.minimum]

        cutoff = now - timedelta(days=policy.max_age_days)
        for record in list(retained):
            if record.quarantined_at < cutoff and record in eligible():
                retained.remove(record)
                disposed.append(record)
        while len(retained) > policy.max_count and eligible():
            record = eligible()[0]
            retained.remove(record)
            disposed.append(record)
        total = sum(record.byte_count for record in retained)
        while total > policy.max_bytes and eligible():
            record = eligible()[0]
            retained.remove(record)
            total -= record.byte_count
            disposed.append(record)

        for record in disposed:
            metadata = self._read(record.operation_id)
            metadata["state"] = "DISPOSING"
            self._write(record.operation_id, metadata)
            os.replace(self.failed / record.operation_id, self.disposal / record.operation_id)
            shutil.rmtree(self.disposal / record.operation_id)
            metadata["state"] = "DISPOSED"
            metadata["disposed_at"] = now.astimezone(UTC).isoformat()
            self._write(record.operation_id, metadata)
        return {record.operation_id for record in retained}, {record.operation_id for record in disposed}

    def export(self, operation_id: str, destination: Path, *, approved: bool) -> str:
        if not approved:
            raise RuntimeError("approval required")
        source = self.failed / operation_id
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(source).as_posix())
        raw = destination.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        metadata = self._read(operation_id)
        metadata.update({"export_count": int(metadata.get("export_count", 0)) + 1, "last_export_sha256": digest, "last_export_bytes": len(raw)})
        self._write(operation_id, metadata)
        return digest
