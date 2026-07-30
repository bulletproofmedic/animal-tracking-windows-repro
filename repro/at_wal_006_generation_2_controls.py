from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Sequence

from at_wal_006_reaudit_controls import (
    ACCEPTED,
    Event,
    Observation,
    SourceSnapshot,
    accepted_matching,
    bound_snapshot,
    normalize_statuses,
    selected_events,
)


class OutputMutationDetected(RuntimeError):
    pass


class ConstructionFailed(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReportBucket:
    key: str
    label: str
    value: int


@dataclass(frozen=True, slots=True)
class OwnedFile:
    name: str
    stream: io.BytesIO

    def close(self) -> None:
        self.stream.close()


@dataclass(slots=True)
class SyntheticBundle:
    files: tuple[OwnedFile, ...]
    input_record: bytes
    manifest: bytes
    closed: bool = False

    def close(self) -> None:
        for item in self.files:
            item.close()
        self.closed = True


def canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def event_record(event: Event) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "status": event.status,
        "capture_time": event.capture_time,
        "observations": [
            asdict(row)
            for row in sorted(
                accepted_matching(event),
                key=lambda row: row.observation_id,
            )
        ],
    }


def report_input_record(
    events: Sequence[Event],
    *,
    statuses: Sequence[str],
    snapshot: SourceSnapshot,
) -> bytes:
    selected = selected_events(events, statuses)
    payload = {
        "schema_version": "generation-2",
        "statuses": sorted(normalize_statuses(statuses)),
        "snapshot": asdict(snapshot),
        "events": [
            event_record(event)
            for event in sorted(selected, key=lambda row: row.event_id)
        ],
    }
    return canonical_bytes(payload)


def replay_report(input_record: bytes) -> tuple[ReportBucket, ...]:
    payload = json.loads(input_record)
    values: dict[tuple[str, str], int] = {}
    for event in payload["events"]:
        for row in event["observations"]:
            key = (row["species_id"], row["species_label"])
            values[key] = values.get(key, 0) + int(row["count_value"])
    return tuple(
        ReportBucket(key=key, label=label, value=value)
        for (key, label), value in sorted(
            values.items(),
            key=lambda item: (item[0][1].casefold(), item[0][0]),
        )
    )


def guarded_report(
    baseline_events: Sequence[Event],
    staged_events: Sequence[Event],
    final_events: Sequence[Event],
    *,
    statuses: Sequence[str],
    before: SourceSnapshot,
    after: SourceSnapshot,
) -> tuple[bytes, tuple[ReportBucket, ...]]:
    snapshot = bound_snapshot(before, after)
    baseline = report_input_record(
        baseline_events,
        statuses=statuses,
        snapshot=snapshot,
    )
    staged = report_input_record(
        staged_events,
        statuses=statuses,
        snapshot=snapshot,
    )
    if staged != baseline:
        raise OutputMutationDetected("output-affecting source data changed")
    result = replay_report(baseline)
    final = report_input_record(
        final_events,
        statuses=statuses,
        snapshot=snapshot,
    )
    if final != baseline:
        raise OutputMutationDetected("output-affecting source data changed")
    return baseline, result


def csv_file(
    name: str,
    rows: Iterable[dict[str, object]],
    *,
    fail: bool = False,
) -> OwnedFile:
    if fail:
        raise OSError(f"simulated construction failure: {name}")
    stream = io.BytesIO()
    text = io.TextIOWrapper(stream, encoding="utf-8", newline="", write_through=True)
    writer = csv.DictWriter(text, fieldnames=("id", "label"), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    text.flush()
    text.detach()
    stream.seek(0)
    return OwnedFile(name=name, stream=stream)


def build_two_files(
    first_factory: Callable[[], OwnedFile],
    second_factory: Callable[[], OwnedFile],
) -> tuple[OwnedFile, ...]:
    files: list[OwnedFile] = []
    try:
        files.append(first_factory())
        files.append(second_factory())
    except BaseException:
        for item in files:
            item.close()
        raise
    return tuple(files)


def build_archive(
    bundle: SyntheticBundle,
    archive_factory: Callable[[], io.BytesIO],
) -> io.BytesIO:
    archive: io.BytesIO | None = None
    response_owns_archive = False
    try:
        archive = archive_factory()
        archive.write(bundle.manifest)
        for item in bundle.files:
            archive.write(item.stream.getvalue())
        archive.seek(0)
        response_owns_archive = True
        return archive
    except OSError as exc:
        raise ConstructionFailed("no partial download was produced") from exc
    finally:
        bundle.close()
        if archive is not None and not response_owns_archive:
            archive.close()


def export_input_and_manifest(
    events: Sequence[Event],
    *,
    statuses: Sequence[str],
    snapshot: SourceSnapshot,
) -> tuple[bytes, bytes]:
    input_record = report_input_record(
        events,
        statuses=statuses,
        snapshot=snapshot,
    )
    manifest_payload = {
        "schema_version": "generation-2",
        "input_sha256": hashlib.sha256(input_record).hexdigest(),
        "snapshot": asdict(snapshot),
    }
    return input_record, canonical_bytes(manifest_payload)


def semantic_mutation_is_killed(
    source: str,
    *,
    marker: str,
    replacement: str,
    behavioral_check: Callable[[str], bool],
) -> bool:
    if marker not in source:
        raise ValueError("mutation marker missing")
    mutant = source.replace(marker, replacement, 1)
    return not behavioral_check(mutant)
