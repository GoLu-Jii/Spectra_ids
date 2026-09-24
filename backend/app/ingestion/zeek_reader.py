from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class ZeekReadError(ValueError):
    """Raised when a Zeek input line cannot be parsed."""


def iter_zeek_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield records from Zeek JSON-lines or tab-separated logs."""
    input_path = Path(path)
    parser = ZeekRecordParser(input_path)
    with input_path.open("r", encoding="utf-8", newline="") as stream:
        for line_number, line in enumerate(stream, start=1):
            record = parser.parse(line, line_number)
            if record is not None:
                yield record


class ZeekRecordParser:
    """Incremental line decoder shared by file reads and the live tailer."""

    def __init__(self, path: str | Path) -> None:
        input_path = Path(path)
        self.event_type = input_path.stem if input_path.stem in {"conn", "dns", "ssl", "tls", "packet"} else None
        self.fields: list[str] | None = None

    def parse(self, line: str, line_number: int) -> dict[str, Any] | None:
        stripped = line.rstrip("\r\n")
        if not stripped or stripped.startswith("#") and not stripped.startswith("#fields"):
            return None
        if stripped.startswith("#fields"):
            self.fields = stripped[len("#fields") :].lstrip("\t ").split("\t")
            return None
        if self.fields is not None:
            return _parse_tsv(stripped, self.fields, line_number, self.event_type)
        record = _parse_json(stripped, line_number)
        if self.event_type is not None:
            record.setdefault("event_type", self.event_type)
        return record


def read_zeek_records(path: str | Path) -> list[dict[str, Any]]:
    """Read all structured Zeek records from a file."""
    return list(iter_zeek_records(path))


def _parse_json(line: str, line_number: int) -> dict[str, Any]:
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ZeekReadError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
    if not isinstance(record, dict):
        raise ZeekReadError(f"Zeek record on line {line_number} is not an object")
    return record


def _parse_tsv(
    line: str, fields: list[str], line_number: int, event_type: str | None = None
) -> dict[str, Any]:
    values = next(csv.reader([line], delimiter="\t"))
    if len(values) != len(fields):
        raise ZeekReadError(
            f"Zeek TSV line {line_number} has {len(values)} values; expected {len(fields)}"
        )
    record = {field: None if value == "-" else value for field, value in zip(fields, values)}
    if event_type is not None:
        record["event_type"] = event_type
    return record
