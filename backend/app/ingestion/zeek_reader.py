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
    with input_path.open("r", encoding="utf-8", newline="") as stream:
        first_data_line: str | None = None
        fields: list[str] | None = None
        for line_number, line in enumerate(stream, start=1):
            stripped = line.rstrip("\r\n")
            if not stripped:
                continue
            if stripped.startswith("#fields"):
                fields = stripped[len("#fields") :].lstrip("\t ").split("\t")
                continue
            if stripped.startswith("#"):
                continue
            first_data_line = stripped
            break

        if first_data_line is None:
            return

        event_type = input_path.stem if input_path.stem in {"conn", "dns", "ssl", "tls", "packet"} else None
        if fields is not None:
            yield _parse_tsv(first_data_line, fields, line_number, event_type)
            for line_number, line in enumerate(stream, start=line_number + 1):
                stripped = line.rstrip("\r\n")
                if stripped and not stripped.startswith("#"):
                    yield _parse_tsv(stripped, fields, line_number, event_type)
            return

        yield _parse_json(first_data_line, line_number)
        for line_number, line in enumerate(stream, start=line_number + 1):
            stripped = line.strip()
            if stripped:
                yield _parse_json(stripped, line_number)


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
