from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .zeek_reader import ZeekReadError, ZeekRecordParser


@dataclass(frozen=True)
class ZeekAvailableRecord:
    record: dict[str, object]
    zeek_available_at: datetime
    source_file: str


@dataclass
class _Cursor:
    offset: int
    identity: tuple[int, int]
    parser: ZeekRecordParser
    line_number: int = 0
    pending: bytes = b""
    discarding_oversized_line: bool = False


@dataclass
class ZeekLogTailer:
    """Bounded incremental reader for Zeek JSON or TSV log files."""

    directory: Path
    filenames: tuple[str, ...]
    max_bytes_per_file_poll: int = 65536
    max_pending_line_bytes: int = 1048576
    cursors: dict[str, _Cursor] = field(default_factory=dict, init=False)
    parse_errors: int = field(default=0, init=False)
    overflow_records: int = field(default=0, init=False)
    active_files: tuple[str, ...] = field(default=(), init=False)
    source_available: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.max_bytes_per_file_poll < 1 or self.max_pending_line_bytes < 1:
            raise ValueError("Tail limits must be positive")
        # LIVE starts at the current end to avoid replaying historical records.
        for name in self.filenames:
            path = self.directory / name
            try:
                stat = path.stat()
            except OSError:
                continue
            self.cursors[name] = _Cursor(
                offset=stat.st_size,
                identity=(stat.st_dev, stat.st_ino),
                parser=ZeekRecordParser(path),
            )
            self._prime_parser(path, self.cursors[name])

    def poll(self) -> list[ZeekAvailableRecord]:
        output: list[ZeekAvailableRecord] = []
        active: list[str] = []
        directory_exists = self.directory.is_dir()
        for name in self.filenames:
            path = self.directory / name
            try:
                stat = path.stat()
                if not path.is_file():
                    continue
                active.append(name)
                identity = (stat.st_dev, stat.st_ino)
                cursor = self.cursors.get(name)
                if cursor is None or cursor.identity != identity or stat.st_size < cursor.offset:
                    cursor = _Cursor(0, identity, ZeekRecordParser(path))
                    self.cursors[name] = cursor
                if stat.st_size <= cursor.offset:
                    continue
                with path.open("rb") as stream:
                    stream.seek(cursor.offset)
                    chunk = stream.read(self.max_bytes_per_file_poll)
                    cursor.offset = stream.tell()
            except OSError:
                continue
            completed = cursor.pending + chunk
            lines = completed.split(b"\n")
            cursor.pending = lines.pop()
            for raw_line in lines:
                cursor.line_number += 1
                if cursor.discarding_oversized_line:
                    cursor.discarding_oversized_line = False
                    continue
                if raw_line.endswith(b"\r"):
                    raw_line = raw_line[:-1]
                if len(raw_line) > self.max_pending_line_bytes:
                    self.parse_errors += 1
                    self.overflow_records += 1
                    continue
                try:
                    line = raw_line.decode("utf-8")
                    record = cursor.parser.parse(line, cursor.line_number)
                except (UnicodeDecodeError, ZeekReadError):
                    self.parse_errors += 1
                    continue
                if record is not None:
                    output.append(ZeekAvailableRecord(record, datetime.now(timezone.utc), name))
            if len(cursor.pending) > self.max_pending_line_bytes:
                self.parse_errors += 1
                self.overflow_records += 1
                cursor.pending = b""
                cursor.discarding_oversized_line = True
        self.active_files = tuple(active)
        self.source_available = directory_exists and bool(active)
        return output

    @staticmethod
    def _prime_parser(path: Path, cursor: _Cursor) -> None:
        """Read only the Zeek header needed to decode future TSV appends."""
        try:
            with path.open("rb") as stream:
                for number in range(1, 257):
                    line = stream.readline(65537)
                    if not line:
                        break
                    cursor.line_number = number
                    if len(line) > 65536:
                        break
                    decoded = line.decode("utf-8")
                    if decoded.startswith("#fields"):
                        cursor.parser.parse(decoded, number)
                        break
                    if decoded and not decoded.startswith("#"):
                        break
        except (OSError, UnicodeDecodeError):
            return
