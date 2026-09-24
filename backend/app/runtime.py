from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .config.runtime import RuntimeConfig
from .ingestion.normalizer import EventNormalizationError, normalize_zeek_record
from .ingestion.zeek_reader import ZeekReadError, ZeekRecordParser
from .ingestion.zeek_tailer import ZeekLogTailer


@dataclass
class ZeekRuntime:
    """Connect Zeek files to an already configured SPECTRA orchestrator."""

    config: RuntimeConfig
    orchestrator: Any
    tailer: ZeekLogTailer | None = None
    task: asyncio.Task[None] | None = field(default=None, init=False)
    running: bool = field(default=False, init=False)
    events_ingested: int = field(default=0, init=False)
    normalization_errors: int = field(default=0, init=False)
    source_errors: int = field(default=0, init=False)
    _event_index: int = field(default=0, init=False)
    replay_files: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if self.config.mode == "LIVE":
            self.tailer = ZeekLogTailer(
                self.config.zeek_log_dir,
                self.config.log_files,
                self.config.max_bytes_per_file_poll,
                self.config.max_pending_line_bytes,
            )

    async def start(self) -> None:
        if self.running:
            return
        if self.config.mode == "TEST":
            return
        self.running = True
        if self.config.mode == "LIVE":
            self.task = asyncio.create_task(self._run_live(), name="spectra-zeek-live")
        elif self.config.mode == "REPLAY":
            self.task = asyncio.create_task(self._run_replay(), name="spectra-zeek-replay")
        # TEST leaves ingestion under direct control of the test harness.

    async def stop(self) -> None:
        self.running = False
        task, self.task = self.task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self.config.flush_on_shutdown:
            self.orchestrator.flush()

    def snapshot(self) -> dict[str, object]:
        tailer = self.tailer
        ordering_stats = getattr(getattr(self.orchestrator, "ordering", None), "stats", None)
        return {
            "runtime_mode": self.config.mode,
            "zeek_source_available": tailer.source_available if tailer else bool(self.replay_files),
            "zeek_log_directory": str(self.config.zeek_log_dir),
            "files_consumed": list(tailer.active_files) if tailer else list(self.replay_files),
            "events_ingested": self.events_ingested,
            "normalization_errors": self.normalization_errors,
            "source_errors": self.source_errors,
            "tail_overflow_events": tailer.overflow_records if tailer else 0,
            "zeek_parse_errors": tailer.parse_errors if tailer else 0,
            "late_events": getattr(ordering_stats, "late_events", None),
            "too_late_events": getattr(ordering_stats, "too_late_events", None),
            "events_rejected_or_late": self.orchestrator.get_metrics().get("events_rejected_or_late", 0),
            "running": self.running,
        }

    async def _run_live(self) -> None:
        assert self.tailer is not None
        while self.running:
            try:
                for available in self.tailer.poll():
                    self._ingest(available.record, available.source_file, available.zeek_available_at)
            except OSError:
                self.source_errors += 1
            await asyncio.sleep(self.config.poll_interval_seconds)

    async def _run_replay(self) -> None:
        for filename in self.config.log_files:
            path = self.config.zeek_log_dir / filename
            if not path.is_file():
                continue
            self.replay_files.append(filename)
            try:
                parser = ZeekRecordParser(path)
                with path.open("r", encoding="utf-8", newline="") as stream:
                    for line_number, line in enumerate(stream, 1):
                        if not self.running:
                            return
                        try:
                            record = parser.parse(line, line_number)
                        except ZeekReadError:
                            self.source_errors += 1
                            await asyncio.sleep(0)
                            continue
                        if record is not None:
                            # Replay uses deterministic record order and deliberately has no t1.
                            self._ingest(record, filename, None, event_index=self._event_index)
                            self._event_index += 1
                        await asyncio.sleep(0)
            except (OSError, UnicodeError):
                self.source_errors += 1
        self.running = False

    def _ingest(
        self,
        record: dict[str, object],
        source_file: str,
        available_at: datetime | None,
        *,
        event_index: int | None = None,
    ) -> None:
        try:
            event = normalize_zeek_record(record)
        except (EventNormalizationError, TypeError, ValueError):
            self.normalization_errors += 1
            return
        if event_index is None:
            self._event_index += 1
            event_index = self._event_index
        self.events_ingested += 1
        try:
            self.orchestrator.process_event(
                event,
                event_id=f"{source_file}:{event_index}",
                zeek_available_at=available_at,
            )
        except Exception:
            # Keep a faulty event from terminating the long-running source task.
            self.source_errors += 1
            return
