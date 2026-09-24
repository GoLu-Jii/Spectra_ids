from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from heapq import heappop, heappush
from typing import Literal

from ..ingestion.events import NormalizedEvent

LateEventBehavior = Literal["release", "quarantine"]
OverflowBehavior = Literal["release_oldest", "reject"]


@dataclass(frozen=True)
class ReorderConfig:
    """Explicit policy for timestamp ordering and bounded buffering."""

    maximum_lateness: timedelta
    buffer_capacity: int
    late_event_behavior: LateEventBehavior = "release"
    overflow_behavior: OverflowBehavior = "release_oldest"

    def __post_init__(self) -> None:
        if self.maximum_lateness < timedelta(0):
            raise ValueError("maximum_lateness must be non-negative")
        if self.buffer_capacity < 1:
            raise ValueError("buffer_capacity must be positive")


@dataclass(frozen=True)
class ReorderEntry:
    event: NormalizedEvent
    arrival_index: int
    event_id: str


@dataclass(frozen=True)
class ReorderOutcome:
    accepted: bool
    late: bool
    too_late: bool
    released: tuple[ReorderEntry, ...] = ()
    quarantined: tuple[ReorderEntry, ...] = ()


@dataclass
class ReorderStats:
    events_accepted: int = 0
    events_released: int = 0
    late_events: int = 0
    too_late_events: int = 0
    current_buffer_depth: int = 0
    peak_buffer_depth: int = 0
    overflow_events: int = 0


class BufferOverflowError(RuntimeError):
    """Raised when a configured reject-on-overflow policy is triggered."""


class ReorderBuffer:
    """Bounded timestamp reorder buffer for normalized passive events."""

    def __init__(self, config: ReorderConfig) -> None:
        self.config = config
        self.stats = ReorderStats()
        self._buffer: list[tuple[datetime, int, ReorderEntry]] = []
        self._arrival_index = 0
        self._max_seen_at: datetime | None = None

    def push(self, event: NormalizedEvent, event_id: str | None = None) -> ReorderOutcome:
        """Accept an event and release entries safe under the current watermark."""
        arrival_index = self._arrival_index
        self._arrival_index += 1
        entry = ReorderEntry(
            event=event,
            arrival_index=arrival_index,
            event_id=event_id or event.flow_id or f"event-{arrival_index}",
        )
        is_late = self._max_seen_at is not None and event.observed_at < self._max_seen_at
        self.stats.late_events += int(is_late)
        if self._max_seen_at is None or event.observed_at > self._max_seen_at:
            self._max_seen_at = event.observed_at

        watermark = self.watermark
        if watermark is not None and event.observed_at < watermark:
            self.stats.too_late_events += 1
            if self.config.late_event_behavior == "quarantine":
                self._refresh_depth()
                return ReorderOutcome(
                    accepted=False,
                    late=True,
                    too_late=True,
                    quarantined=(entry,),
                )
            released = self._release_entry(entry)
            return ReorderOutcome(
                accepted=True,
                late=is_late,
                too_late=True,
                released=(released,),
            )

        if len(self._buffer) >= self.config.buffer_capacity:
            self.stats.overflow_events += 1
            if self.config.overflow_behavior == "reject":
                raise BufferOverflowError("Reorder buffer capacity exceeded")
            released = self._release_oldest()
        else:
            released = None

        heappush(self._buffer, (event.observed_at, arrival_index, entry))
        self.stats.events_accepted += 1
        self._refresh_depth()
        released_entries = tuple([released] if released is not None else [])
        released_entries += self._release_before(watermark)
        return ReorderOutcome(
            accepted=True,
            late=is_late,
            too_late=False,
            released=released_entries,
        )

    def flush(self) -> tuple[ReorderEntry, ...]:
        """Release all buffered events in timestamp order."""
        released: list[ReorderEntry] = []
        while self._buffer:
            released.append(self._release_oldest())
        self._refresh_depth()
        return tuple(released)

    @property
    def watermark(self) -> datetime | None:
        if self._max_seen_at is None:
            return None
        return self._max_seen_at - self.config.maximum_lateness

    def _release_before(self, watermark: datetime | None) -> tuple[ReorderEntry, ...]:
        if watermark is None:
            return ()
        released: list[ReorderEntry] = []
        while self._buffer and self._buffer[0][0] <= watermark:
            released.append(self._release_oldest())
        return tuple(released)

    def _release_oldest(self) -> ReorderEntry:
        _, _, entry = heappop(self._buffer)
        self.stats.events_released += 1
        self._refresh_depth()
        return entry

    def _release_entry(self, entry: ReorderEntry) -> ReorderEntry:
        self.stats.events_accepted += 1
        self.stats.events_released += 1
        return entry

    def _refresh_depth(self) -> None:
        self.stats.current_buffer_depth = len(self._buffer)
        self.stats.peak_buffer_depth = max(
            self.stats.peak_buffer_depth, self.stats.current_buffer_depth
        )
