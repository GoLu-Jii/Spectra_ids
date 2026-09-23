from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Hashable

from ..ingestion.events import NormalizedEvent


@dataclass(frozen=True)
class WindowConfig:
    """Generic context and scoring timing; no detector feature semantics."""

    context_window: timedelta
    scoring_interval: timedelta

    def __post_init__(self) -> None:
        if self.context_window <= timedelta(0):
            raise ValueError("context_window must be positive")
        if self.scoring_interval <= timedelta(0):
            raise ValueError("scoring_interval must be positive")


@dataclass(frozen=True)
class WindowEmission:
    detector_name: str
    grouping_key: Hashable
    context_events: tuple[NormalizedEvent, ...]
    scoring_start: datetime
    scoring_end: datetime


@dataclass
class WindowState:
    events: deque[NormalizedEvent]
    last_observed_at: datetime | None = None
    next_scoring_at: datetime | None = None


class DetectorWindowManager:
    """Maintains isolated timestamp-ordered context for detector/group pairs."""

    def __init__(self, config: WindowConfig) -> None:
        self.config = config
        self._states: dict[tuple[str, Hashable], WindowState] = {}

    def add(
        self,
        detector_name: str,
        grouping_key: Hashable,
        event: NormalizedEvent,
    ) -> tuple[WindowEmission, ...]:
        """Add an ordered event and emit generic scoring snapshots when due."""
        state = self._states.setdefault(
            (detector_name, grouping_key), WindowState(events=deque())
        )
        if state.last_observed_at is not None and event.observed_at < state.last_observed_at:
            raise ValueError("Window events must be timestamp-ordered")
        state.events.append(event)
        state.last_observed_at = event.observed_at
        state.next_scoring_at = state.next_scoring_at or (
            event.observed_at + self.config.scoring_interval
        )
        self._expire_state(state, event.observed_at)

        emissions: list[WindowEmission] = []
        while state.next_scoring_at is not None and event.observed_at >= state.next_scoring_at:
            scoring_end = state.next_scoring_at
            emissions.append(
                self._emission(
                    detector_name,
                    grouping_key,
                    state,
                    scoring_end - self.config.scoring_interval,
                    scoring_end,
                )
            )
            state.next_scoring_at += self.config.scoring_interval
        return tuple(emissions)

    def flush(
        self,
        detector_name: str | None = None,
        grouping_key: Hashable | None = None,
    ) -> tuple[WindowEmission, ...]:
        """Emit remaining context and remove selected or all window state."""
        selected = [
            (key, state)
            for key, state in self._states.items()
            if (detector_name is None or key[0] == detector_name)
            and (grouping_key is None or key[1] == grouping_key)
        ]
        emissions = tuple(
            self._emission(
                key[0],
                key[1],
                state,
                state.last_observed_at or datetime.min,
                state.last_observed_at or datetime.min,
            )
            for key, state in selected
            if state.events
        )
        for key, _ in selected:
            del self._states[key]
        return emissions

    def expire(self, reference_time: datetime) -> tuple[tuple[str, Hashable], ...]:
        """Remove state whose latest event is outside the context horizon."""
        expired: list[tuple[str, Hashable]] = []
        for key, state in list(self._states.items()):
            if state.last_observed_at is not None and reference_time - state.last_observed_at >= self.config.context_window:
                expired.append(key)
                del self._states[key]
        return tuple(expired)

    def get_state(self, detector_name: str, grouping_key: Hashable) -> WindowState | None:
        return self._states.get((detector_name, grouping_key))

    def _expire_state(self, state: WindowState, observed_at: datetime) -> None:
        cutoff = observed_at - self.config.context_window
        while state.events and state.events[0].observed_at < cutoff:
            state.events.popleft()

    def _emission(
        self,
        detector_name: str,
        grouping_key: Hashable,
        state: WindowState,
        scoring_start: datetime,
        scoring_end: datetime,
    ) -> WindowEmission:
        return WindowEmission(
            detector_name=detector_name,
            grouping_key=grouping_key,
            context_events=tuple(state.events),
            scoring_start=scoring_start,
            scoring_end=scoring_end,
        )
