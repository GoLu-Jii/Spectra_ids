from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import monotonic
from typing import Callable


TimestampClock = Callable[[], datetime]
MonotonicClock = Callable[[], float]


@dataclass
class LatencyTiming:
    """UTC evidence timestamps plus monotonic local processing marks."""

    observed_at: datetime
    ordered_at: datetime | None = None
    zeek_available_at: datetime | None = None
    ingested_at: datetime | None = None
    feature_ready_at: datetime | None = None
    inference_started_at: datetime | None = None
    inference_finished_at: datetime | None = None
    alert_created_at: datetime | None = None
    delivered_at: datetime | None = None
    _monotonic_marks: dict[str, float] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.observed_at = _utc(self.observed_at)
        for name in (
            "ordered_at",
            "zeek_available_at",
            "ingested_at",
            "feature_ready_at",
            "inference_started_at",
            "inference_finished_at",
            "alert_created_at",
            "delivered_at",
        ):
            value = getattr(self, name)
            if value is not None:
                setattr(self, name, _utc(value))

    @classmethod
    def start(
        cls,
        observed_at: datetime,
        *,
        now: TimestampClock | None = None,
        mono: MonotonicClock = monotonic,
        zeek_available_at: datetime | None = None,
    ) -> "LatencyTiming":
        timestamp_clock = now or (lambda: datetime.now(timezone.utc))
        timing = cls(
            observed_at=observed_at,
            zeek_available_at=zeek_available_at,
            ingested_at=timestamp_clock(),
        )
        timing._monotonic_marks["ingested_at"] = mono()
        return timing

    def mark(
        self,
        name: str,
        *,
        now: TimestampClock | None = None,
        mono: MonotonicClock = monotonic,
    ) -> None:
        if name not in {
            "ordered_at",
            "zeek_available_at",
            "ingested_at",
            "feature_ready_at",
            "inference_started_at",
            "inference_finished_at",
            "alert_created_at",
            "delivered_at",
        }:
            raise ValueError(f"Unsupported timing field: {name}")
        timestamp_clock = now or (lambda: datetime.now(timezone.utc))
        setattr(self, name, _utc(timestamp_clock()))
        self._monotonic_marks[name] = mono()

    def durations(self) -> dict[str, float]:
        """Return only durations supported by available timing marks."""
        durations: dict[str, float] = {}
        self._duration_from_monotonic(durations, "queue_wait", "ingested_at", "ordered_at")
        self._duration_from_monotonic(
            durations, "window_wait", "ordered_at", "feature_ready_at"
        )
        self._duration_from_monotonic(
            durations, "feature_time", "feature_ready_at", "inference_started_at"
        )
        self._duration_from_monotonic(
            durations, "inference_time", "inference_started_at", "inference_finished_at"
        )
        self._duration_from_monotonic(
            durations, "alert_generation_time", "inference_finished_at", "alert_created_at"
        )
        self._duration_from_monotonic(
            durations, "delivery_time", "alert_created_at", "delivered_at"
        )
        if self.zeek_available_at is not None and self.ingested_at is not None:
            durations["zeek_to_ingest"] = _seconds(
                self.ingested_at - self.zeek_available_at
            )
        if self.alert_created_at is not None:
            durations["capture_to_alert"] = _seconds(
                self.alert_created_at - self.observed_at
            )
        if self.delivered_at is not None:
            durations["capture_to_dashboard"] = _seconds(
                self.delivered_at - self.observed_at
            )
        return durations

    def _duration_from_monotonic(
        self,
        target: dict[str, float],
        name: str,
        start: str,
        end: str,
    ) -> None:
        start_mark = self._monotonic_marks.get(start)
        end_mark = self._monotonic_marks.get(end)
        if start_mark is not None and end_mark is not None:
            target[name] = max(0.0, end_mark - start_mark)

    def model_dump(self) -> dict[str, datetime | None]:
        return {
            "observed_at": self.observed_at,
            "zeek_available_at": self.zeek_available_at,
            "ingested_at": self.ingested_at,
            "feature_ready_at": self.feature_ready_at,
            "inference_started_at": self.inference_started_at,
            "inference_finished_at": self.inference_finished_at,
            "alert_created_at": self.alert_created_at,
            "delivered_at": self.delivered_at,
        }


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timing timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _seconds(value) -> float:
    return max(0.0, value.total_seconds())


@dataclass
class LatencyMetricsCollector:
    """Collect completed latency observations and calculate percentiles."""

    observations: dict[str, list[float]] = field(default_factory=dict)

    def record(self, timing: LatencyTiming) -> None:
        for name, value in timing.durations().items():
            self.observations.setdefault(name, []).append(value)

    def record_delivery(self, alert) -> None:
        for name in ("delivery_time", "capture_to_dashboard"):
            value = alert.latency_durations.get(name)
            if value is not None:
                self.observations.setdefault(name, []).append(value)

    def summary(self, metric: str) -> dict[str, float | int | None]:
        values = sorted(self.observations.get(metric, []))
        if not values:
            return {"count": 0, "p50": None, "p95": None, "p99": None, "max": None}
        return {
            "count": len(values),
            "p50": _percentile(values, 0.50),
            "p95": _percentile(values, 0.95),
            "p99": _percentile(values, 0.99),
            "max": values[-1],
        }

    def report(self) -> dict[str, dict[str, float | int | None]]:
        return {metric: self.summary(metric) for metric in sorted(self.observations)}


def _percentile(values: list[float], fraction: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    weight = position - lower
    return values[lower] + (values[upper] - values[lower]) * weight
