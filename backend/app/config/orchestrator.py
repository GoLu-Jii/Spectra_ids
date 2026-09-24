from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Mapping

from ..pipeline.ordering import LateEventBehavior, OverflowBehavior

REQUIRED_ORCHESTRATOR_FIELDS = (
    "maximum_lateness_seconds",
    "buffer_capacity",
    "late_event_behavior",
    "overflow_behavior",
    "window_config",
)


class MissingRuntimeConfigurationError(ValueError):
    """Raised when an orchestrator is requested without all explicit settings."""


@dataclass(frozen=True)
class OrchestratorRuntimeConfig:
    """Explicit ordering and scoring mode for one SPECTRA orchestrator.

    ``window_config=None`` explicitly selects the currently integrated
    per-flow detectors. A WindowConfig is not accepted by that detector set.
    """

    maximum_lateness_seconds: float
    buffer_capacity: int
    late_event_behavior: LateEventBehavior
    overflow_behavior: OverflowBehavior
    window_config: None

    def __post_init__(self) -> None:
        if (
            isinstance(self.maximum_lateness_seconds, bool)
            or not isinstance(self.maximum_lateness_seconds, (int, float))
            or not isfinite(self.maximum_lateness_seconds)
            or self.maximum_lateness_seconds < 0
        ):
            raise ValueError("maximum_lateness_seconds must be a non-negative number")
        if (
            isinstance(self.buffer_capacity, bool)
            or not isinstance(self.buffer_capacity, int)
            or self.buffer_capacity < 1
        ):
            raise ValueError("buffer_capacity must be a positive integer")
        if self.late_event_behavior not in {"release", "quarantine"}:
            raise ValueError("late_event_behavior must be 'release' or 'quarantine'")
        if self.overflow_behavior not in {"release_oldest", "reject"}:
            raise ValueError("overflow_behavior must be 'release_oldest' or 'reject'")
        if self.window_config is not None:
            raise ValueError(
                "window_config must be explicitly null for the integrated per-flow DDoS and Port Scan detectors"
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "OrchestratorRuntimeConfig":
        missing = [field for field in REQUIRED_ORCHESTRATOR_FIELDS if field not in value]
        if missing:
            raise MissingRuntimeConfigurationError(
                "Missing required runtime configuration fields: " + ", ".join(missing)
            )
        unexpected = sorted(set(value) - set(REQUIRED_ORCHESTRATOR_FIELDS))
        if unexpected:
            raise ValueError("Unknown runtime configuration fields: " + ", ".join(unexpected))
        return cls(
            maximum_lateness_seconds=value["maximum_lateness_seconds"],  # type: ignore[arg-type]
            buffer_capacity=value["buffer_capacity"],  # type: ignore[arg-type]
            late_event_behavior=value["late_event_behavior"],  # type: ignore[arg-type]
            overflow_behavior=value["overflow_behavior"],  # type: ignore[arg-type]
            window_config=value["window_config"],  # type: ignore[arg-type]
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "maximum_lateness_seconds": self.maximum_lateness_seconds,
            "buffer_capacity": self.buffer_capacity,
            "late_event_behavior": self.late_event_behavior,
            "overflow_behavior": self.overflow_behavior,
            "window_config": None,
        }
