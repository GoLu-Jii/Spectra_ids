from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config.detectors import DetectorConfig


@dataclass(frozen=True)
class DetectorHealth:
    detector_name: str
    registered: bool
    artifact_present: bool
    artifact_loadable: bool
    dependency_available: bool
    ready_for_inference: bool
    error_reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "detector_name": self.detector_name,
            "registered": self.registered,
            "artifact_present": self.artifact_present,
            "artifact_loadable": self.artifact_loadable,
            "dependency_available": self.dependency_available,
            "ready_for_inference": self.ready_for_inference,
            "error_reason": self.error_reason,
        }


def unavailable_health(
    config: DetectorConfig,
    *,
    registered: bool = False,
    artifact_path: Path | None = None,
    dependency_available: bool = False,
    error_reason: str | None = None,
) -> DetectorHealth:
    artifact_present = artifact_path.is_file() if artifact_path is not None else False
    return DetectorHealth(
        detector_name=config.detector_name,
        registered=registered,
        artifact_present=artifact_present,
        artifact_loadable=False,
        dependency_available=dependency_available,
        ready_for_inference=False,
        error_reason=error_reason,
    )
