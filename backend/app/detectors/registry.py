from __future__ import annotations

from collections.abc import Iterable

from .base import BaseThreatDetector


class DetectorRegistry:
    """Simple in-memory registry for threat detectors."""

    def __init__(self) -> None:
        self._detectors: dict[str, BaseThreatDetector] = {}

    def register(self, detector: BaseThreatDetector) -> None:
        """Register a detector by its unique name, rejecting duplicates."""
        name = detector.detector_name
        if name in self._detectors:
            raise ValueError(f"Detector already registered: {name}")
        self._detectors[name] = detector

    def get(self, name: str) -> BaseThreatDetector:
        """Return a detector by name."""
        return self._detectors[name]

    def list(self) -> list[str]:
        """Return all registered detector names."""
        return list(self._detectors.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._detectors

    def __iter__(self) -> Iterable[str]:
        return iter(self._detectors)
