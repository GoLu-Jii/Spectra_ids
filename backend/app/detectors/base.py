from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseThreatDetector(ABC):
    """Abstract interface for SPECTRA threat detectors."""

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Human-readable detector name."""

    @property
    @abstractmethod
    def detector_version(self) -> str:
        """Detector implementation version."""

    @property
    @abstractmethod
    def required_features(self) -> list[str]:
        """Feature names required by the detector contract."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier."""

    @property
    @abstractmethod
    def model_version(self) -> str:
        """Model artifact version."""

    @property
    @abstractmethod
    def feature_schema(self) -> str:
        """Versioned feature schema identifier."""

    @abstractmethod
    def predict(self, features: dict[str, Any], context: dict[str, Any]) -> Any:
        """Run detector inference for one observation."""

