from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config.detectors import DetectorConfig
from ..schemas.prediction import Prediction
from .base import BaseThreatDetector


class DetectorOutputError(ValueError):
    """Raised when a detector output cannot satisfy Prediction."""


class DetectorAdapter(BaseThreatDetector):
    """Strict adapter from an existing detector implementation to Prediction."""

    def __init__(self, implementation: Any, config: DetectorConfig) -> None:
        self._implementation = implementation
        self._config = config

    @property
    def detector_name(self) -> str:
        return self._config.detector_name

    @property
    def detector_version(self) -> str:
        return self._config.detector_version

    @property
    def required_features(self) -> list[str]:
        return list(self._config.required_features)

    @property
    def model_name(self) -> str:
        return self._config.model_name

    @property
    def model_version(self) -> str:
        return self._config.model_version

    @property
    def feature_schema(self) -> str:
        return self._config.feature_schema

    @property
    def threshold(self) -> float | None:
        return self._config.threshold

    @property
    def score_type(self) -> str:
        return self._config.score_type

    def predict(self, features: dict[str, Any], context: dict[str, Any]) -> Prediction:
        if hasattr(self._implementation, "predict_flow"):
            output = self._implementation.predict_flow(features)
        else:
            output = self._implementation.predict(features, context)
        if isinstance(output, Prediction):
            data = output.model_dump()
        elif isinstance(output, Mapping):
            data = dict(output)
        else:
            raise DetectorOutputError(
                "Detector output must be a Prediction or mapping; raw scores are not accepted"
            )

        self._reject_conflicting_metadata(data)
        try:
            return Prediction(
                status=data["status"],
                threat_class=data.get("threat_class", self._config.detector_name),
                score_type=data.get("score_type", self._config.score_type),
                raw_score=data.get("raw_score"),
                threshold=data.get("threshold", self._config.threshold),
                evidence=data.get("evidence", {}),
                context=data.get("context", context),
                detector_name=self._config.detector_name,
                detector_version=self._config.detector_version,
                model_name=self._config.model_name,
                model_version=self._config.model_version,
                feature_schema=self._config.feature_schema,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DetectorOutputError(f"Detector output is not a valid Prediction: {exc}") from exc

    def _reject_conflicting_metadata(self, data: dict[str, Any]) -> None:
        expected = {
            "detector_name": self.detector_name,
            "detector_version": self.detector_version,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_schema": self.feature_schema,
            "threshold": self.threshold,
            "score_type": self.score_type,
        }
        for field, value in expected.items():
            if field in data and data[field] != value:
                raise DetectorOutputError(
                    f"Detector output metadata mismatch for {field}: "
                    f"expected {value!r}, got {data[field]!r}"
                )
