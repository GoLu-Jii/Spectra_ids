from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict

PredictionStatus = Literal["DETECTED", "BENIGN", "INSUFFICIENT_CONTEXT", "REVIEW", "ERROR"]
PredictionScoreType = Literal["probability", "anomaly"]


class Prediction(BaseModel):
    """Common detector output contract required by the SPECTRA ML specification."""

    model_config = ConfigDict(extra="forbid")

    status: PredictionStatus
    threat_class: str
    score_type: PredictionScoreType
    raw_score: float | None = None
    threshold: float | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    detector_name: str
    detector_version: str
    model_name: str
    model_version: str
    feature_schema: str
