from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .prediction import PredictionScoreType

AlertSeverity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
AlertStatus = Literal["NEW", "ACKNOWLEDGED", "RESOLVED"]


class Alert(BaseModel):
    """Standardized backend alert format exposed to the dashboard and API."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    timestamp: datetime
    flow_id: str | None = None
    threat_class: str
    severity: AlertSeverity | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    model: str | None = None
    model_version: str | None = None
    feature_schema: str | None = None
    status: AlertStatus = "NEW"
    score_type: PredictionScoreType | None = None
    raw_model_score: float | None = None
    raw_model_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    calibrated_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    feature_provenance: dict[str, Any] | None = None
    timing: dict[str, datetime | None] | None = None
    latency_durations: dict[str, float] = Field(default_factory=dict)
