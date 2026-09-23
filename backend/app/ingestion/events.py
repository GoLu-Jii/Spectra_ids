from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedEvent(BaseModel):
    """Canonical passive telemetry event entering SPECTRA."""

    model_config = ConfigDict(extra="forbid")

    observed_at: datetime
    event_type: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    bytes: int | None = Field(default=None, ge=0)
    packets: int | None = Field(default=None, ge=0)
    flow_id: str | None = None
    direction: str | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_utc_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(timezone.utc)
