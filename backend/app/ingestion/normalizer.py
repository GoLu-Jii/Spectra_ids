from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from .events import NormalizedEvent

SUPPORTED_EVENT_TYPES = {"conn", "dns", "ssl", "tls", "packet"}


class EventNormalizationError(ValueError):
    """Raised when a supported record cannot become a normalized event."""


class UnsupportedEventTypeError(EventNormalizationError):
    """Raised when a record has no supported SPECTRA event type."""


def normalize_zeek_record(record: Mapping[str, Any]) -> NormalizedEvent:
    """Normalize one Zeek-style record without inventing absent values."""
    if not isinstance(record, Mapping):
        raise EventNormalizationError("Zeek record must be a mapping")

    event_type = _event_type(record)
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise UnsupportedEventTypeError(f"Unsupported Zeek event type: {event_type!r}")

    _require(record, event_type, "ts")
    if event_type in {"conn", "dns", "ssl", "tls"}:
        for field in ("id.orig_h", "id.resp_h"):
            _require(record, event_type, field)

    normalized: dict[str, Any] = {
        "observed_at": _parse_timestamp(record["ts"]),
        "event_type": event_type,
        "source_ip": _first(record, "id.orig_h", "src", "source_ip"),
        "destination_ip": _first(record, "id.resp_h", "dst", "destination_ip"),
        "source_port": _integer(_first(record, "id.orig_p", "src_port", "source_port")),
        "destination_port": _integer(_first(record, "id.resp_p", "dst_port", "destination_port")),
        "protocol": _string(_first(record, "proto", "protocol")),
        "bytes": _total_count(record, "bytes", "orig_bytes", "resp_bytes"),
        "packets": _total_count(record, "packets", "orig_pkts", "resp_pkts"),
        "flow_id": _string(_first(record, "uid", "flow_id", "connection_id")),
        "direction": _string(_first(record, "direction", "conn_state_direction")),
        "raw_metadata": dict(record),
    }

    try:
        return NormalizedEvent.model_validate(normalized)
    except ValidationError as exc:
        raise EventNormalizationError(str(exc)) from exc


def _event_type(record: Mapping[str, Any]) -> str:
    value = _first(record, "event_type", "type", "log_type")
    if value is None:
        raise EventNormalizationError("Zeek record is missing event type")
    return str(value).strip().lower()


def _require(record: Mapping[str, Any], event_type: str, field: str) -> None:
    value = record.get(field)
    if value is None or value == "":
        raise EventNormalizationError(f"{event_type} event is missing required field: {field}")


def _first(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value is not None and value != "-" and value != "":
            return value
    return None


def _string(value: Any) -> str | None:
    return None if value is None else str(value)


def _integer(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise EventNormalizationError(f"Expected integer value, got {value!r}") from exc


def _total_count(record: Mapping[str, Any], direct: str, first: str, second: str) -> int | None:
    direct_value = _first(record, direct)
    if direct_value is not None:
        return _integer(direct_value)
    values = [_first(record, first), _first(record, second)]
    present = [value for value in values if value is not None]
    if not present:
        return None
    return sum(_integer(value) for value in present)


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = (
                datetime.fromtimestamp(float(text), tz=timezone.utc)
                if _is_numeric_timestamp(text)
                else datetime.fromisoformat(text)
            )
        except ValueError as exc:
            raise EventNormalizationError(f"Invalid timestamp: {value!r}") from exc
    else:
        raise EventNormalizationError(f"Invalid timestamp: {value!r}")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventNormalizationError("Timestamp must include timezone information")
    return parsed.astimezone(timezone.utc)


def _is_numeric_timestamp(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True
