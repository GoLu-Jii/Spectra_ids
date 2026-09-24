"""Telemetry ingestion and normalization for SPECTRA."""

from .events import NormalizedEvent
from .zeek_tailer import ZeekAvailableRecord, ZeekLogTailer
from .normalizer import EventNormalizationError, UnsupportedEventTypeError, normalize_zeek_record
from .zeek_reader import ZeekReadError, ZeekRecordParser, iter_zeek_records, read_zeek_records

__all__ = [
    "NormalizedEvent",
    "ZeekAvailableRecord",
    "ZeekLogTailer",
    "EventNormalizationError",
    "UnsupportedEventTypeError",
    "normalize_zeek_record",
    "ZeekReadError",
    "ZeekRecordParser",
    "iter_zeek_records",
    "read_zeek_records",
]
