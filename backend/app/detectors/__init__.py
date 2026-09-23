"""Detector integration interfaces for the SPECTRA backend."""

from .adapter import DetectorAdapter, DetectorOutputError
from .base import BaseThreatDetector
from .health import DetectorHealth
from .loader import DetectorLoadResult, DetectorLoader
from .registry import DetectorRegistry

__all__ = [
	"BaseThreatDetector",
	"DetectorAdapter",
	"DetectorOutputError",
	"DetectorHealth",
	"DetectorLoadResult",
	"DetectorLoader",
	"DetectorRegistry",
]
