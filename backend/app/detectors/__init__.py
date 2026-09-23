"""Detector integration interfaces for the SPECTRA backend."""

from .adapter import DetectorAdapter, DetectorOutputError
from .base import BaseThreatDetector
from .health import DetectorHealth
from .loader import DetectorLoadResult, DetectorLoader
from .registry import DetectorRegistry
from .factories import DETECTOR_FACTORIES, create_ddos_detector, create_port_scan_detector

__all__ = [
	"BaseThreatDetector",
	"DetectorAdapter",
	"DetectorOutputError",
	"DetectorHealth",
	"DetectorLoadResult",
	"DetectorLoader",
	"DetectorRegistry",
	"DETECTOR_FACTORIES",
	"create_ddos_detector",
	"create_port_scan_detector",
]
