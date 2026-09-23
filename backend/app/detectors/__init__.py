"""Detector integration interfaces for the SPECTRA backend."""

from .base import BaseThreatDetector
from .registry import DetectorRegistry

__all__ = ["BaseThreatDetector", "DetectorRegistry"]
