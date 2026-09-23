"""Standardized backend schemas for detector outputs and alerts."""

from .alert import Alert
from .prediction import Prediction

__all__ = ["Prediction", "Alert"]
