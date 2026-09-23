from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable

from .schemas.alert import Alert


class DuplicateAlertError(ValueError):
    """Raised when an alert ID already exists in the store."""


class AlertStore:
    """Small bounded in-memory alert store for the MVP."""

    def __init__(self, max_size: int = 1000) -> None:
        if max_size < 1:
            raise ValueError("max_size must be positive")
        self.max_size = max_size
        self._alerts: OrderedDict[str, Alert] = OrderedDict()

    def create(self, alert: Alert) -> Alert:
        if alert.alert_id in self._alerts:
            raise DuplicateAlertError(f"Alert already exists: {alert.alert_id}")
        self._alerts[alert.alert_id] = alert
        while len(self._alerts) > self.max_size:
            self._alerts.popitem(last=False)
        return alert

    def get(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def list(self) -> list[Alert]:
        return list(self._alerts.values())

    def __len__(self) -> int:
        return len(self._alerts)
