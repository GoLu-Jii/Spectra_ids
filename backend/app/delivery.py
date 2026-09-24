from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import WebSocket

from .latency import LatencyMetricsCollector
from .schemas.alert import Alert


@dataclass
class _Client:
    websocket: WebSocket
    queue: asyncio.Queue[tuple[Alert, dict[str, object]]]
    task: asyncio.Task[None] | None = None


@dataclass
class AlertDelivery:
    """Bounded in-memory fan-out for alerts produced by the orchestrator."""

    latency_metrics: LatencyMetricsCollector
    queue_size: int = 32
    clients: dict[int, _Client] = field(default_factory=dict)
    metrics: dict[str, int] = field(
        default_factory=lambda: {
            "connected_clients": 0,
            "delivered_alerts": 0,
            "client_drops": 0,
            "send_failures": 0,
        }
    )

    def __post_init__(self) -> None:
        if self.queue_size < 1:
            raise ValueError("queue_size must be positive")

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        client = _Client(websocket, asyncio.Queue(maxsize=self.queue_size))
        key = id(websocket)
        self.clients[key] = client
        self.metrics["connected_clients"] = len(self.clients)
        client.task = asyncio.create_task(self._send_loop(key, client))
        try:
            while True:
                await websocket.receive_text()
        except Exception:
            await self.disconnect(key)

    async def disconnect(self, key: int) -> None:
        client = self.clients.pop(key, None)
        self.metrics["connected_clients"] = len(self.clients)
        if client is not None and client.task is not asyncio.current_task():
            if client.task is not None:
                client.task.cancel()
                try:
                    await client.task
                except asyncio.CancelledError:
                    pass

    def publish(self, alert: Alert) -> None:
        """Queue an alert for each client without blocking the producer."""
        for key, client in list(self.clients.items()):
            try:
                client.queue.put_nowait((alert, alert.model_dump(mode="json")))
            except asyncio.QueueFull:
                self.metrics["client_drops"] += 1
                self._schedule_disconnect(key)

    def snapshot(self) -> dict[str, int]:
        return {**self.metrics, "connected_clients": len(self.clients)}

    async def _send_loop(self, key: int, client: _Client) -> None:
        try:
            while True:
                alert, payload = await client.queue.get()
                try:
                    await client.websocket.send_json(payload)
                except Exception:
                    self.metrics["send_failures"] += 1
                    await self.disconnect(key)
                    return
                self._mark_delivered(alert)
        except asyncio.CancelledError:
            raise

    def _schedule_disconnect(self, key: int) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.disconnect(key))

    def _mark_delivered(self, alert: Alert) -> None:
        if alert.timing and alert.timing.get("delivered_at") is not None:
            return
        delivered_at = datetime.now(timezone.utc)
        timing = dict(alert.timing or {})
        timing["delivered_at"] = delivered_at
        alert.timing = timing
        created_at = timing.get("alert_created_at")
        observed_at = timing.get("observed_at")
        durations = dict(alert.latency_durations)
        if isinstance(created_at, datetime):
            durations["delivery_time"] = max(
                0.0, (delivered_at - created_at).total_seconds()
            )
        if isinstance(observed_at, datetime):
            durations["capture_to_dashboard"] = max(
                0.0, (delivered_at - observed_at).total_seconds()
            )
        alert.latency_durations = durations
        self.latency_metrics.record_delivery(alert)
        self.metrics["delivered_alerts"] += 1