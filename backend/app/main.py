from fastapi import FastAPI, WebSocket

from .delivery import AlertDelivery
from .latency import LatencyMetricsCollector
from .stores import AlertStore

app = FastAPI(title="SPECTRA Backend", version="0.1.0")
app.state.alert_store = AlertStore()
app.state.latency_metrics = LatencyMetricsCollector()
app.state.delivery = AlertDelivery(app.state.latency_metrics)
app.state.orchestrator = None


def configure_runtime(orchestrator) -> None:
    app.state.orchestrator = orchestrator
    orchestrator.alert_store = app.state.alert_store
    orchestrator.latency_metrics = app.state.latency_metrics
    orchestrator.alert_publisher = app.state.delivery.publish


@app.get("/health")
async def health() -> dict[str, object]:
    orchestrator = app.state.orchestrator
    runtime = orchestrator.get_runtime_state() if orchestrator is not None else {}
    return {
        "status": "ok",
        "service_started": True,
        "service_ready": True,
        "worker_alive": orchestrator is not None,
        "model_validation_ok": all(
            item.get("ready_for_inference", False)
            for item in runtime.get("detector_health", {}).values()
        ) if runtime.get("detector_health") else True,
        "storage_ok": True,
        "capture_connected": None,
        "runtime_mode": "in_memory",
        **runtime,
    }


@app.get("/stats")
async def stats() -> dict[str, object]:
    orchestrator = app.state.orchestrator
    return {
        "orchestrator": orchestrator.get_metrics() if orchestrator is not None else {},
        "latency": app.state.latency_metrics.report(),
        "alerts": {"count": len(app.state.alert_store)},
        "websocket": app.state.delivery.snapshot(),
    }


@app.get("/alerts")
async def alerts() -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in app.state.alert_store.list()]


@app.get("/alerts/{alert_id}")
async def alert(alert_id: str):
    item = app.state.alert_store.get(alert_id)
    if item is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Alert not found")
    return item


@app.websocket("/ws")
async def websocket(websocket: WebSocket) -> None:
    await app.state.delivery.connect(websocket)
