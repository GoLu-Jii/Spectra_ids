from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket

from .config.runtime import RuntimeConfig
from .delivery import AlertDelivery
from .latency import LatencyMetricsCollector
from .stores import AlertStore

@asynccontextmanager
async def lifespan(application: FastAPI):
    runtime = application.state.zeek_runtime
    if runtime is not None:
        await runtime.start()
    try:
        yield
    finally:
        if runtime is not None:
            await runtime.stop()
        await application.state.delivery.close_all()


app = FastAPI(title="SPECTRA Backend", version="0.1.0", lifespan=lifespan)
app.state.alert_store = AlertStore()
app.state.latency_metrics = LatencyMetricsCollector()
app.state.delivery = AlertDelivery(app.state.latency_metrics)
app.state.orchestrator = None
app.state.zeek_runtime = None
app.state.runtime_config = RuntimeConfig.from_env()


def configure_runtime(orchestrator) -> None:
    app.state.orchestrator = orchestrator
    orchestrator.alert_store = app.state.alert_store
    orchestrator.latency_metrics = app.state.latency_metrics
    orchestrator.alert_publisher = app.state.delivery.publish


def configure_zeek_runtime(orchestrator, config: RuntimeConfig | None = None):
    """Attach file ingestion to an explicitly configured runtime pipeline."""
    from .runtime import ZeekRuntime

    configure_runtime(orchestrator)
    selected = config or app.state.runtime_config
    app.state.runtime_config = selected
    app.state.zeek_runtime = ZeekRuntime(selected, orchestrator)
    return app.state.zeek_runtime


@app.get("/health")
async def health() -> dict[str, object]:
    orchestrator = app.state.orchestrator
    runtime = orchestrator.get_runtime_state() if orchestrator is not None else {}
    runtime_source = app.state.zeek_runtime
    state = runtime_source.snapshot() if runtime_source is not None else {
        "runtime_mode": app.state.runtime_config.mode,
        "zeek_source_available": False,
        "files_consumed": [],
        "events_ingested": 0,
        "normalization_errors": 0,
        "source_errors": 0,
        "tail_overflow_events": 0,
        "late_events": None,
        "too_late_events": None,
        "events_rejected_or_late": 0,
        "running": False,
    }
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
        "runtime_mode": app.state.runtime_config.mode,
        "zeek_runtime": state,
        "active_detectors": [
            name
            for name, item in runtime.get("detector_health", {}).items()
            if item.get("registered")
        ],
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
        "zeek_runtime": app.state.zeek_runtime.snapshot() if app.state.zeek_runtime is not None else None,
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
