from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.app.config.detectors import DetectorConfig
from backend.app.detectors.adapter import DetectorAdapter
from backend.app.detectors.health import DetectorHealth
from backend.app.detectors.registry import DetectorRegistry
from backend.app.latency import LatencyMetricsCollector
from backend.app.main import app, configure_runtime
from backend.app.pipeline.orchestrator import RuntimeOrchestrator
from backend.app.pipeline.ordering import ReorderBuffer, ReorderConfig
from backend.app.pipeline.windows import DetectorWindowManager, WindowConfig
from backend.app.schemas.alert import Alert
from backend.app.stores import AlertStore

BASE = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)


def make_alert(alert_id="ALT-test"):
    return Alert(
        alert_id=alert_id,
        timestamp=BASE,
        flow_id="flow-1",
        threat_class="TestThreat",
        evidence={"source": "test"},
        timing={"observed_at": BASE, "alert_created_at": BASE},
    )


def setup_function():
    app.state.alert_store = AlertStore()
    app.state.latency_metrics = LatencyMetricsCollector()
    from backend.app.delivery import AlertDelivery

    app.state.delivery = AlertDelivery(app.state.latency_metrics, queue_size=2)
    app.state.orchestrator = None


def test_rest_endpoints_and_fallback_without_websocket_client():
    alert = make_alert()
    app.state.alert_store.create(alert)

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/stats").json()["alerts"]["count"] == 1
        assert client.get("/alerts").json()[0]["alert_id"] == alert.alert_id
        assert client.get(f"/alerts/{alert.alert_id}").json()["flow_id"] == "flow-1"
        assert client.get("/alerts/missing").status_code == 404
    assert alert.timing.get("delivered_at") is None


def test_real_orchestrator_alert_reaches_websocket_and_records_delivery():
    name = "api_detector"
    config = DetectorConfig(
        detector_name=name, detector_version="1", model_name="model", model_version="1",
        feature_schema="schema", required_features=(), threshold=0.5,
        score_type="probability", artifact_path=None, expected_format=None,
    )

    class Detector:
        def predict(self, features, context):
            return {"status": "DETECTED", "threat_class": "TestThreat",
                    "score_type": "probability", "raw_score": 0.9,
                    "threshold": 0.5, "evidence": {"source": "test"},
                    "context": {}}

    registry = DetectorRegistry()
    registry.register(DetectorAdapter(Detector(), config))
    health = DetectorHealth(name, True, True, True, True, True)
    orchestrator = RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(0), 20)),
        DetectorWindowManager(WindowConfig(timedelta(seconds=30), timedelta(seconds=1))),
        registry, {name: health},
    )
    configure_runtime(orchestrator)

    from backend.app.ingestion.events import NormalizedEvent

    event = lambda seconds, flow: NormalizedEvent(
        observed_at=BASE + timedelta(seconds=seconds), event_type="conn",
        flow_id=flow, source_ip="192.0.2.1", destination_ip="198.51.100.1",
        source_port=1, destination_port=443, protocol="tcp",
    )
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as websocket:
            orchestrator.process_event(event(0, "one"))
            assert app.state.alert_store.list() == []
            orchestrator.process_event(event(1, "two"))
            payload = websocket.receive_json()

    stored = app.state.alert_store.get(payload["alert_id"])
    assert payload["flow_id"] == "two"
    assert stored.timing["delivered_at"] is not None
    assert "delivery_time" in stored.latency_durations
    assert "capture_to_dashboard" in stored.latency_durations
    assert app.state.latency_metrics.summary("capture_to_dashboard")["count"] == 1


def test_multiple_clients_are_isolated_and_disconnect_is_cleaned_up():
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as first:
            with client.websocket_connect("/ws") as second:
                assert app.state.delivery.snapshot()["connected_clients"] == 2
                app.state.delivery.publish(make_alert())
                assert first.receive_json()["alert_id"] == "ALT-test"
                assert second.receive_json()["alert_id"] == "ALT-test"
            assert app.state.delivery.snapshot()["connected_clients"] == 1
        assert app.state.delivery.snapshot()["connected_clients"] == 0


def test_slow_client_queue_is_bounded_and_dropped():
    class SlowSocket:
        async def send_json(self, payload):
            return None

    delivery = app.state.delivery
    import asyncio

    async def exercise():
        client = type("Client", (), {})()
        client.queue = asyncio.Queue(maxsize=1)
        delivery.clients[1] = client
        delivery.publish(make_alert("one"))
        delivery.publish(make_alert("two"))

    asyncio.run(exercise())
    assert delivery.snapshot()["client_drops"] == 1
    assert delivery.snapshot()["queue_peak_depth"] == 1
